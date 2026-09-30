use credshim_aws::{
    AuthError, AwsKeySpec, AwsRule, AwsRuleError, BlockedHost, Decision, Payload, Reason, Scope,
    SigV4Auth, blocked, is_aws_host,
};
use http::Request;
use http::request::Parts;

const DUMMY: &str = "CREDSHIMDUMMYAWSKEYAAAAAAAA";
const OTHER: &str = "CREDSHIMDUMMYAWSKEYBBBBBBBB";

fn spec(name: &str, dummy: &str) -> AwsKeySpec {
    AwsKeySpec {
        name: name.to_string(),
        dummy_access_key_id: dummy.to_string(),
        access_key_id: format!("{name}-akid"),
        secret_access_key: format!("{name}-secret"),
        services: None,
        regions: None,
    }
}

fn rules() -> Vec<AwsRule> {
    AwsRule::from_specs(&[spec("dev", DUMMY)]).unwrap()
}

fn authorization(akid: &str, region: &str, service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={akid}/20261001/{region}/{service}/aws4_request, SignedHeaders=host;x-amz-date, Signature={}",
        "0".repeat(64)
    )
}

fn request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

fn signed(method: &str, uri: &str, service: &str, extra: &[(&str, &str)]) -> Parts {
    let auth = authorization(DUMMY, "ap-northeast-1", service);
    let mut headers = vec![
        ("authorization", auth.as_str()),
        ("x-amz-date", "20261001T010203Z"),
    ];
    headers.extend_from_slice(extra);
    request(method, uri, &headers)
}

fn reason(decision: Decision<'_>) -> Reason {
    match decision {
        Decision::Deny(denial) => denial.reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

#[test]
fn parses_the_sigv4_authorization_header() {
    let parts = signed("GET", "/", "sts", &[]);
    let auth = SigV4Auth::from_headers(&parts.headers).unwrap().unwrap();
    assert_eq!(auth.access_key_id, DUMMY);
    assert_eq!(
        auth.scope,
        Scope {
            date: "20261001".into(),
            region: "ap-northeast-1".into(),
            service: "sts".into(),
        }
    );
    assert_eq!(auth.signed_headers, ["host", "x-amz-date"]);
    assert!(auth.signing_time(&parts.headers).is_ok());
}

#[test]
fn rejects_malformed_authorization_headers() {
    for value in [
        "AWS4-HMAC-SHA256 Credential=A/20261001/r/s/aws4_request, SignedHeaders=host",
        "AWS4-HMAC-SHA256 Credential=A/2026/r/s/aws4_request, SignedHeaders=host, Signature=0",
        "AWS4-HMAC-SHA256 Credential=A/20261001/r/S3/aws4_request, SignedHeaders=host, Signature=0",
        "AWS4-HMAC-SHA256 Credential=A/20261001/r/s/aws4_request/x, SignedHeaders=host, Signature=0",
        "AWS4-HMAC-SHA256 Credential=A/20261001/r/s/aws4_request, SignedHeaders=Host, Signature=0",
        "AWS4-HMAC-SHA256 Credential=A/20261001/r/s/aws4_request, Credential=B/20261001/r/s/aws4_request, SignedHeaders=host, Signature=0",
    ] {
        let parts = request("GET", "/", &[("authorization", value)]);
        assert_eq!(
            SigV4Auth::from_headers(&parts.headers),
            Err(AuthError::Malformed),
            "{value}"
        );
    }
    let parts = request("GET", "/", &[("authorization", "Bearer abc")]);
    assert_eq!(
        SigV4Auth::from_headers(&parts.headers),
        Err(AuthError::NotSigV4)
    );
    let auth = authorization(DUMMY, "us-east-1", "sts");
    let parts = request(
        "GET",
        "/",
        &[("authorization", &auth), ("authorization", &auth)],
    );
    assert_eq!(
        SigV4Auth::from_headers(&parts.headers),
        Err(AuthError::Repeated)
    );
}

#[test]
fn signing_time_must_match_the_scope_date() {
    let auth = authorization(DUMMY, "us-east-1", "sts");
    let parts = request(
        "GET",
        "/",
        &[("authorization", &auth), ("x-amz-date", "20261002T000000Z")],
    );
    let parsed = SigV4Auth::from_headers(&parts.headers).unwrap().unwrap();
    assert_eq!(
        parsed.signing_time(&parts.headers),
        Err(AuthError::DateMismatch)
    );
    let parts = request("GET", "/", &[("authorization", &auth)]);
    assert_eq!(parsed.signing_time(&parts.headers), Err(AuthError::BadDate));
}

#[test]
fn recognises_aws_and_always_blocked_hosts() {
    assert!(is_aws_host("sts.ap-northeast-1.amazonaws.com"));
    assert!(is_aws_host("bucket.s3.us-east-1.amazonaws.com"));
    assert!(!is_aws_host("amazonaws.com"));
    assert!(!is_aws_host("evilamazonaws.com"));
    assert!(!is_aws_host("amazonaws.com.evil.test"));
    for (host, expected) in [
        ("oidc.us-east-1.amazonaws.com", Some(BlockedHost::SsoOidc)),
        (
            "oidc-fips.us-east-1.amazonaws.com",
            Some(BlockedHost::SsoOidc),
        ),
        ("oidc.us-east-1.api.aws", Some(BlockedHost::SsoOidc)),
        (
            "portal.sso.ap-northeast-1.amazonaws.com",
            Some(BlockedHost::SsoPortal),
        ),
        ("portal.sso.us-east-1.api.aws", Some(BlockedHost::SsoPortal)),
        ("us-east-1.signin.aws.amazon.com", Some(BlockedHost::Signin)),
        ("signin.aws.amazon.com", Some(BlockedHost::Signin)),
        ("us-east-1.oauth.signin.aws", Some(BlockedHost::Signin)),
        ("sts.us-east-1.amazonaws.com", None),
        ("oidc.example.test", None),
        ("api.openai.com", None),
    ] {
        assert_eq!(blocked(host), expected, "{host}");
    }
}

#[test]
fn validates_rule_specs() {
    let bad = |spec: AwsKeySpec| AwsRule::from_specs(&[spec]).unwrap_err();
    assert_eq!(
        bad(spec("bad name", DUMMY)),
        AwsRuleError::InvalidName("bad name".into())
    );
    assert_eq!(
        bad(spec("dev", "short")),
        AwsRuleError::InvalidDummy("dev".into())
    );
    assert_eq!(
        bad(AwsKeySpec {
            secret_access_key: "no/slash".into(),
            ..spec("dev", DUMMY)
        }),
        AwsRuleError::InvalidSecretName {
            rule: "dev".into(),
            secret: "no/slash".into()
        }
    );
    assert_eq!(
        bad(AwsKeySpec {
            services: Some(vec![]),
            ..spec("dev", DUMMY)
        }),
        AwsRuleError::InvalidFilter {
            rule: "dev".into(),
            field: "services"
        }
    );
    assert_eq!(
        AwsRule::from_specs(&[spec("a", DUMMY), spec("a", OTHER)]).unwrap_err(),
        AwsRuleError::DuplicateName("a".into())
    );
    assert_eq!(
        AwsRule::from_specs(&[spec("a", DUMMY), spec("b", &format!("{DUMMY}X"))]).unwrap_err(),
        AwsRuleError::OverlappingDummies("a".into(), "b".into())
    );
    let parsed: AwsKeySpec = toml::from_str(
        r#"
        name = "dev"
        dummy_access_key_id = "CREDSHIMDUMMYAWSKEYAAAAAAAA"
        access_key_id = "aws-akid"
        secret_access_key = "aws-secret"
        services = ["sts", "s3"]
        regions = ["ap-northeast-1"]
        "#,
    )
    .unwrap();
    assert_eq!(AwsRule::from_specs(&[parsed]).unwrap().len(), 1);
}

#[test]
fn resigns_a_bound_request_and_reports_its_labels() {
    let rules = rules();
    let parts = signed(
        "POST",
        "/",
        "sts",
        &[("content-type", "application/x-www-form-urlencoded")],
    );
    let host = "sts.ap-northeast-1.amazonaws.com";
    assert!(credshim_aws::policy::needs_body(&rules, host, &parts));
    let body = b"Action=GetCallerIdentity&Version=2011-06-15";
    let Decision::Resign(resign) = credshim_aws::policy::decide(&rules, host, &parts, Some(body))
    else {
        panic!("expected a re-sign");
    };
    assert_eq!(resign.rule.name(), "dev");
    assert_eq!(resign.payload, Payload::Buffered);
    assert_eq!(
        resign.labels.operation.as_deref(),
        Some("GetCallerIdentity")
    );
    assert_eq!(resign.labels.scope.unwrap().region, "ap-northeast-1");
}

#[test]
fn s3_payload_hash_decides_how_the_body_is_signed() {
    let rules = rules();
    let host = "bucket.s3.ap-northeast-1.amazonaws.com";
    for (value, expected) in [
        ("UNSIGNED-PAYLOAD", Ok(Payload::Unsigned)),
        (
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            Ok(Payload::StreamingUnsignedTrailer),
        ),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Ok(Payload::Precomputed(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            )),
        ),
        (
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            Err(Reason::SignedChunks),
        ),
        (
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            Err(Reason::SignedChunks),
        ),
        ("E3B0C442", Err(Reason::BadPayloadHash)),
    ] {
        let parts = signed("PUT", "/key", "s3", &[("x-amz-content-sha256", value)]);
        assert!(!credshim_aws::policy::needs_body(&rules, host, &parts));
        let got = match credshim_aws::policy::decide(&rules, host, &parts, None) {
            Decision::Resign(resign) => Ok(resign.payload),
            Decision::Deny(denial) => Err(denial.reason),
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(got, expected, "{value}");
    }
    let parts = signed("PUT", "/key", "s3", &[]);
    assert_eq!(
        reason(credshim_aws::policy::decide(&rules, host, &parts, None)),
        Reason::BadPayloadHash
    );
}

#[test]
fn dummy_outside_aws_or_outside_the_authorization_credential_is_denied() {
    let rules = rules();
    let parts = signed("GET", "/", "sts", &[]);
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "api.openai.com",
            &parts,
            None
        )),
        Reason::NotBound
    );
    let parts = request(
        "GET",
        &format!("/?X-Amz-Credential={DUMMY}%2F20261001"),
        &[],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "sts.us-east-1.amazonaws.com",
            &parts,
            Some(b"")
        )),
        Reason::UnsupportedLocation
    );
    let parts = request(
        "GET",
        "/",
        &[
            ("authorization", "AWS4-HMAC-SHA256 Credential="),
            ("x-note", DUMMY),
        ],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "sts.us-east-1.amazonaws.com",
            &parts,
            Some(b"")
        )),
        Reason::BadAuthorization
    );
}

#[test]
fn service_and_region_filters_use_the_credential_scope() {
    let rules = AwsRule::from_specs(&[AwsKeySpec {
        services: Some(vec!["sts".into()]),
        regions: Some(vec!["ap-northeast-1".into()]),
        ..spec("dev", DUMMY)
    }])
    .unwrap();
    let host = "dynamodb.ap-northeast-1.amazonaws.com";
    let parts = signed("POST", "/", "dynamodb", &[]);
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            host,
            &parts,
            Some(b"{}")
        )),
        Reason::ServiceNotAllowed
    );
    let auth = authorization(DUMMY, "us-west-2", "sts");
    let parts = request(
        "POST",
        "/",
        &[("authorization", &auth), ("x-amz-date", "20261001T000000Z")],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "sts.us-west-2.amazonaws.com",
            &parts,
            Some(b"")
        )),
        Reason::RegionNotAllowed
    );
}

#[test]
fn credential_issuing_operations_are_denied_whichever_way_they_are_named() {
    let rules = rules();
    let sts = "sts.ap-northeast-1.amazonaws.com";
    let form = [("content-type", "application/x-www-form-urlencoded")];
    for (uri, body) in [
        ("/", &b"Action=AssumeRole&RoleArn=x"[..]),
        ("/", b"Action=GetSessionToken"),
        ("/?Action=GetCallerIdentity", b"Action=GetFederationToken"),
        ("/?Action=AssumeRoot", b""),
        ("/", b"action=getsessiontoken"),
    ] {
        let parts = signed("POST", uri, "sts", &form);
        assert_eq!(
            reason(credshim_aws::policy::decide(
                &rules,
                sts,
                &parts,
                Some(body)
            )),
            Reason::CredentialOperation,
            "{uri} {body:?}"
        );
    }
    let iam = signed("POST", "/", "iam", &form);
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "iam.amazonaws.com",
            &iam,
            Some(b"Action=CreateAccessKey&UserName=x")
        )),
        Reason::CredentialOperation
    );
    let ssm = signed(
        "POST",
        "/",
        "ssm",
        &[("x-amz-target", "AmazonSSM.GetAccessToken")],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "ssm.ap-northeast-1.amazonaws.com",
            &ssm,
            Some(b"{}")
        )),
        Reason::CredentialOperation
    );
    let eks = signed(
        "POST",
        "/clusters/dev/assume-role-for-pod-identity",
        "eks-auth",
        &[],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "eks-auth.ap-northeast-1.api.aws",
            &eks,
            Some(b"{}")
        )),
        Reason::NotBound
    );
    let eks_on_amazonaws = signed(
        "POST",
        "/clusters/dev/assume-role-for-pod-identity",
        "eks-auth",
        &[],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "eks-auth.ap-northeast-1.amazonaws.com",
            &eks_on_amazonaws,
            Some(b"{}")
        )),
        Reason::CredentialOperation
    );
    for uri in ["/?session", "/bucket?session="] {
        let s3 = signed(
            "GET",
            uri,
            "s3",
            &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
        );
        assert_eq!(
            reason(credshim_aws::policy::decide(
                &rules,
                "bucket.s3.ap-northeast-1.amazonaws.com",
                &s3,
                None
            )),
            Reason::CredentialOperation,
            "{uri}"
        );
    }
    let cbor = signed(
        "POST",
        "/service/GraniteServiceVersion20100801/operation/GetSpaceCredentialsForOrganization",
        "cloudwatch",
        &[],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &rules,
            "monitoring.ap-northeast-1.amazonaws.com",
            &cbor,
            Some(b"")
        )),
        Reason::CredentialOperation
    );
}

#[test]
fn ordinary_operations_with_similar_names_pass() {
    let rules = rules();
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let parts = signed("POST", "/", "sts", &form);
    assert!(matches!(
        credshim_aws::policy::decide(
            &rules,
            "sts.ap-northeast-1.amazonaws.com",
            &parts,
            Some(b"Action=GetCallerIdentity")
        ),
        Decision::Resign(_)
    ));
    let s3 = signed(
        "GET",
        "/?list-type=2",
        "s3",
        &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
    );
    assert!(matches!(
        credshim_aws::policy::decide(&rules, "bucket.s3.ap-northeast-1.amazonaws.com", &s3, None),
        Decision::Resign(_)
    ));
    let other_service = signed(
        "POST",
        "/",
        "bedrock",
        &[("x-amz-target", "Bedrock.CreateSession")],
    );
    assert!(matches!(
        credshim_aws::policy::decide(
            &rules,
            "bedrock.ap-northeast-1.amazonaws.com",
            &other_service,
            Some(b"{}")
        ),
        Decision::Resign(_)
    ));
}

#[test]
fn unsigned_credential_apis_are_denied_without_any_rule() {
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let sts = "sts.ap-northeast-1.amazonaws.com";
    let parts = request("POST", "/", &form);
    assert!(credshim_aws::policy::needs_body(&[], sts, &parts));
    for body in [
        &b"Action=AssumeRoleWithWebIdentity&WebIdentityToken=x"[..],
        b"Action=AssumeRoleWithSAML",
    ] {
        assert_eq!(
            reason(credshim_aws::policy::decide(&[], sts, &parts, Some(body))),
            Reason::UnsignedCredentialOperation
        );
    }
    let cognito = request(
        "POST",
        "/",
        &[(
            "x-amz-target",
            "AWSCognitoIdentityService.GetCredentialsForIdentity",
        )],
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &[],
            "cognito-identity.ap-northeast-1.amazonaws.com",
            &cognito,
            Some(b"{}")
        )),
        Reason::UnsignedCredentialOperation
    );
    assert_eq!(
        reason(credshim_aws::policy::decide(
            &[],
            "oidc.ap-northeast-1.amazonaws.com",
            &request("POST", "/token", &[]),
            None
        )),
        Reason::BlockedHost(BlockedHost::SsoOidc)
    );
    let plain = request("POST", "/", &form);
    assert!(matches!(
        credshim_aws::policy::decide(&[], sts, &plain, Some(b"Action=GetCallerIdentity")),
        Decision::Pass(_)
    ));
    assert!(!credshim_aws::policy::needs_body(
        &[],
        "dynamodb.ap-northeast-1.amazonaws.com",
        &plain
    ));
}

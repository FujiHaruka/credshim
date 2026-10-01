use credshim_aws::refusal::error_response;
use credshim_aws::sso::SsoSessionError;
use credshim_aws::{
    AwsKeySpec, AwsRule, AwsRuleError, AwsSsoRoleSpec, Source, SsoRole, SsoSession, SsoSessionSpec,
};
use http::{Request, StatusCode};

fn session(name: &str, start_url: &str, region: &str) -> SsoSessionSpec {
    SsoSessionSpec {
        name: name.into(),
        start_url: start_url.into(),
        region: region.into(),
    }
}

fn role(name: &str, dummy: &str) -> AwsSsoRoleSpec {
    AwsSsoRoleSpec {
        name: name.into(),
        dummy_access_key_id: dummy.into(),
        session: "work".into(),
        account_id: "123456789012".into(),
        role_name: "Developer".into(),
        services: None,
        regions: None,
        operations: None,
        limits: Default::default(),
    }
}

fn sessions() -> Vec<SsoSession> {
    SsoSession::from_specs(&[session(
        "work",
        "https://example.awsapps.com/start",
        "us-east-1",
    )])
    .unwrap()
}

#[test]
fn sessions_need_an_https_start_url_a_region_and_unique_names() {
    let good = sessions();
    assert_eq!(good[0].oidc_host(), "oidc.us-east-1.amazonaws.com");
    assert_eq!(good[0].portal_host(), "portal.sso.us-east-1.amazonaws.com");
    assert_eq!(good[0].secret_name(), "credshim-aws-sso-work");

    let cases = [
        (
            session("work", "http://example.awsapps.com/start", "us-east-1"),
            SsoSessionError::InvalidStartUrl("work".into()),
        ),
        (
            session("work", "example.awsapps.com", "us-east-1"),
            SsoSessionError::InvalidStartUrl("work".into()),
        ),
        (
            session(
                "work",
                "https://example.awsapps.com/start",
                "us-east-1.evil.test/x",
            ),
            SsoSessionError::InvalidRegion("work".into()),
        ),
        (
            session("work", "https://example.awsapps.com/start", ""),
            SsoSessionError::InvalidRegion("work".into()),
        ),
        (
            session("a/b", "https://example.awsapps.com/start", "us-east-1"),
            SsoSessionError::InvalidName("a/b".into()),
        ),
    ];
    for (spec, expected) in cases {
        assert_eq!(SsoSession::from_specs(&[spec]).unwrap_err(), expected);
    }
    let twice = session("work", "https://example.awsapps.com/start", "us-east-1");
    assert_eq!(
        SsoSession::from_specs(&[twice.clone(), twice]).unwrap_err(),
        SsoSessionError::DuplicateName("work".into())
    );
}

#[test]
fn sso_roles_name_a_known_session_an_account_and_a_role() {
    let rules =
        AwsRule::from_config(&[], &[role("dev", "CREDSHIMSSODUMMYKEY00001")], &sessions()).unwrap();
    assert_eq!(
        rules[0].source(),
        &Source::Sso(SsoRole {
            session: "work".into(),
            account_id: "123456789012".into(),
            role_name: "Developer".into(),
        })
    );

    let mut unknown = role("dev", "CREDSHIMSSODUMMYKEY00001");
    unknown.session = "home".into();
    let mut account = role("dev", "CREDSHIMSSODUMMYKEY00001");
    account.account_id = "12345678901x".into();
    let mut role_name = role("dev", "CREDSHIMSSODUMMYKEY00001");
    role_name.role_name = "Dev&action=x".into();
    let cases = [
        (
            unknown,
            AwsRuleError::UnknownSession {
                rule: "dev".into(),
                session: "home".into(),
            },
        ),
        (account, AwsRuleError::InvalidAccount("dev".into())),
        (role_name, AwsRuleError::InvalidRoleName("dev".into())),
    ];
    for (spec, expected) in cases {
        assert_eq!(
            AwsRule::from_config(&[], &[spec], &sessions()).unwrap_err(),
            expected
        );
    }
}

#[test]
fn static_keys_and_sso_roles_share_one_namespace_and_never_overlap() {
    let key = AwsKeySpec {
        name: "dev".into(),
        dummy_access_key_id: "CREDSHIMSSODUMMYKEY00001".into(),
        access_key_id: "akid".into(),
        secret_access_key: "secret".into(),
        services: None,
        regions: None,
        operations: None,
        limits: Default::default(),
    };
    assert_eq!(
        AwsRule::from_config(
            std::slice::from_ref(&key),
            &[role("dev", "CREDSHIMSSODUMMYKEY00002")],
            &sessions()
        )
        .unwrap_err(),
        AwsRuleError::DuplicateName("dev".into())
    );
    assert_eq!(
        AwsRule::from_config(
            &[key],
            &[role("sso", "CREDSHIMSSODUMMYKEY00001X")],
            &sessions()
        )
        .unwrap_err(),
        AwsRuleError::OverlappingDummies("dev".into(), "sso".into())
    );
}

#[test]
fn refusals_are_shaped_so_each_aws_protocol_shows_the_message() {
    let parts = |headers: &[(&str, &str)]| {
        let mut builder = Request::builder().uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    };
    let message = "credshim: run `credshim aws sso login work` & retry";

    let json = error_response(
        &parts(&[("x-amz-target", "DynamoDB_20120810.ListTables")]),
        Some("dynamodb"),
        StatusCode::FORBIDDEN,
        "CredShimSsoLoginRequired",
        message,
    );
    assert_eq!(json.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json.headers()["x-amzn-errortype"],
        "CredShimSsoLoginRequired"
    );
    let body: serde_json::Value = serde_json::from_slice(json.body()).unwrap();
    assert_eq!(body["__type"], "CredShimSsoLoginRequired");
    assert_eq!(body["message"], message);

    let query = error_response(
        &parts(&[]),
        Some("sts"),
        StatusCode::FORBIDDEN,
        "C",
        message,
    );
    let text = std::str::from_utf8(query.body()).unwrap();
    assert!(text.starts_with("<ErrorResponse><Error>"), "{text}");
    assert!(
        text.contains("<Message>credshim: run `credshim aws sso login work` &amp; retry</Message>")
    );

    let s3 = error_response(&parts(&[]), Some("s3"), StatusCode::FORBIDDEN, "C", message);
    assert!(
        std::str::from_utf8(s3.body())
            .unwrap()
            .contains("\n<Error><Code>C</Code>")
    );

    let ec2 = error_response(
        &parts(&[]),
        Some("ec2"),
        StatusCode::FORBIDDEN,
        "C",
        message,
    );
    assert!(
        std::str::from_utf8(ec2.body())
            .unwrap()
            .contains("<Response><Errors><Error><Code>C</Code>")
    );
}

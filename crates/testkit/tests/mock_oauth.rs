use std::collections::HashMap;

use credshim_testkit::oauth::{
    ClientAuthMethod, MOCK_CLIENT_ID, MOCK_ID_TOKEN, TokenFormat, pkce_challenge,
};
use credshim_testkit::{
    MockOAuth, MockOAuthConfig, TestCa, client_trusting, install_crypto_provider,
};

const HOST: &str = "oauth.example.test";
const SECRET: &str = "mock-client-secret";
const VERIFIER: &str = "mock-verifier-0123456789-0123456789-0123456789";

struct Mock {
    server: MockOAuth,
    client: reqwest::Client,
    auth: ClientAuthMethod,
}

async fn mock(edit: impl FnOnce(&mut MockOAuthConfig)) -> Mock {
    install_crypto_provider();
    let ca = TestCa::new();
    let mut config = MockOAuthConfig::new(SECRET);
    edit(&mut config);
    let auth = config.client_auth;
    let server = MockOAuth::start(ca.issue(&[HOST]), config).await;
    let client = client_trusting(&ca)
        .resolve(HOST, server.addr())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Mock {
        server,
        client,
        auth,
    }
}

impl Mock {
    fn url(&self, path: &str) -> String {
        format!("https://{HOST}:{}{path}", self.server.addr().port())
    }

    async fn token(&self, mut form: Vec<(&str, String)>) -> (u16, HashMap<String, String>) {
        let request = self.client.post(self.url("/token"));
        let request = match self.auth {
            ClientAuthMethod::Post => {
                form.push(("client_id", MOCK_CLIENT_ID.into()));
                form.push(("client_secret", SECRET.into()));
                request
            }
            ClientAuthMethod::Basic => request.basic_auth(MOCK_CLIENT_ID, Some(SECRET)),
        };
        let response = request.form(&form).send().await.unwrap();
        let status = response.status().as_u16();
        let json = response
            .headers()
            .get("content-type")
            .is_some_and(|value| value.as_bytes().starts_with(b"application/json"));
        let text = response.text().await.unwrap();
        let fields = if json {
            serde_json::from_str::<HashMap<String, serde_json::Value>>(&text)
                .unwrap()
                .into_iter()
                .map(|(name, value)| {
                    (
                        name,
                        value.as_str().map_or(value.to_string(), str::to_string),
                    )
                })
                .collect()
        } else {
            form_urlencoded::parse(text.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        };
        (status, fields)
    }

    async fn code(&self, verifier: &str) -> String {
        let response = self
            .client
            .get(self.url("/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", MOCK_CLIENT_ID),
                ("redirect_uri", "http://localhost/cb"),
                ("state", "s1"),
                ("code_challenge", &pkce_challenge(verifier)),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap();
        let location = response.headers()["location"].to_str().unwrap();
        assert!(location.starts_with("http://localhost/cb?"));
        assert!(location.ends_with("state=s1"));
        form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(name, _)| name == "code")
            .unwrap()
            .1
            .into_owned()
    }

    async fn exchange(&self, verifier: &str) -> (u16, HashMap<String, String>) {
        let code = self.code(VERIFIER).await;
        self.token(vec![
            ("grant_type", "authorization_code".into()),
            ("code", code),
            ("code_verifier", verifier.into()),
        ])
        .await
    }

    async fn refresh(&self, token: &str) -> (u16, HashMap<String, String>) {
        self.token(vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", token.into()),
        ])
        .await
    }

    async fn me(&self, token: &str) -> u16 {
        self.client
            .get(self.url("/api/me"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
}

#[tokio::test]
async fn authorization_code_with_pkce_in_every_client_auth_and_format() {
    for (auth, format) in [
        (ClientAuthMethod::Post, TokenFormat::Json),
        (ClientAuthMethod::Basic, TokenFormat::Form),
    ] {
        let m = mock(|c| {
            c.client_auth = auth;
            c.format = format;
        })
        .await;

        let (status, tokens) = m.exchange(VERIFIER).await;

        assert_eq!(status, 200, "{auth:?} {format:?}");
        assert_eq!(tokens["expires_in"], "3600");
        assert_eq!(tokens["id_token"], MOCK_ID_TOKEN);
        assert_eq!(m.me(&tokens["access_token"]).await, 200);
        assert_eq!(m.server.issued().len(), 2);
    }
}

#[tokio::test]
async fn wrong_verifier_or_client_secret_is_rejected() {
    let m = mock(|_| {}).await;
    assert_eq!(
        m.exchange("some-other-verifier-0123456789-0123456789")
            .await
            .0,
        400
    );

    let m = mock(|c| c.client_auth = ClientAuthMethod::Basic).await;
    let response = m
        .client
        .post(m.url("/token"))
        .basic_auth(MOCK_CLIENT_ID, Some("wrong"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn refresh_rotates_or_keeps_the_refresh_token() {
    let m = mock(|_| {}).await;
    let (_, first) = m.exchange(VERIFIER).await;
    let (status, second) = m.refresh(&first["refresh_token"]).await;
    assert_eq!(status, 200);
    assert_ne!(second["refresh_token"], first["refresh_token"]);
    assert_eq!(m.refresh(&first["refresh_token"]).await.0, 400);

    let m = mock(|c| c.rotate_refresh = false).await;
    let (_, first) = m.exchange(VERIFIER).await;
    for _ in 0..2 {
        let (status, next) = m.refresh(&first["refresh_token"]).await;
        assert_eq!(status, 200);
        assert!(!next.contains_key("refresh_token"));
        assert_eq!(m.me(&next["access_token"]).await, 200);
    }
    assert_eq!(m.server.refreshes(), 2);
}

#[tokio::test]
async fn client_credentials_and_revocation() {
    let m = mock(|_| {}).await;
    let (status, tokens) = m
        .token(vec![("grant_type", "client_credentials".into())])
        .await;
    assert_eq!(status, 200);
    assert!(!tokens.contains_key("refresh_token"));
    let access = &tokens["access_token"];
    assert_eq!(m.me(access).await, 200);

    let response = m
        .client
        .post(m.url("/revoke"))
        .form(&[("token", access)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!m.server.is_active(access));
    assert_eq!(m.me(access).await, 401);
}

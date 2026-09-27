//! Controller-side verification of a refreshed Codex (ChatGPT login) credential.
//!
//! A Codex CLI refreshes its tokens inside the sandbox and runnerd hands the refreshed
//! `auth.json` back. That file is written by untrusted code: the agent can put anything in it.
//! Checking its (unsigned) claims proves nothing — the agent can even copy the victim's
//! genuine, signed `id_token` next to a refresh token of its own. The only way to bind a
//! refresh token to the enrolled account is to *use* it:
//!
//! ```text
//! submitted auth.json ──▶ refresh_token ──▶ POST <token endpoint> (controller, not sandbox)
//!                                            │
//!                    fresh id_token + access_token + refresh_token
//!                                            │
//!             RS256 signature (JWKS) · iss · aud · exp · chatgpt_account_id == enrolled
//!                                            │
//!             store the controller-obtained tokens (never the submitted bytes)
//! ```
//!
//! A garbage or foreign refresh token fails at the provider or at the account check, and the
//! stored profile stays unchanged. Refreshing rotates the submitted token; the sandbox is
//! finishing anyway.
//!
//! Defaults below were taken from the pinned `@openai/codex` 0.156.1 binary (token endpoint,
//! client id) and the OIDC conventions of the issuer (JWKS path). All are configurable.

use async_trait::async_trait;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const DEFAULT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const DEFAULT_ISSUER: &str = "https://auth.openai.com";
pub const DEFAULT_JWKS_URL: &str = "https://auth.openai.com/.well-known/jwks.json";
pub const DEFAULT_SCOPE: &str = "openid profile email";
/// Claim namespace carrying the ChatGPT account of a Codex id_token.
pub const AUTH_CLAIM: &str = "https://api.openai.com/auth";

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("token endpoint: {0}")]
    Endpoint(String),
    #[error("id_token: {0}")]
    IdToken(String),
    #[error("JWKS: {0}")]
    Jwks(String),
}

/// Tokens returned by the provider for a refresh (all controller-obtained).
#[derive(Debug, Clone)]
pub struct RefreshedTokens {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Verified claims of `id_token`.
    pub claims: Value,
}

impl RefreshedTokens {
    /// The ChatGPT account id from the verified claims.
    pub fn account_id(&self) -> Option<&str> {
        self.claims.get(AUTH_CLAIM).and_then(|a| a.get("chatgpt_account_id")).and_then(|v| v.as_str())
    }
}

#[async_trait]
pub trait TokenRefresher: Send + Sync {
    /// Redeem `refresh_token` at the provider and verify the returned id_token.
    async fn refresh(&self, refresh_token: &str) -> Result<RefreshedTokens, RefreshError>;
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Where the verification keys come from.
pub enum JwksSource {
    Url(String),
    /// Fixed key set (tests, air-gapped deployments with a mounted JWKS).
    Static(String),
}

/// RS256 id_token verifier with a cached JWKS (refetched on an unknown `kid`, at most once a
/// minute, and after an hour).
pub struct IdTokenVerifier {
    pub issuer: String,
    pub audience: String,
    source: JwksSource,
    http: HttpClient,
    cache: Mutex<Option<(Instant, Vec<Jwk>)>>,
}

fn b64url(s: &str) -> Result<Vec<u8>, RefreshError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| RefreshError::IdToken("invalid base64url".into()))
}

impl IdTokenVerifier {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, source: JwksSource, http: HttpClient) -> Self {
        IdTokenVerifier { issuer: issuer.into(), audience: audience.into(), source, http, cache: Mutex::new(None) }
    }

    async fn keys(&self, force: bool) -> Result<Vec<Jwk>, RefreshError> {
        if let Some((at, keys)) = self.cache.lock().expect("jwks").as_ref() {
            let fresh = at.elapsed() < Duration::from_secs(3600);
            let recent = at.elapsed() < Duration::from_secs(60);
            if (fresh && !force) || recent {
                return Ok(keys.clone());
            }
        }
        let text = match &self.source {
            JwksSource::Static(t) => t.clone(),
            JwksSource::Url(u) => {
                let (status, body) = self.http.get(u).await.map_err(RefreshError::Jwks)?;
                if !(200..300).contains(&status) {
                    return Err(RefreshError::Jwks(format!("HTTP {status}")));
                }
                String::from_utf8(body).map_err(|_| RefreshError::Jwks("not UTF-8".into()))?
            }
        };
        let set: JwkSet = serde_json::from_str(&text).map_err(|e| RefreshError::Jwks(e.to_string()))?;
        *self.cache.lock().expect("jwks") = Some((Instant::now(), set.keys.clone()));
        Ok(set.keys)
    }

    /// Verify signature (RS256), issuer, audience and expiry; return the claims.
    pub async fn verify(&self, jwt: &str, now_unix: i64) -> Result<Value, RefreshError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        let [h, p, s] = parts[..] else { return Err(RefreshError::IdToken("not a JWS compact token".into())) };
        let header: Value =
            serde_json::from_slice(&b64url(h)?).map_err(|_| RefreshError::IdToken("unreadable header".into()))?;
        if header.get("alg").and_then(|a| a.as_str()) != Some("RS256") {
            return Err(RefreshError::IdToken("only RS256 is accepted".into()));
        }
        let kid = header.get("kid").and_then(|k| k.as_str()).map(str::to_string);
        let sig = b64url(s)?;
        let signed = format!("{h}.{p}");
        let mut verified = false;
        for force in [false, true] {
            let keys = self.keys(force).await?;
            let candidates: Vec<&Jwk> = keys
                .iter()
                .filter(|k| k.kty == "RSA" && k.alg.as_deref().is_none_or(|a| a == "RS256"))
                .filter(|k| kid.is_none() || k.kid == kid)
                .collect();
            for k in &candidates {
                let (Some(n), Some(e)) = (&k.n, &k.e) else { continue };
                let key = ring::signature::RsaPublicKeyComponents { n: b64url(n)?, e: b64url(e)? };
                if key.verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &sig).is_ok() {
                    verified = true;
                    break;
                }
            }
            if verified || !candidates.is_empty() {
                break; // known key but bad signature: do not refetch
            }
        }
        if !verified {
            return Err(RefreshError::IdToken("signature does not verify against the issuer's keys".into()));
        }
        let claims: Value =
            serde_json::from_slice(&b64url(p)?).map_err(|_| RefreshError::IdToken("unreadable claims".into()))?;
        if claims.get("iss").and_then(|v| v.as_str()) != Some(self.issuer.as_str()) {
            return Err(RefreshError::IdToken("issuer mismatch".into()));
        }
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => a == &self.audience,
            Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(self.audience.as_str())),
            _ => false,
        };
        if !aud_ok {
            return Err(RefreshError::IdToken("audience mismatch".into()));
        }
        match claims.get("exp").and_then(|v| v.as_i64()) {
            Some(exp) if exp > now_unix - 60 => {}
            _ => return Err(RefreshError::IdToken("expired or missing exp".into())),
        }
        Ok(claims)
    }
}

/// OAuth refresh-token grant against the provider's token endpoint.
pub struct OAuthRefresher {
    pub token_url: String,
    pub client_id: String,
    pub scope: String,
    http: HttpClient,
    verifier: IdTokenVerifier,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

/// Minimal HTTPS client (hyper + rustls with an explicit ring provider and the system's root
/// certificates). Deliberately does not touch rustls' process-wide default provider or
/// reqwest's features, which other components share.
#[derive(Clone)]
pub struct HttpClient {
    inner: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<bytes::Bytes>,
    >,
    timeout: Duration,
}

impl HttpClient {
    pub fn new(timeout: Duration) -> Result<Self, RefreshError> {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(provider)
            .map_err(|e| RefreshError::Endpoint(format!("TLS roots: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        let inner = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);
        Ok(HttpClient { inner, timeout })
    }

    async fn send(&self, req: hyper::Request<http_body_util::Full<bytes::Bytes>>) -> Result<(u16, Vec<u8>), String> {
        use http_body_util::BodyExt;
        let fut = async {
            let resp = self.inner.request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let body = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
            if body.len() > 1 << 20 {
                return Err("response too large".to_string());
            }
            Ok((status, body.to_vec()))
        };
        tokio::time::timeout(self.timeout, fut).await.map_err(|_| "timed out".to_string())?
    }

    pub async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
        let req =
            hyper::Request::get(url).body(http_body_util::Full::new(bytes::Bytes::new())).map_err(|e| e.to_string())?;
        self.send(req).await
    }

    pub async fn post_json(&self, url: &str, body: &Value) -> Result<(u16, Vec<u8>), String> {
        let req = hyper::Request::post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(body.to_string())))
            .map_err(|e| e.to_string())?;
        self.send(req).await
    }
}

/// The default client (20 s timeout).
pub fn http_client() -> HttpClient {
    HttpClient::new(Duration::from_secs(20)).expect("https client")
}

pub struct RefresherConfig {
    pub token_url: String,
    pub client_id: String,
    pub issuer: String,
    pub jwks: JwksSource,
    pub scope: String,
}

impl Default for RefresherConfig {
    fn default() -> Self {
        RefresherConfig {
            token_url: DEFAULT_TOKEN_URL.into(),
            client_id: DEFAULT_CLIENT_ID.into(),
            issuer: DEFAULT_ISSUER.into(),
            jwks: JwksSource::Url(DEFAULT_JWKS_URL.into()),
            scope: DEFAULT_SCOPE.into(),
        }
    }
}

impl OAuthRefresher {
    pub fn new(cfg: RefresherConfig) -> Result<Self, RefreshError> {
        let http = HttpClient::new(Duration::from_secs(20))?;
        let verifier = IdTokenVerifier::new(cfg.issuer, cfg.client_id.clone(), cfg.jwks, http.clone());
        Ok(OAuthRefresher { token_url: cfg.token_url, client_id: cfg.client_id, scope: cfg.scope, http, verifier })
    }
}

#[async_trait]
impl TokenRefresher for OAuthRefresher {
    async fn refresh(&self, refresh_token: &str) -> Result<RefreshedTokens, RefreshError> {
        let body = serde_json::json!({
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": self.scope,
        });
        let (status, resp) = self.http.post_json(&self.token_url, &body).await.map_err(RefreshError::Endpoint)?;
        if !(200..300).contains(&status) {
            // The body may echo request details; report the status only.
            return Err(RefreshError::Endpoint(format!("HTTP {status}")));
        }
        let t: TokenResponse =
            serde_json::from_slice(&resp).map_err(|e| RefreshError::Endpoint(format!("response: {e}")))?;
        let (Some(id_token), Some(access_token), Some(refresh_token)) = (t.id_token, t.access_token, t.refresh_token)
        else {
            return Err(RefreshError::Endpoint("response lacks id_token, access_token or refresh_token".into()));
        };
        let now = chrono::Utc::now().timestamp();
        let claims = self.verifier.verify(&id_token, now).await?;
        Ok(RefreshedTokens { id_token, access_token, refresh_token, claims })
    }
}

/// Build the auth.json to store from the submitted file's shape and controller-obtained
/// tokens. Unknown top-level fields of the submitted file are dropped except `auth_mode` and
/// `OPENAI_API_KEY: null` (Codex's own layout).
pub fn rebuild_auth_json(t: &RefreshedTokens) -> Vec<u8> {
    let account = t.account_id().unwrap_or_default();
    serde_json::to_vec_pretty(&serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": t.id_token,
            "access_token": t.access_token,
            "refresh_token": t.refresh_token,
            "account_id": account,
        },
        "last_refresh": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
    }))
    .expect("json")
}

#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    //! Deterministic RS256 test issuer (throw-away 2048-bit key; compiled only for tests and
    //! the `test-support` feature, never into release binaries).
    use super::*;
    use ring::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

    /// PKCS#1 DER (base64) of a throw-away RSA-2048 key used only by tests.
    pub const TEST_KEY_PKCS8_B64: &str = include_str!("../testdata/rs256-test-key.der.b64");

    pub struct TestIssuer {
        key: RsaKeyPair,
        pub kid: String,
    }

    impl Default for TestIssuer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestIssuer {
        pub fn new() -> Self {
            let der = base64::engine::general_purpose::STANDARD.decode(TEST_KEY_PKCS8_B64.trim()).expect("test key");
            TestIssuer { key: RsaKeyPair::from_der(&der).expect("pkcs1 der"), kid: "test-key-1".into() }
        }

        /// JWKS document with the public half.
        pub fn jwks(&self) -> String {
            let pk = self.key.public_key();
            let comps: ring::rsa::PublicKeyComponents<Vec<u8>> = pk.into();
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            serde_json::json!({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": self.kid,
                                          "n": b.encode(&comps.n), "e": b.encode(&comps.e)}]})
            .to_string()
        }

        pub fn sign(&self, claims: &Value) -> String {
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let h = b.encode(serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": self.kid}).to_string());
            let p = b.encode(claims.to_string());
            let signed = format!("{h}.{p}");
            let mut sig = vec![0u8; self.key.public().modulus_len()];
            self.key
                .sign(&RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signed.as_bytes(), &mut sig)
                .expect("sign");
            format!("{signed}.{}", b.encode(sig))
        }

        pub fn id_token(&self, issuer: &str, audience: &str, account: &str) -> String {
            let exp = chrono::Utc::now().timestamp() + 3600;
            self.sign(&serde_json::json!({
                "iss": issuer, "aud": audience, "exp": exp, "email": "ops@example.com",
                AUTH_CLAIM: {"chatgpt_account_id": account, "chatgpt_plan_type": "pro"}
            }))
        }
    }

    /// In-process refresher for tests: accepts refresh tokens of the form `rt_<account>_<n>`
    /// and answers like the provider would, with id_tokens signed by the [`TestIssuer`].
    pub struct FakeRefresher {
        pub issuer: TestIssuer,
        pub verifier: IdTokenVerifier,
        pub calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeRefresher {
        pub fn new() -> Self {
            let issuer = TestIssuer::new();
            let verifier = IdTokenVerifier::new(
                DEFAULT_ISSUER,
                DEFAULT_CLIENT_ID,
                JwksSource::Static(issuer.jwks()),
                http_client(),
            );
            FakeRefresher { issuer, verifier, calls: Default::default() }
        }
    }

    impl Default for FakeRefresher {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl TokenRefresher for FakeRefresher {
        async fn refresh(&self, refresh_token: &str) -> Result<RefreshedTokens, RefreshError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let account = refresh_token
                .strip_prefix("rt_")
                .and_then(|r| r.rsplit_once('_').map(|(a, _)| a))
                .ok_or_else(|| RefreshError::Endpoint("HTTP 400 Bad Request (invalid_grant)".into()))?;
            let id_token = self.issuer.id_token(DEFAULT_ISSUER, DEFAULT_CLIENT_ID, account);
            let claims = self.verifier.verify(&id_token, chrono::Utc::now().timestamp()).await?;
            Ok(RefreshedTokens {
                id_token,
                access_token: format!("access-{account}-{n}-0000000000000000"),
                refresh_token: format!("rt_{account}_{}", n + 1000),
                claims,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn verifier(issuer: &TestIssuer) -> IdTokenVerifier {
        IdTokenVerifier::new(DEFAULT_ISSUER, DEFAULT_CLIENT_ID, JwksSource::Static(issuer.jwks()), http_client())
    }

    #[tokio::test]
    async fn verifies_signature_issuer_audience_and_expiry() {
        let iss = TestIssuer::new();
        let v = verifier(&iss);
        let now = chrono::Utc::now().timestamp();
        let good = iss.id_token(DEFAULT_ISSUER, DEFAULT_CLIENT_ID, "acct-1");
        let c = v.verify(&good, now).await.unwrap();
        assert_eq!(c[AUTH_CLAIM]["chatgpt_account_id"], "acct-1");
        // tampered claims
        let (h, rest) = good.split_once('.').unwrap();
        let (_, s) = rest.split_once('.').unwrap();
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let forged = format!(
            "{h}.{}.{s}",
            b.encode(
                serde_json::json!({"iss": DEFAULT_ISSUER, "aud": DEFAULT_CLIENT_ID, "exp": now + 100,
                                   AUTH_CLAIM: {"chatgpt_account_id": "acct-victim"}})
                .to_string()
            )
        );
        assert!(v.verify(&forged, now).await.is_err());
        // alg none / wrong issuer / wrong audience / expired
        let none = format!("{}.{}.", b.encode(r#"{"alg":"none"}"#), b.encode(r#"{"iss":"x"}"#));
        assert!(v.verify(&none, now).await.is_err());
        assert!(v.verify(&iss.id_token("https://evil.example", DEFAULT_CLIENT_ID, "a"), now).await.is_err());
        assert!(v.verify(&iss.id_token(DEFAULT_ISSUER, "app_other", "a"), now).await.is_err());
        let old = iss.sign(&serde_json::json!({"iss": DEFAULT_ISSUER, "aud": DEFAULT_CLIENT_ID, "exp": now - 3600}));
        assert!(v.verify(&old, now).await.is_err());
    }

    #[tokio::test]
    async fn fake_refresher_binds_tokens_to_accounts() {
        let f = FakeRefresher::new();
        let t = f.refresh("rt_acct-1_7").await.unwrap();
        assert_eq!(t.account_id(), Some("acct-1"));
        assert!(f.refresh("attacker-controlled").await.is_err());
        let json: Value = serde_json::from_slice(&rebuild_auth_json(&t)).unwrap();
        assert_eq!(json["tokens"]["account_id"], "acct-1");
        assert_eq!(json["auth_mode"], "chatgpt");
    }
}

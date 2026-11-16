//! A [`TokenValidator`] for opaque access tokens, using OAuth 2.0 Token
//! Introspection (RFC 7662). Feature `server-auth-introspection`.
//!
//! [`IntrospectionValidator`] posts each token to the authorization server's
//! introspection endpoint and maps an `active: true` answer to an
//! [`AuthenticatedPrincipal`]. It keeps answers in two bounded caches, keyed
//! by the SHA-256 of the token:
//!
//! - active answers, for at most the active TTL and never past `exp`;
//! - inactive answers, for a shorter TTL, so a flood of bad tokens costs one
//!   introspection call per token per TTL. The caches are separate, so bad
//!   tokens cannot evict good ones.
//!
//! Outages (timeouts, non-2xx answers, bodies over the limit, answers that
//! are not RFC 7662 JSON) are [`AuthError::unavailable`] and are never
//! cached.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::Engine;
use http::{HeaderValue, header};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    AuthError, AuthenticatedPrincipal, Clock, TokenValidator, ValidationRequest, system_clock,
};

/// Default longest time an active answer is reused (it is also capped by
/// `exp`).
pub const DEFAULT_ACTIVE_TTL: Duration = Duration::from_secs(60);
/// Default time an inactive answer is reused.
pub const DEFAULT_INACTIVE_TTL: Duration = Duration::from_secs(5);
/// Default most answers kept in each cache.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;
/// Default longest wait for the introspection endpoint.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default largest accepted introspection answer.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// How the resource server authenticates to the introspection endpoint
/// (RFC 7662 section 2.1).
#[derive(Clone)]
#[non_exhaustive]
pub enum IntrospectionClientAuth {
    /// HTTP Basic with the client ID and secret (RFC 6749 section 2.3.1).
    ClientSecretBasic {
        /// The resource server's client ID.
        client_id: String,
        /// The client secret.
        client_secret: Zeroizing<String>,
    },
    /// The client ID and secret in the form body.
    ClientSecretPost {
        /// The resource server's client ID.
        client_id: String,
        /// The client secret.
        client_secret: Zeroizing<String>,
    },
    /// A bearer token for the introspection endpoint.
    Bearer(Zeroizing<String>),
}

impl IntrospectionClientAuth {
    /// `client_secret_basic`.
    pub fn basic(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self::ClientSecretBasic {
            client_id: client_id.into(),
            client_secret: Zeroizing::new(client_secret.into()),
        }
    }

    /// `client_secret_post`.
    pub fn post(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self::ClientSecretPost {
            client_id: client_id.into(),
            client_secret: Zeroizing::new(client_secret.into()),
        }
    }

    /// A bearer token.
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(Zeroizing::new(token.into()))
    }
}

impl fmt::Debug for IntrospectionClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientSecretBasic { client_id, .. } => f
                .debug_struct("ClientSecretBasic")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            Self::ClientSecretPost { client_id, .. } => f
                .debug_struct("ClientSecretPost")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
        }
    }
}

type CacheKey = [u8; 32];

struct CacheEntry {
    sequence: u64,
    principal: Option<AuthenticatedPrincipal>,
    until: SystemTime,
}

/// A bounded map that drops the oldest insertion when full.
#[derive(Default)]
struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
    order: BTreeMap<u64, CacheKey>,
    next: u64,
}

impl Cache {
    fn get(&self, key: &CacheKey, now: SystemTime) -> Option<Option<AuthenticatedPrincipal>> {
        self.entries
            .get(key)
            .filter(|entry| entry.until > now)
            .map(|entry| entry.principal.clone())
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.order.remove(&entry.sequence);
        }
    }

    fn insert(
        &mut self,
        key: CacheKey,
        principal: Option<AuthenticatedPrincipal>,
        until: SystemTime,
        max_entries: usize,
    ) {
        if max_entries == 0 {
            return;
        }
        self.remove(&key);
        while self.entries.len() >= max_entries {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        let sequence = self.next;
        self.next = sequence.wrapping_add(1);
        self.order.insert(sequence, key);
        self.entries.insert(
            key,
            CacheEntry {
                sequence,
                principal,
                until,
            },
        );
    }
}

/// The RFC 7662 members this validator reads. Unknown members go to
/// [`AuthenticatedPrincipal::claims`].
#[derive(Deserialize)]
struct Introspection {
    active: bool,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<Audience>,
    #[serde(default)]
    exp: Option<f64>,
    #[serde(default)]
    nbf: Option<f64>,
    #[serde(default)]
    cnf: Option<Value>,
    #[serde(flatten)]
    rest: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

fn seconds_to_time(seconds: f64) -> Option<SystemTime> {
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::try_from_secs_f64(seconds).ok()?)
}

/// Validates opaque tokens at an RFC 7662 introspection endpoint.
///
/// Tokens with a `cnf` member are refused, because this validator cannot
/// check a proof of possession. [`Self::allow_confirmed_tokens`] passes them
/// through with an unverified [`super::Confirmation`] instead, for a wrapping
/// validator that checks the proof (for example DPoP) and marks it verified.
pub struct IntrospectionValidator {
    http: reqwest::Client,
    endpoint: String,
    auth: IntrospectionClientAuth,
    timeout: Duration,
    max_response_bytes: usize,
    active_ttl: Duration,
    inactive_ttl: Duration,
    max_cache_entries: usize,
    allow_confirmed_tokens: bool,
    clock: Clock,
    active: Mutex<Cache>,
    inactive: Mutex<Cache>,
}

impl fmt::Debug for IntrospectionValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionValidator")
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("active_ttl", &self.active_ttl)
            .field("inactive_ttl", &self.inactive_ttl)
            .field("max_cache_entries", &self.max_cache_entries)
            .field("allow_confirmed_tokens", &self.allow_confirmed_tokens)
            .finish_non_exhaustive()
    }
}

impl IntrospectionValidator {
    /// A validator that posts to `endpoint` with `http`, authenticating with
    /// `auth`. Configure TLS, proxies and redirects on `http`; redirects
    /// should be off for an introspection endpoint.
    pub fn new(
        http: reqwest::Client,
        endpoint: impl Into<String>,
        auth: IntrospectionClientAuth,
    ) -> Self {
        Self {
            http,
            endpoint: endpoint.into(),
            auth,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            active_ttl: DEFAULT_ACTIVE_TTL,
            inactive_ttl: DEFAULT_INACTIVE_TTL,
            max_cache_entries: DEFAULT_MAX_CACHE_ENTRIES,
            allow_confirmed_tokens: false,
            clock: system_clock(),
            active: Mutex::default(),
            inactive: Mutex::default(),
        }
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the largest accepted answer, in bytes.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// Set the cache TTLs. Zero turns that cache off. Revocation takes up to
    /// `active` to take effect.
    pub fn with_cache_ttls(mut self, active: Duration, inactive: Duration) -> Self {
        self.active_ttl = active;
        self.inactive_ttl = inactive;
        self
    }

    /// Set the most answers kept in each cache. Zero turns caching off.
    pub fn with_max_cache_entries(mut self, entries: usize) -> Self {
        self.max_cache_entries = entries;
        self
    }

    /// Pass tokens with `cnf` through, with an unverified confirmation. The
    /// layer still refuses them unless a wrapping validator verifies the
    /// binding.
    pub fn allow_confirmed_tokens(mut self) -> Self {
        self.allow_confirmed_tokens = true;
        self
    }

    /// Replace the clock. For tests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn cache(&self, active: bool) -> std::sync::MutexGuard<'_, Cache> {
        let cache = if active { &self.active } else { &self.inactive };
        cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The principal for `token`; `Ok(None)` when it is not usable here.
    pub async fn introspect(
        &self,
        token: &str,
    ) -> Result<Option<AuthenticatedPrincipal>, AuthError> {
        let key: CacheKey = Sha256::digest(token.as_bytes()).into();
        let now = (self.clock)();
        let hit = self
            .cache(true)
            .get(&key, now)
            .or_else(|| self.cache(false).get(&key, now));
        if let Some(hit) = hit {
            return Ok(hit);
        }
        let body = self.ask(token).await?;
        if !matches!(body.get("active"), Some(Value::Bool(_))) {
            return Err(AuthError::unavailable(
                "introspection answer has no boolean `active`",
            ));
        }
        let now = (self.clock)();
        // A malformed member makes the token inactive.
        let principal = serde_json::from_value::<Introspection>(body)
            .ok()
            .and_then(|answer| self.principal(answer, now));
        let (ttl, active) = match &principal {
            Some(principal) => {
                let until_exp = principal
                    .expires_at
                    .and_then(|exp| exp.duration_since(now).ok())
                    .unwrap_or(self.active_ttl);
                (self.active_ttl.min(until_exp), true)
            }
            None => (self.inactive_ttl, false),
        };
        if !ttl.is_zero() {
            self.cache(!active).remove(&key);
            self.cache(active).insert(
                key,
                principal.clone(),
                now.checked_add(ttl).unwrap_or(now),
                self.max_cache_entries,
            );
        }
        Ok(principal)
    }

    fn principal(&self, answer: Introspection, now: SystemTime) -> Option<AuthenticatedPrincipal> {
        let Introspection {
            active,
            scope,
            client_id,
            sub,
            aud,
            exp,
            nbf,
            cnf,
            rest,
        } = answer;
        if !active {
            return None;
        }
        let expires_at = match exp {
            Some(exp) => Some(seconds_to_time(exp)?),
            None => None,
        };
        if expires_at.is_some_and(|exp| exp <= now) {
            return None;
        }
        if let Some(nbf) = nbf
            && seconds_to_time(nbf)? > now
        {
            return None;
        }
        if cnf.is_some() && !self.allow_confirmed_tokens {
            return None;
        }
        let mut principal = AuthenticatedPrincipal::new()
            .with_scopes(
                scope
                    .as_deref()
                    .unwrap_or_default()
                    .split_ascii_whitespace(),
            )
            .with_audiences(match aud {
                Some(Audience::One(one)) => vec![one],
                Some(Audience::Many(many)) => many,
                None => Vec::new(),
            })
            .with_claims(rest);
        principal.subject = sub;
        principal.client_id = client_id;
        principal.expires_at = expires_at;
        if let Some(cnf) = cnf {
            principal = principal.with_unverified_confirmation(cnf);
        }
        Some(principal)
    }

    /// The introspection request for `token`.
    fn request(&self, token: &str) -> Result<reqwest::RequestBuilder, AuthError> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("token", token)
            .append_pair("token_type_hint", "access_token");
        let mut request = self
            .http
            .post(&self.endpoint)
            .timeout(self.timeout)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        match &self.auth {
            IntrospectionClientAuth::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                // RFC 6749 section 2.3.1: form-encode both parts first.
                let encode = |value: &str| {
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
                };
                let credentials = Zeroizing::new(format!(
                    "{}:{}",
                    encode(client_id),
                    Zeroizing::new(encode(client_secret)).as_str()
                ));
                let value = Zeroizing::new(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
                ));
                request = request.header(header::AUTHORIZATION, sensitive(&value)?);
            }
            IntrospectionClientAuth::ClientSecretPost {
                client_id,
                client_secret,
            } => {
                form.append_pair("client_id", client_id)
                    .append_pair("client_secret", client_secret);
            }
            IntrospectionClientAuth::Bearer(secret) => {
                let value = Zeroizing::new(format!("Bearer {}", secret.as_str()));
                request = request.header(header::AUTHORIZATION, sensitive(&value)?);
            }
        }
        let body = Zeroizing::new(form.finish());
        Ok(request.body(body.as_str().to_owned()))
    }

    async fn ask(&self, token: &str) -> Result<Value, AuthError> {
        let unavailable =
            |reason: String| AuthError::unavailable(format!("introspection: {reason}"));
        let mut response = self
            .request(token)?
            .send()
            .await
            .map_err(|error| unavailable(error.without_url().to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(unavailable(format!("HTTP {}", status.as_u16())));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(unavailable("answer too large".to_owned()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| unavailable(error.without_url().to_string()))?
        {
            if bytes.len() + chunk.len() > self.max_response_bytes {
                return Err(unavailable("answer too large".to_owned()));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| unavailable("answer is not JSON".to_owned()))
    }
}

fn sensitive(value: &str) -> Result<HeaderValue, AuthError> {
    let mut value = HeaderValue::from_str(value)
        .map_err(|_| AuthError::internal("introspection credentials do not encode"))?;
    value.set_sensitive(true);
    Ok(value)
}

#[async_trait]
impl TokenValidator for IntrospectionValidator {
    async fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        self.introspect(request.credential.token)
            .await?
            .ok_or_else(AuthError::invalid_token)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use serde_json::json;

    use super::*;

    const RESOURCE: &str = "https://mcp.example.com/mcp";
    const NOW: u64 = 1_000_000;

    #[derive(Default)]
    struct Server {
        calls: AtomicUsize,
        last_authorization: Mutex<Option<String>>,
        last_form: Mutex<Option<String>>,
    }

    async fn introspect(
        State(server): State<Arc<Server>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, String) {
        server.calls.fetch_add(1, Ordering::SeqCst);
        *server.last_authorization.lock().unwrap() = headers
            .get("authorization")
            .map(|value| value.to_str().unwrap().to_owned());
        let form = String::from_utf8(body.to_vec()).unwrap();
        *server.last_form.lock().unwrap() = Some(form.clone());
        let token = url::form_urlencoded::parse(form.as_bytes())
            .find(|(name, _)| name == "token")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default();
        let active = json!({
            "active": true,
            "sub": "alice",
            "client_id": "app",
            "scope": "mcp read",
            "aud": [RESOURCE],
            "exp": NOW + 30,
            "tenant": "t1",
        });
        let answer = match token.as_str() {
            "good" => active,
            "bound" => {
                let mut bound = active;
                bound["cnf"] = json!({"jkt": "abc"});
                bound
            }
            "expired" => json!({"active": true, "exp": NOW - 1}),
            "future" => json!({"active": true, "nbf": NOW + 10}),
            "malformed" => json!({"active": true, "scope": 5}),
            "error" => return (StatusCode::BAD_GATEWAY, String::new()),
            "huge" => json!({"active": false, "pad": "x".repeat(2048)}),
            "no-active" => json!({"ok": true}),
            _ => json!({"active": false}),
        };
        (StatusCode::OK, answer.to_string())
    }

    async fn start() -> (Arc<Server>, String) {
        let server = Arc::new(Server::default());
        let app = Router::new()
            .route("/introspect", post(introspect))
            .with_state(server.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (server, format!("http://{address}/introspect"))
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn validator(endpoint: &str, auth: IntrospectionClientAuth) -> IntrospectionValidator {
        IntrospectionValidator::new(reqwest::Client::new(), endpoint, auth)
            .with_clock(Arc::new(|| at(NOW)))
    }

    #[tokio::test]
    async fn active_answer_becomes_a_principal_and_is_cached() {
        let (server, endpoint) = start().await;
        let validator = validator(&endpoint, IntrospectionClientAuth::bearer("rs-secret"));
        let principal = validator.introspect("good").await.unwrap().unwrap();
        assert_eq!(principal.subject.as_deref(), Some("alice"));
        assert_eq!(principal.client_id.as_deref(), Some("app"));
        assert_eq!(principal.scopes, ["mcp", "read"]);
        assert_eq!(principal.audiences, [RESOURCE]);
        assert_eq!(principal.expires_at, Some(at(NOW + 30)));
        assert_eq!(principal.claims["tenant"], "t1");
        assert_eq!(
            server.last_authorization.lock().unwrap().as_deref(),
            Some("Bearer rs-secret")
        );
        assert!(
            server
                .last_form
                .lock()
                .unwrap()
                .as_deref()
                .unwrap()
                .contains("token_type_hint=access_token")
        );
        validator.introspect("good").await.unwrap().unwrap();
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unusable_answers_are_inactive_and_cached_separately() {
        let (server, endpoint) = start().await;
        let validator = validator(&endpoint, IntrospectionClientAuth::bearer("s"));
        for token in ["nope", "expired", "future", "malformed", "bound"] {
            assert_eq!(validator.introspect(token).await.unwrap(), None, "{token}");
        }
        assert_eq!(server.calls.load(Ordering::SeqCst), 5);
        validator.introspect("nope").await.unwrap();
        assert_eq!(server.calls.load(Ordering::SeqCst), 5, "inactive is cached");
        assert_eq!(validator.cache(false).entries.len(), 5);
        assert_eq!(validator.cache(true).entries.len(), 0);
    }

    #[tokio::test]
    async fn confirmed_tokens_pass_unverified_when_allowed() {
        let (_server, endpoint) = start().await;
        let validator =
            validator(&endpoint, IntrospectionClientAuth::bearer("s")).allow_confirmed_tokens();
        let principal = validator.introspect("bound").await.unwrap().unwrap();
        let confirmation = principal.confirmation.unwrap();
        assert_eq!(confirmation.value, json!({"jkt": "abc"}));
        assert!(!confirmation.verified);
    }

    #[tokio::test]
    async fn outages_are_unavailable_and_not_cached() {
        let (server, endpoint) = start().await;
        let validator = validator(&endpoint, IntrospectionClientAuth::bearer("s"))
            .with_max_response_bytes(1024);
        for token in ["error", "huge", "no-active"] {
            let error = validator.introspect(token).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE, "{token}");
        }
        validator.introspect("error").await.unwrap_err();
        assert_eq!(server.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn client_auth_methods() {
        let (server, endpoint) = start().await;
        validator(
            &endpoint,
            IntrospectionClientAuth::basic("rs client", "p@ss:word"),
        )
        .introspect("good")
        .await
        .unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode("rs+client:p%40ss%3Aword");
        assert_eq!(
            server.last_authorization.lock().unwrap().clone(),
            Some(format!("Basic {expected}"))
        );
        validator(&endpoint, IntrospectionClientAuth::post("rs", "secret"))
            .introspect("good")
            .await
            .unwrap();
        assert_eq!(server.last_authorization.lock().unwrap().clone(), None);
        let form = server.last_form.lock().unwrap().clone().unwrap();
        assert!(form.contains("client_id=rs&client_secret=secret"), "{form}");
    }

    #[test]
    fn debug_redacts_secrets() {
        let auth = IntrospectionClientAuth::basic("rs", "top-secret");
        let validator = IntrospectionValidator::new(
            reqwest::Client::new(),
            "https://as.example.com/introspect",
            auth,
        );
        let text = format!("{validator:?}");
        assert!(!text.contains("top-secret"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn cache_is_bounded_oldest_first() {
        let mut cache = Cache::default();
        let until = at(NOW + 10);
        for i in 0..3u8 {
            cache.insert([i; 32], None, until, 2);
        }
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.get(&[0; 32], at(NOW)).is_none());
        assert!(cache.get(&[2; 32], at(NOW)).is_some());
        assert!(cache.get(&[2; 32], until).is_none(), "expired");
    }
}

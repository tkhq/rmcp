//! The tower layer that puts an MCP endpoint behind a [`TokenValidator`].

use std::{
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header, request::Parts};
use http_body::Body;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};

use super::{
    AuthError, AuthenticatedPrincipal, Clock, Credential, MetadataError, ProtectedResourceMetadata,
    TokenValidator, ValidationRequest, add_leeway, canonical_resource, system_clock,
};

/// The boxed error type of the layer's response body.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// The layer's response body.
pub type AuthBody = UnsyncBoxBody<Bytes, BoxError>;

struct Config {
    validator: Arc<dyn TokenValidator>,
    resource: String,
    metadata_url: String,
    public_base_url: String,
    required_scopes: Vec<String>,
    expiry_leeway: Duration,
    clock: Clock,
}

/// A [`tower_layer::Layer`] that admits only requests with a valid token for
/// this resource.
///
/// For each request it:
///
/// 1. reads the one `Authorization` header. Tokens in the query string are
///    never read (MCP authorization, "Token Requirements"). Two or more
///    `Authorization` fields are refused;
/// 2. calls [`TokenValidator::validate`] for a scheme the validator accepts;
/// 3. checks that one of the principal's audiences is this resource, compared
///    with [`canonical_resource`] on both sides;
/// 4. checks the expiry, with the configured leeway;
/// 5. refuses a principal whose confirmation (`cnf`) is not verified;
/// 6. checks the required scopes;
/// 7. inserts the [`AuthenticatedPrincipal`] into the request extensions and
///    calls the inner service.
///
/// A refused request gets 401 (with `WWW-Authenticate` naming the
/// `resource_metadata` URL, and `scope` when the layer requires scopes), 403
/// `insufficient_scope`, or 503 / 500 for validator outages and failures.
///
/// Wrap the MCP service itself, for example with axum's `route_service`, so
/// the request path the validator sees is the full public path. `nest` and
/// `nest_service` strip their prefix; in that case include the prefix in
/// [`Self::with_public_base_url`].
#[derive(Clone)]
pub struct ResourceServerLayer {
    config: Arc<Config>,
}

impl std::fmt::Debug for ResourceServerLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceServerLayer")
            .field("resource", &self.config.resource)
            .field("metadata_url", &self.config.metadata_url)
            .field("public_base_url", &self.config.public_base_url)
            .field("required_scopes", &self.config.required_scopes)
            .field("expiry_leeway", &self.config.expiry_leeway)
            .finish_non_exhaustive()
    }
}

impl ResourceServerLayer {
    /// A layer for the resource that `metadata` describes. The public base
    /// URL defaults to the resource's origin.
    pub fn new(validator: impl TokenValidator, metadata: &ProtectedResourceMetadata) -> Self {
        let resource = canonical_resource(metadata.resource())
            .expect("ProtectedResourceMetadata::new checked the resource");
        let public_base_url = url::Url::parse(metadata.resource())
            .expect("ProtectedResourceMetadata::new checked the resource")
            .origin()
            .ascii_serialization();
        Self {
            config: Arc::new(Config {
                validator: Arc::new(validator),
                resource,
                metadata_url: metadata.metadata_url(),
                public_base_url,
                required_scopes: Vec::new(),
                expiry_leeway: Duration::ZERO,
                clock: system_clock(),
            }),
        }
    }

    fn config_mut(&mut self) -> &mut Config {
        Arc::get_mut(&mut self.config).expect("builder methods run before the layer is cloned")
    }

    /// Scopes every request needs. A token without them gets 403
    /// `insufficient_scope`. Build one layer per scope set for per-route
    /// scopes; layers can share one validator through an `Arc`.
    ///
    /// # Panics
    ///
    /// When called on a layer that has been cloned.
    pub fn with_required_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config_mut().required_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The scheme, authority, and optional path prefix that clients use, such
    /// as `https://mcp.example.com`. The layer appends the request path to
    /// get [`ValidationRequest::url`]. Set it when a proxy rewrites the host
    /// or strips a path prefix.
    ///
    /// # Errors
    ///
    /// [`MetadataError`] when `url` is not an `http` or `https` URL with a
    /// host, or has a query or fragment.
    ///
    /// # Panics
    ///
    /// When called on a layer that has been cloned.
    pub fn with_public_base_url(mut self, url: &str) -> Result<Self, MetadataError> {
        let parsed = url::Url::parse(url).ok().filter(|parsed| {
            matches!(parsed.scheme(), "http" | "https")
                && parsed.host().is_some()
                && parsed.query().is_none()
                && parsed.fragment().is_none()
        });
        if parsed.is_none() {
            return Err(MetadataError {
                resource: url.to_owned(),
            });
        }
        self.config_mut().public_base_url = url.trim_end_matches('/').to_owned();
        Ok(self)
    }

    /// How long after `expires_at` a principal is still accepted, for
    /// validators whose own checks allow clock skew. Default zero.
    ///
    /// # Panics
    ///
    /// When called on a layer that has been cloned.
    pub fn with_expiry_leeway(mut self, leeway: Duration) -> Self {
        self.config_mut().expiry_leeway = leeway;
        self
    }

    /// Replace the clock. For tests.
    ///
    /// # Panics
    ///
    /// When called on a layer that has been cloned.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.config_mut().clock = clock;
        self
    }
}

impl<S> tower_layer::Layer<S> for ResourceServerLayer {
    type Service = ResourceServerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResourceServerService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// The service that [`ResourceServerLayer`] wraps around an MCP service.
#[derive(Clone)]
pub struct ResourceServerService<S> {
    inner: S,
    config: Arc<Config>,
}

impl<S> std::fmt::Debug for ResourceServerService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceServerService")
            .field("resource", &self.config.resource)
            .finish_non_exhaustive()
    }
}

impl<S, B, ResBody> tower_service::Service<Request<B>> for ResourceServerService<S>
where
    S: tower_service::Service<Request<B>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    ResBody: Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = Response<AuthBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // The clone may not be ready; keep the one that is.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();
        Box::pin(async move {
            let now = (config.clock)();
            let (mut parts, body) = request.into_parts();
            let principal = match authorize(&config, &parts, now).await {
                Ok(principal) => principal,
                Err((error, scheme)) => return Ok(refusal(&config, &error, scheme, now)),
            };
            parts.extensions.insert(principal.clone());
            let response = inner.call(Request::from_parts(parts, body)).await?;
            let mut response = response.map(|body| body.map_err(Into::into).boxed_unsync());
            config
                .validator
                .on_response(&principal, response.headers_mut(), now);
            Ok(response)
        })
    }
}

/// The principal for this request, or the error and the scheme the request
/// used (when the validator accepts it).
async fn authorize(
    config: &Config,
    parts: &Parts,
    now: SystemTime,
) -> Result<AuthenticatedPrincipal, (AuthError, Option<&'static str>)> {
    let mut fields = parts.headers.get_all(header::AUTHORIZATION).iter();
    let Some(first) = fields.next() else {
        return Err((AuthError::missing_credentials(), None));
    };
    if fields.next().is_some() {
        return Err((
            AuthError::invalid_token().with_description("more than one Authorization header"),
            None,
        ));
    }
    let Ok(value) = first.to_str() else {
        return Err((
            AuthError::invalid_token().with_description("Authorization header is not valid text"),
            None,
        ));
    };
    let value = value.trim();
    let (scheme, token) = value
        .split_once([' ', '\t'])
        .map_or((value, ""), |(scheme, token)| (scheme, token.trim()));
    let Some(scheme) = config
        .validator
        .schemes()
        .iter()
        .copied()
        .find(|known| known.eq_ignore_ascii_case(scheme))
    else {
        return Err((AuthError::missing_credentials(), None));
    };
    let refuse = |error: AuthError| (error, Some(scheme));
    if token.is_empty() || token.contains([' ', '\t', ',']) {
        return Err(refuse(
            AuthError::invalid_token().with_description("malformed credential"),
        ));
    }
    let url = format!("{}{}", config.public_base_url, parts.uri.path());
    let request = ValidationRequest::new(parts, Credential::new(scheme, token), &url, now);
    let principal = config.validator.validate(&request).await.map_err(refuse)?;

    let for_this_resource = principal
        .audiences
        .iter()
        .filter_map(|audience| canonical_resource(audience))
        .any(|audience| audience == config.resource);
    if !for_this_resource {
        return Err(refuse(
            AuthError::invalid_token().with_description("token is not for this resource"),
        ));
    }
    if principal
        .expires_at
        .is_some_and(|expires_at| add_leeway(expires_at, config.expiry_leeway) <= now)
    {
        return Err(refuse(
            AuthError::invalid_token().with_description("token expired"),
        ));
    }
    if principal
        .confirmation
        .as_ref()
        .is_some_and(|confirmation| !confirmation.verified)
    {
        return Err(refuse(
            AuthError::invalid_token().with_description("token is bound to a key"),
        ));
    }
    let missing: Vec<&String> = config
        .required_scopes
        .iter()
        .filter(|scope| !principal.has_scope(scope))
        .collect();
    if !missing.is_empty() {
        return Err(refuse(AuthError::insufficient_scope(
            config.required_scopes.iter().cloned(),
        )));
    }
    Ok(principal)
}

/// A `quoted-string` (RFC 9110 section 5.6.4). Characters that a header value
/// cannot hold become `?`.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => out.push('?'),
        }
    }
    out.push('"');
    out
}

/// The `WWW-Authenticate` challenge for `scheme`.
fn challenge(config: &Config, scheme: &str, error: &AuthError) -> String {
    let mut params = Vec::new();
    if let Some(code) = error.code() {
        params.push(format!("error={}", quoted(code)));
        if let Some(description) = error.description() {
            params.push(format!("error_description={}", quoted(description)));
        }
    }
    let scopes = if error.scopes().is_empty() {
        &config.required_scopes
    } else {
        error.scopes()
    };
    if !scopes.is_empty() {
        params.push(format!("scope={}", quoted(&scopes.join(" "))));
    }
    params.push(format!(
        "resource_metadata={}",
        quoted(&config.metadata_url)
    ));
    for (name, value) in config.validator.challenge_params(scheme) {
        params.push(format!("{name}={}", quoted(&value)));
    }
    format!("{scheme} {}", params.join(", "))
}

fn empty_response(status: StatusCode) -> Response<AuthBody> {
    let mut response = Response::new(
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

/// The response for a refused request.
fn refusal(
    config: &Config,
    error: &AuthError,
    scheme: Option<&'static str>,
    now: SystemTime,
) -> Response<AuthBody> {
    let status = error.status();
    if status.is_server_error() {
        tracing::warn!(%error, "token validation could not complete");
        let mut response = empty_response(status);
        extend(response.headers_mut(), error.headers());
        return response;
    }
    tracing::debug!(%error, "request refused");
    let schemes: Vec<&str> = match scheme {
        Some(scheme) => vec![scheme],
        None => config.validator.schemes().to_vec(),
    };
    let www_authenticate = schemes
        .iter()
        .map(|scheme| challenge(config, scheme, error))
        .collect::<Vec<_>>()
        .join(", ");
    let mut response = match error.code() {
        Some(code) => {
            let mut body = serde_json::json!({ "error": code });
            if let Some(description) = error.description() {
                body["error_description"] = description.into();
            }
            let mut response = Response::new(
                Full::new(Bytes::from(body.to_string()))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            );
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        None => empty_response(status),
    };
    match HeaderValue::from_str(&www_authenticate) {
        Ok(value) => {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        // `quoted` keeps values printable, so only a bad scheme or param
        // name from the validator gets here. A 401 without a challenge would
        // break discovery, so answer 500.
        Err(_) => {
            tracing::error!("WWW-Authenticate challenge does not encode");
            return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    extend(response.headers_mut(), error.headers());
    config
        .validator
        .on_challenge(status, response.headers_mut(), now);
    response
}

fn extend(headers: &mut HeaderMap, extra: &HeaderMap) {
    for (name, value) in extra {
        headers.append(name, value.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::Mutex,
        time::{Duration, UNIX_EPOCH},
    };

    use async_trait::async_trait;
    use http::HeaderName;
    use tower_layer::Layer;
    use tower_service::Service;

    use super::*;

    const RESOURCE: &str = "https://mcp.example.com/mcp";
    const METADATA_URL: &str = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    /// Accepts the token "good" (and a few test tokens) in either scheme,
    /// and records the URL it was given.
    #[derive(Default)]
    struct TestValidator {
        seen_url: Mutex<Option<String>>,
    }

    #[async_trait]
    impl TokenValidator for TestValidator {
        async fn validate(
            &self,
            request: &ValidationRequest<'_>,
        ) -> Result<AuthenticatedPrincipal, AuthError> {
            *self.seen_url.lock().unwrap() = Some(request.url.to_owned());
            let base = AuthenticatedPrincipal::new()
                .with_subject("alice")
                .with_audiences([format!("{RESOURCE}?toolsets=all")])
                .with_scopes(["mcp"])
                .with_expires_at(now() + Duration::from_secs(60));
            match request.credential.token {
                "good" => Ok(base),
                "other-audience" => Ok(base.with_audiences(["https://other.example.com/mcp"])),
                "expired" => Ok(base.with_expires_at(now() - Duration::from_secs(1))),
                "no-scope" => Ok(base.with_scopes(["read"])),
                "bound" => Ok(base.with_unverified_confirmation(serde_json::json!({"jkt": "x"}))),
                "bound-verified" => {
                    Ok(base.with_verified_confirmation(serde_json::json!({"jkt": "x"})))
                }
                "outage" => Err(AuthError::unavailable("down")),
                "nonce" => Err(AuthError::oauth(StatusCode::UNAUTHORIZED, "use_dpop_nonce")
                    .with_header(
                        HeaderName::from_static("dpop-nonce"),
                        HeaderValue::from_static("n1"),
                    )),
                _ => Err(AuthError::invalid_token()),
            }
        }

        fn schemes(&self) -> &[&'static str] {
            &[super::super::BEARER, super::super::DPOP]
        }

        fn challenge_params(&self, scheme: &str) -> Vec<(&'static str, String)> {
            if scheme == super::super::DPOP {
                vec![("algs", "ES256".to_owned())]
            } else {
                Vec::new()
            }
        }

        fn on_response(
            &self,
            _principal: &AuthenticatedPrincipal,
            headers: &mut HeaderMap,
            _now: SystemTime,
        ) {
            headers.insert("x-validated", HeaderValue::from_static("1"));
        }
    }

    #[derive(Clone)]
    struct Echo;

    impl Service<Request<()>> for Echo {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<()>) -> Self::Future {
            let subject = request
                .extensions()
                .get::<AuthenticatedPrincipal>()
                .and_then(|principal| principal.subject.clone())
                .unwrap_or_default();
            std::future::ready(Ok(Response::new(Full::new(Bytes::from(subject)))))
        }
    }

    fn layer(validator: Arc<TestValidator>) -> ResourceServerLayer {
        let metadata = ProtectedResourceMetadata::new(RESOURCE).unwrap();
        ResourceServerLayer::new(validator, &metadata)
            .with_required_scopes(["mcp"])
            .with_clock(Arc::new(now))
    }

    async fn send(layer: &ResourceServerLayer, authorization: &[&str]) -> Response<AuthBody> {
        let mut builder = Request::post("/mcp?token=query-tokens-are-ignored");
        for value in authorization {
            builder = builder.header(header::AUTHORIZATION, *value);
        }
        layer
            .layer(Echo)
            .call(builder.body(()).unwrap())
            .await
            .unwrap()
    }

    async fn body(response: Response<AuthBody>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn www_authenticate(response: &Response<AuthBody>) -> &str {
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
    }

    #[tokio::test]
    async fn valid_token_reaches_the_handler_with_the_principal() {
        let validator = Arc::new(TestValidator::default());
        let layer = layer(validator.clone());
        let response = send(&layer, &["bearer good"]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-validated"], "1");
        assert_eq!(body(response).await, "alice");
        assert_eq!(
            validator.seen_url.lock().unwrap().as_deref(),
            Some("https://mcp.example.com/mcp")
        );
    }

    #[tokio::test]
    async fn missing_token_gets_a_discovery_challenge_without_error_code() {
        let layer = layer(Arc::default());
        for authorization in [&[][..], &["Basic dXNlcjpwYXNz"]] {
            let response = send(&layer, authorization).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                www_authenticate(&response),
                format!(
                    r#"Bearer scope="mcp", resource_metadata="{METADATA_URL}", DPoP scope="mcp", resource_metadata="{METADATA_URL}", algs="ES256""#
                )
            );
            assert_eq!(body(response).await, "");
        }
    }

    #[tokio::test]
    async fn invalid_tokens_get_401_invalid_token() {
        let layer = layer(Arc::default());
        let cases = [
            (&["Bearer nope"][..], None),
            (
                &["Bearer other-audience"],
                Some("token is not for this resource"),
            ),
            (&["Bearer expired"], Some("token expired")),
            (&["Bearer bound"], Some("token is bound to a key")),
            (&["Bearer"], Some("malformed credential")),
            (&["Bearer a b"], Some("malformed credential")),
            (
                &["Bearer good", "Bearer good"],
                Some("more than one Authorization header"),
            ),
        ];
        for (authorization, description) in cases {
            let response = send(&layer, authorization).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{authorization:?}"
            );
            let challenge = www_authenticate(&response).to_owned();
            assert!(
                challenge.starts_with(r#"Bearer error="invalid_token""#),
                "{challenge}"
            );
            let json: serde_json::Value = serde_json::from_str(&body(response).await).unwrap();
            assert_eq!(json["error"], "invalid_token");
            assert_eq!(json["error_description"].as_str(), description);
        }
    }

    #[tokio::test]
    async fn the_used_scheme_picks_the_challenge() {
        let layer = layer(Arc::default());
        let response = send(&layer, &["DPoP nope"]).await;
        assert_eq!(
            www_authenticate(&response),
            format!(
                r#"DPoP error="invalid_token", scope="mcp", resource_metadata="{METADATA_URL}", algs="ES256""#
            )
        );
        let response = send(&layer, &["DPoP bound-verified"]).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_scope_gets_403_insufficient_scope() {
        let layer = layer(Arc::default());
        let response = send(&layer, &["Bearer no-scope"]).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            www_authenticate(&response),
            format!(
                r#"Bearer error="insufficient_scope", scope="mcp", resource_metadata="{METADATA_URL}""#
            )
        );
    }

    #[tokio::test]
    async fn validator_errors_keep_their_code_and_headers() {
        let layer = layer(Arc::default());
        let response = send(&layer, &["DPoP nonce"]).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["dpop-nonce"], "n1");
        assert!(www_authenticate(&response).starts_with(r#"DPoP error="use_dpop_nonce""#));

        let response = send(&layer, &["Bearer outage"]).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
        assert_eq!(body(response).await, "", "the reason is not sent");
    }

    #[tokio::test]
    async fn expiry_leeway_and_public_base_url() {
        let validator = Arc::new(TestValidator::default());
        let metadata = ProtectedResourceMetadata::new(RESOURCE).unwrap();
        let layer = ResourceServerLayer::new(validator.clone(), &metadata)
            .with_expiry_leeway(Duration::from_secs(5))
            .with_public_base_url("https://proxy.example.com/prefix/")
            .unwrap()
            .with_clock(Arc::new(now));
        let response = send(&layer, &["Bearer expired"]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            validator.seen_url.lock().unwrap().as_deref(),
            Some("https://proxy.example.com/prefix/mcp")
        );
        let metadata = ProtectedResourceMetadata::new(RESOURCE).unwrap();
        for bad in ["proxy.example.com", "https://h/?q", "ftp://h"] {
            assert!(
                ResourceServerLayer::new(Arc::new(TestValidator::default()), &metadata)
                    .with_public_base_url(bad)
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn quoted_escapes_and_replaces() {
        assert_eq!(quoted(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quoted("é\n"), r#""??""#);
    }
}

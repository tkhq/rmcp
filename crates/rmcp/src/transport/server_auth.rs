//! OAuth 2.0 resource-server support for MCP servers (feature `server-auth`).
//!
//! The [MCP authorization specification] makes an HTTP MCP server an OAuth
//! 2.1 resource server. This module has the parts of that role that do not
//! depend on the token format or the authorization server:
//!
//! - [`TokenValidator`]: the trait a token format implements (JWT, opaque
//!   tokens with introspection, DPoP-bound tokens, and so on). It turns the
//!   credential of one request into an [`AuthenticatedPrincipal`], or an
//!   [`AuthError`].
//! - [`ResourceServerLayer`]: a [`tower`](https://docs.rs/tower) layer that
//!   reads the `Authorization` header (never the query string), calls the
//!   validator, checks the audience and the required scopes, and puts the
//!   principal in the request extensions. A refused request gets a 401 or 403
//!   with the `WWW-Authenticate` challenge that starts OAuth discovery.
//! - [`ProtectedResourceMetadata`]: the RFC 9728 metadata document, and
//!   [`ProtectedResourceMetadataService`], which serves it.
//! - With the `server-auth-introspection` feature,
//!   [`introspection::IntrospectionValidator`]: a validator for opaque tokens
//!   that asks the authorization server (RFC 7662).
//!
//! # Reading the principal in a handler
//!
//! `StreamableHttpService` (feature `transport-streamable-http-server`) puts the
//! request's [`http::request::Parts`] into the MCP request extensions. The
//! principal is in those parts:
//!
//! ```rust,ignore
//! use rmcp::{handler::server::tool::Extension, transport::server_auth::AuthenticatedPrincipal};
//!
//! #[tool(description = "Who am I")]
//! async fn whoami(&self, Extension(parts): Extension<http::request::Parts>) -> String {
//!     let principal = parts.extensions.get::<AuthenticatedPrincipal>().unwrap();
//!     principal.subject.clone().unwrap_or_default()
//! }
//! ```
//!
//! # What stays in your code
//!
//! The layer does not bind MCP sessions to principals, issue tokens, or decide
//! what a principal may do beyond scopes. See the `servers_resource_server_auth`
//! example for a full server.
//!
//! [MCP authorization specification]: https://modelcontextprotocol.io/specification/draft/basic/authorization

use std::{
    borrow::Cow,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, request::Parts};

#[cfg(feature = "server-auth-introspection")]
pub mod introspection;
mod layer;
mod metadata;

pub use layer::{ResourceServerLayer, ResourceServerService};
pub use metadata::{
    MetadataError, ProtectedResourceMetadata, ProtectedResourceMetadataService, WELL_KNOWN_PATH,
};

/// The `Bearer` authorization scheme (RFC 6750).
pub const BEARER: &str = "Bearer";
/// The `DPoP` authorization scheme (RFC 9449).
pub const DPOP: &str = "DPoP";

/// A source of the current time. The default is [`SystemTime::now`].
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

pub(crate) fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}

/// A token confirmation (`cnf`, RFC 7800) and whether the validator checked it.
///
/// A token with `cnf` is bound to a key (RFC 9449 DPoP, RFC 8705 mTLS).
/// Accepting it without checking the binding turns it back into a plain
/// bearer token. So [`ResourceServerLayer`] refuses a principal whose
/// confirmation is not verified.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Confirmation {
    /// The `cnf` value, for example `{"jkt": "..."}`.
    pub value: serde_json::Value,
    /// Whether the validator checked the binding for this request.
    pub verified: bool,
}

/// Who a validated token acts for. [`ResourceServerLayer`] inserts it into the
/// request extensions.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct AuthenticatedPrincipal {
    /// `sub`: the resource owner, when the token names one.
    pub subject: Option<String>,
    /// `client_id`: the OAuth client the token was issued to.
    pub client_id: Option<String>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// `aud`: the resources the token was issued for.
    pub audiences: Vec<String>,
    /// `exp`: when the token expires.
    pub expires_at: Option<SystemTime>,
    /// `cnf`: the key the token is bound to.
    pub confirmation: Option<Confirmation>,
    /// Other claims or introspection members, for application use.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

impl AuthenticatedPrincipal {
    /// An empty principal. Set fields with the `with_*` methods.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the subject.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set the client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the granted scopes.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Set the audiences.
    pub fn with_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Set the expiry.
    pub fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set a confirmation that this validator did not check. The layer
    /// refuses the principal unless a wrapping validator replaces it with
    /// [`Self::with_verified_confirmation`].
    pub fn with_unverified_confirmation(mut self, cnf: serde_json::Value) -> Self {
        self.confirmation = Some(Confirmation {
            value: cnf,
            verified: false,
        });
        self
    }

    /// Set a confirmation that this validator checked for this request, for
    /// example a DPoP proof whose key thumbprint matches `cnf.jkt`.
    pub fn with_verified_confirmation(mut self, cnf: serde_json::Value) -> Self {
        self.confirmation = Some(Confirmation {
            value: cnf,
            verified: true,
        });
        self
    }

    /// Set the other claims.
    pub fn with_claims(mut self, claims: serde_json::Map<String, serde_json::Value>) -> Self {
        self.claims = claims;
        self
    }

    /// Whether the principal holds `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }
}

/// The credential from the `Authorization` header.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Credential<'a> {
    /// The scheme, as [`TokenValidator::schemes`] spells it.
    pub scheme: &'static str,
    /// The token.
    pub token: &'a str,
}

/// What a [`TokenValidator`] gets for one request.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ValidationRequest<'a> {
    /// The request head: method, URI, headers (for example `DPoP`), and the
    /// extensions set by earlier layers.
    pub parts: &'a Parts,
    /// The credential.
    pub credential: Credential<'a>,
    /// The public URL of the request without query or fragment: the
    /// configured public base URL followed by the request path. A DPoP
    /// validator compares it with the proof's `htu`.
    pub url: &'a str,
    /// The time the layer uses for this request.
    pub now: SystemTime,
}

impl<'a> ValidationRequest<'a> {
    /// A request, for validators that call other validators and for tests.
    pub fn new(
        parts: &'a Parts,
        credential: Credential<'a>,
        url: &'a str,
        now: SystemTime,
    ) -> Self {
        Self {
            parts,
            credential,
            url,
            now,
        }
    }
}

impl<'a> Credential<'a> {
    /// A credential, for validators that call other validators and for tests.
    pub fn new(scheme: &'static str, token: &'a str) -> Self {
        Self { scheme, token }
    }
}

/// Why a request was refused.
///
/// For 4xx errors the OAuth `error` code and the description go to the
/// client, in `WWW-Authenticate` and in a JSON body. For 5xx errors the
/// description is logged and the client gets only the status.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthError {
    status: StatusCode,
    code: Option<Cow<'static, str>>,
    description: Option<String>,
    scopes: Vec<String>,
    // Boxed to keep `Result<_, AuthError>` small.
    headers: Box<HeaderMap>,
}

impl AuthError {
    fn new(status: StatusCode, code: Option<Cow<'static, str>>) -> Self {
        Self {
            status,
            code,
            description: None,
            scopes: Vec::new(),
            headers: Box::default(),
        }
    }

    /// The request has no credential, or one in a scheme the validator does
    /// not accept: 401 with no `error` code (RFC 6750 section 3.1).
    pub fn missing_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, None)
    }

    /// The token is invalid, expired, revoked, or for another resource:
    /// 401 `invalid_token`.
    pub fn invalid_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            Some(Cow::Borrowed("invalid_token")),
        )
    }

    /// The token lacks `scopes`: 403 `insufficient_scope`, with `scopes` in
    /// the challenge.
    pub fn insufficient_scope<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut error = Self::new(
            StatusCode::FORBIDDEN,
            Some(Cow::Borrowed("insufficient_scope")),
        );
        error.scopes = scopes.into_iter().map(Into::into).collect();
        error
    }

    /// Another OAuth error, for example 401 `invalid_dpop_proof` or 401
    /// `use_dpop_nonce` (RFC 9449).
    pub fn oauth(status: StatusCode, code: impl Into<Cow<'static, str>>) -> Self {
        Self::new(status, Some(code.into()))
    }

    /// The validator could not reach a dependency: 503. The client should
    /// retry, not sign in again. `reason` is only logged.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, None).with_description(reason)
    }

    /// The validator failed: 500. `reason` is only logged.
    pub fn internal(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, None).with_description(reason)
    }

    /// Set the description. For 4xx errors the client sees it as
    /// `error_description`, so it must not hold secrets.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a response header, for example `DPoP-Nonce` or `Retry-After`.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The OAuth `error` code, if any.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// The description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The scopes named in an `insufficient_scope` challenge.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Extra response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status.as_u16())?;
        if let Some(code) = &self.code {
            write!(f, " {code}")?;
        }
        if let Some(description) = &self.description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AuthError {}

/// Validates the credential of one request.
///
/// Implement this for a token format. The validator owns the format checks:
/// signature or introspection, issuer, lifetime, and any proof of possession.
/// [`ResourceServerLayer`] then checks, for every validator, that an audience
/// is this resource, that the token has not expired, that the required scopes
/// are granted, and that any confirmation was verified.
#[async_trait]
pub trait TokenValidator: Send + Sync + 'static {
    /// The principal for `request`, or why there is none.
    async fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<AuthenticatedPrincipal, AuthError>;

    /// The `Authorization` schemes this validator accepts, in challenge
    /// order. Scheme names match case-insensitively. Default: `Bearer`.
    fn schemes(&self) -> &[&'static str] {
        &[BEARER]
    }

    /// Extra auth-params for the challenge of `scheme`, for example
    /// `algs="ES256"` for `DPoP` (RFC 9449 section 7.1). Values are quoted
    /// by the layer.
    fn challenge_params(&self, scheme: &str) -> Vec<(&'static str, String)> {
        let _ = scheme;
        Vec::new()
    }

    /// Change the headers of every refused response (401, 403, 400), for
    /// example to add a fresh `DPoP-Nonce` (RFC 9449 section 8).
    fn on_challenge(&self, status: StatusCode, headers: &mut HeaderMap, now: SystemTime) {
        let _ = (status, headers, now);
    }

    /// Change the headers of an accepted request's response, for example to
    /// add the current `DPoP-Nonce`.
    fn on_response(
        &self,
        principal: &AuthenticatedPrincipal,
        headers: &mut HeaderMap,
        now: SystemTime,
    ) {
        let _ = (principal, headers, now);
    }
}

#[async_trait]
impl<T: TokenValidator + ?Sized> TokenValidator for Arc<T> {
    async fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        (**self).validate(request).await
    }

    fn schemes(&self) -> &[&'static str] {
        (**self).schemes()
    }

    fn challenge_params(&self, scheme: &str) -> Vec<(&'static str, String)> {
        (**self).challenge_params(scheme)
    }

    fn on_challenge(&self, status: StatusCode, headers: &mut HeaderMap, now: SystemTime) {
        (**self).on_challenge(status, headers, now)
    }

    fn on_response(
        &self,
        principal: &AuthenticatedPrincipal,
        headers: &mut HeaderMap,
        now: SystemTime,
    ) {
        (**self).on_response(principal, headers, now)
    }
}

/// The canonical form of a resource URI, for audience comparison: `http` or
/// `https`, lowercase scheme and host, no default port, no query or fragment,
/// and no trailing `/`. `None` when `uri` is not such a URL.
///
/// MCP clients send the URL they connected to as the `resource` (RFC 8707),
/// and that URL may carry a query that does not name another resource.
pub fn canonical_resource(uri: &str) -> Option<String> {
    let mut url = url::Url::parse(uri).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return None;
    }
    url.set_query(None);
    url.set_fragment(None);
    let text = String::from(url);
    Some(text.trim_end_matches('/').to_owned())
}

/// Compare two byte strings in time that depends only on their lengths.
///
/// Use it when a validator compares a presented secret with a stored one.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    // Keep the optimizer from turning the fold into an early exit.
    std::hint::black_box(diff) == 0
}

pub(crate) fn add_leeway(time: SystemTime, leeway: Duration) -> SystemTime {
    time.checked_add(leeway).unwrap_or(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_resource_drops_query_fragment_and_trailing_slash() {
        let cases = [
            ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp"),
            (
                "https://MCP.Example.com:443/mcp/?toolsets=all#x",
                "https://mcp.example.com/mcp",
            ),
            ("https://mcp.example.com", "https://mcp.example.com"),
            ("http://localhost:8000/mcp", "http://localhost:8000/mcp"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                canonical_resource(input).as_deref(),
                Some(expected),
                "{input}"
            );
        }
        for bad in ["mcp.example.com/mcp", "ftp://h/mcp", "urn:example:mcp", ""] {
            assert_eq!(canonical_resource(bad), None, "{bad}");
        }
    }

    #[test]
    fn constant_time_eq_matches_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn auth_error_display_and_accessors() {
        let error = AuthError::insufficient_scope(["mcp"]).with_description("needs mcp");
        assert_eq!(error.status(), StatusCode::FORBIDDEN);
        assert_eq!(error.code(), Some("insufficient_scope"));
        assert_eq!(error.scopes(), ["mcp".to_owned()]);
        assert_eq!(error.to_string(), "403 insufficient_scope: needs mcp");
        assert_eq!(AuthError::missing_credentials().to_string(), "401");
    }
}

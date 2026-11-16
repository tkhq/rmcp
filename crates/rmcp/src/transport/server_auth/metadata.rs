//! OAuth 2.0 Protected Resource Metadata (RFC 9728).

use std::{
    convert::Infallible,
    future::{Ready, ready},
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use serde::Serialize;

/// The well-known URI suffix of RFC 9728 section 3.
pub const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

/// A resource identifier that cannot be published.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("resource {resource:?} must be an http or https URL with a host and no query or fragment")]
#[non_exhaustive]
pub struct MetadataError {
    /// The refused identifier.
    pub resource: String,
}

/// The RFC 9728 metadata document for one protected resource.
///
/// Build it with [`Self::new`] and the `with_*` methods. Serve it with
/// [`ProtectedResourceMetadataService`] at [`Self::metadata_path`], and give
/// [`Self::metadata_url`] to [`super::ResourceServerLayer`] for the
/// `resource_metadata` challenge parameter.
///
/// The resource identifier is private, so it stays the URL that [`Self::new`]
/// checked. Read it with [`Self::resource`]:
///
/// ```compile_fail,E0616
/// # use rmcp::transport::server_auth::ProtectedResourceMetadata;
/// let mut metadata = ProtectedResourceMetadata::new("https://mcp.example.com/mcp").unwrap();
/// metadata.resource = "not a URL".to_owned();
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ProtectedResourceMetadata {
    /// The resource identifier: the MCP endpoint URL.
    resource: String,
    /// Authorization server issuer identifiers (RFC 8414).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    /// Scopes that clients may request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// How the resource accepts tokens. Always `["header"]` here: tokens in
    /// the query string or the body are not accepted.
    pub bearer_methods_supported: Vec<String>,
    /// A human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    /// A URL of documentation for developers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
    /// JWS algorithms accepted for DPoP proofs (RFC 9449 section 5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Whether the resource accepts only DPoP-bound tokens. Left out when
    /// `false` (RFC 9449 section 5.2: absent means `false`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dpop_bound_access_tokens_required: bool,
    /// Other members, for extensions.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ProtectedResourceMetadata {
    /// Metadata for `resource`, the public URL of the MCP endpoint, such as
    /// `https://mcp.example.com/mcp`.
    ///
    /// # Errors
    ///
    /// [`MetadataError`] when `resource` is not an `http` or `https` URL with
    /// a host, or has a query or fragment.
    pub fn new(resource: impl Into<String>) -> Result<Self, MetadataError> {
        let resource = resource.into();
        let valid = url::Url::parse(&resource).is_ok_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host().is_some()
                && url.query().is_none()
                && url.fragment().is_none()
        });
        if !valid {
            return Err(MetadataError { resource });
        }
        Ok(Self {
            resource,
            authorization_servers: Vec::new(),
            scopes_supported: None,
            bearer_methods_supported: vec!["header".to_owned()],
            resource_name: None,
            resource_documentation: None,
            dpop_signing_alg_values_supported: None,
            dpop_bound_access_tokens_required: false,
            extra: serde_json::Map::new(),
        })
    }

    /// The resource identifier that [`Self::new`] accepted.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Add an authorization server issuer identifier.
    pub fn with_authorization_server(mut self, issuer: impl Into<String>) -> Self {
        self.authorization_servers.push(issuer.into());
        self
    }

    /// Set `scopes_supported`.
    pub fn with_scopes_supported<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes_supported = Some(scopes.into_iter().map(Into::into).collect());
        self
    }

    /// Set `resource_name`.
    pub fn with_resource_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(name.into());
        self
    }

    /// Set `resource_documentation`.
    pub fn with_resource_documentation(mut self, url: impl Into<String>) -> Self {
        self.resource_documentation = Some(url.into());
        self
    }

    /// Set the DPoP members: the accepted proof algorithms, and whether only
    /// DPoP-bound tokens are accepted.
    pub fn with_dpop<I, S>(mut self, signing_algs: I, bound_tokens_required: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.dpop_signing_alg_values_supported =
            Some(signing_algs.into_iter().map(Into::into).collect());
        self.dpop_bound_access_tokens_required = bound_tokens_required;
        self
    }

    /// Add another member.
    pub fn with_extra(mut self, name: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra.insert(name.into(), value);
        self
    }

    fn origin_and_path(&self) -> (String, String) {
        // `new` checked that the resource parses.
        let url = url::Url::parse(&self.resource).expect("resource is a URL");
        let path = url.path().trim_end_matches('/').to_owned();
        (url.origin().ascii_serialization(), path)
    }

    /// The path to serve the metadata at: [`WELL_KNOWN_PATH`] followed by the
    /// resource path without a trailing `/` (RFC 9728 section 3.1). For
    /// `https://mcp.example.com/mcp` it is
    /// `/.well-known/oauth-protected-resource/mcp`.
    ///
    /// MCP clients also try the bare [`WELL_KNOWN_PATH`]. A server with one
    /// resource can serve the document there too.
    pub fn metadata_path(&self) -> String {
        format!("{WELL_KNOWN_PATH}{}", self.origin_and_path().1)
    }

    /// The full metadata URL, for the `resource_metadata` challenge
    /// parameter.
    pub fn metadata_url(&self) -> String {
        let (origin, path) = self.origin_and_path();
        format!("{origin}{WELL_KNOWN_PATH}{path}")
    }

    /// The JSON document.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("metadata serializes")
    }

    /// A service that serves this document.
    pub fn into_service(self) -> ProtectedResourceMetadataService {
        ProtectedResourceMetadataService::new(&self)
    }
}

/// A [`tower_service::Service`] that serves a [`ProtectedResourceMetadata`]
/// document.
///
/// `GET` and `HEAD` answer 200 with the JSON and
/// `Access-Control-Allow-Origin: *`, so browser-based MCP clients can read it.
/// `OPTIONS` answers a CORS preflight. Other methods answer 405. The service
/// does not look at the path; mount it at
/// [`ProtectedResourceMetadata::metadata_path`].
#[derive(Debug, Clone)]
pub struct ProtectedResourceMetadataService {
    body: Bytes,
}

impl ProtectedResourceMetadataService {
    /// A service for `metadata`.
    pub fn new(metadata: &ProtectedResourceMetadata) -> Self {
        Self {
            body: Bytes::from(metadata.to_json()),
        }
    }

    fn respond(&self, method: &Method) -> Response<Full<Bytes>> {
        let allow = HeaderValue::from_static("GET, HEAD, OPTIONS");
        let mut builder = Response::builder()
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::VARY, "Origin");
        let response = match *method {
            Method::GET | Method::HEAD => {
                let body = if method == Method::GET {
                    self.body.clone()
                } else {
                    Bytes::new()
                };
                builder = builder
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json");
                builder.body(Full::new(body))
            }
            Method::OPTIONS => builder
                .status(StatusCode::NO_CONTENT)
                .header(header::ACCESS_CONTROL_ALLOW_METHODS, allow)
                .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "*")
                .header(header::ACCESS_CONTROL_MAX_AGE, "86400")
                .body(Full::new(Bytes::new())),
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, allow)
                .body(Full::new(Bytes::new())),
        };
        response.expect("static response parts are valid")
    }
}

impl<B> tower_service::Service<Request<B>> for ProtectedResourceMetadataService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        ready(Ok(self.respond(request.method())))
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use tower_service::Service;

    use super::*;

    #[test]
    fn well_known_paths_follow_rfc_9728() {
        let cases = [
            (
                "https://mcp.example.com/mcp",
                "/.well-known/oauth-protected-resource/mcp",
            ),
            (
                "https://mcp.example.com/a/b/",
                "/.well-known/oauth-protected-resource/a/b",
            ),
            (
                "https://mcp.example.com",
                "/.well-known/oauth-protected-resource",
            ),
        ];
        for (resource, path) in cases {
            let metadata = ProtectedResourceMetadata::new(resource).unwrap();
            assert_eq!(metadata.metadata_path(), path, "{resource}");
        }
        let metadata = ProtectedResourceMetadata::new("http://localhost:8000/mcp").unwrap();
        assert_eq!(
            metadata.metadata_url(),
            "http://localhost:8000/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn builders_keep_the_checked_resource() {
        let metadata = ProtectedResourceMetadata::new("https://mcp.example.com/mcp")
            .unwrap()
            .with_authorization_server("https://auth.example.com")
            .with_scopes_supported(["mcp"])
            .with_resource_name("Example")
            .with_resource_documentation("https://docs.example.com")
            .with_dpop(["ES256"], false);
        assert_eq!(metadata.resource(), "https://mcp.example.com/mcp");
        assert_eq!(
            metadata.metadata_url(),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            metadata.metadata_path(),
            "/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn refuses_unpublishable_resources() {
        for bad in [
            "mcp.example.com/mcp",
            "https://h/mcp?x=1",
            "https://h/mcp#f",
            "ftp://h/mcp",
            "urn:example:mcp",
        ] {
            assert!(ProtectedResourceMetadata::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn serializes_set_members_only() {
        let metadata = ProtectedResourceMetadata::new("https://mcp.example.com/mcp")
            .unwrap()
            .with_authorization_server("https://auth.example.com")
            .with_scopes_supported(["mcp"])
            .with_extra("custom", serde_json::json!(1));
        let json: serde_json::Value = serde_json::from_str(&metadata.to_json()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "resource": "https://mcp.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
                "scopes_supported": ["mcp"],
                "bearer_methods_supported": ["header"],
                "custom": 1,
            })
        );
        let dpop = metadata.with_dpop(["ES256"], true);
        let json: serde_json::Value = serde_json::from_str(&dpop.to_json()).unwrap();
        assert_eq!(
            json["dpop_signing_alg_values_supported"],
            serde_json::json!(["ES256"])
        );
        assert_eq!(json["dpop_bound_access_tokens_required"], true);
    }

    #[tokio::test]
    async fn service_answers_get_options_and_405() {
        let metadata = ProtectedResourceMetadata::new("https://mcp.example.com/mcp").unwrap();
        let mut service = metadata.clone().into_service();
        let get = service
            .call(Request::get("/").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        let body = get.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, metadata.to_json().as_bytes());

        let options = service
            .call(Request::options("/").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(options.status(), StatusCode::NO_CONTENT);

        let post = service
            .call(Request::post("/").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(post.headers()[header::ALLOW], "GET, HEAD, OPTIONS");
    }
}

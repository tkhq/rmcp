//! An MCP server that acts as an OAuth resource server, with the `server-auth`
//! feature.
//!
//! - `/mcp` is behind [`ResourceServerLayer`]. It needs a bearer token for
//!   this resource with the `mcp` scope.
//! - `/.well-known/oauth-protected-resource/mcp` serves the RFC 9728 metadata
//!   that the 401 challenge points to.
//!
//! The validator is an in-memory token table, so the example runs without an
//! authorization server. A real server would use a JWT validator or
//! `IntrospectionValidator` (feature `server-auth-introspection`).
//!
//! ```sh
//! cargo run -p mcp-server-examples --example servers_resource_server_auth_streamhttp
//!
//! # 401 with WWW-Authenticate: Bearer scope="mcp", resource_metadata="..."
//! curl -i -X POST http://127.0.0.1:8000/mcp
//!
//! # The metadata
//! curl http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp
//!
//! # 403 insufficient_scope
//! curl -i -X POST -H "Authorization: Bearer read-only-token" http://127.0.0.1:8000/mcp
//!
//! # Accepted
//! curl -X POST -H "Authorization: Bearer demo-token" \
//!   -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
//!   -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
//!   http://127.0.0.1:8000/mcp
//! ```
use std::time::{Duration, SystemTime};

use anyhow::Result;
use axum::Router;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        server_auth::{
            AuthError, AuthenticatedPrincipal, ProtectedResourceMetadata, ResourceServerLayer,
            TokenValidator, ValidationRequest, WELL_KNOWN_PATH, constant_time_eq,
        },
        streamable_http_server::session::local::LocalSessionManager,
    },
};
use tower_layer::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BIND_ADDRESS: &str = "127.0.0.1:8000";
const RESOURCE: &str = "http://127.0.0.1:8000/mcp";
const AUTHORIZATION_SERVER: &str = "https://auth.example.com";

/// A fixed table of tokens. Do not use static tokens in production.
struct InMemoryValidator {
    tokens: Vec<(&'static str, AuthenticatedPrincipal)>,
}

impl InMemoryValidator {
    fn new() -> Self {
        let expires_at = SystemTime::now() + Duration::from_secs(3600);
        let principal = |subject: &str, scopes: &[&str]| {
            AuthenticatedPrincipal::new()
                .with_subject(subject)
                .with_client_id("example-client")
                .with_scopes(scopes.iter().copied())
                .with_audiences([RESOURCE])
                .with_expires_at(expires_at)
        };
        Self {
            tokens: vec![
                ("demo-token", principal("alice", &["mcp"])),
                ("read-only-token", principal("bob", &["read"])),
            ],
        }
    }
}

#[async_trait::async_trait]
impl TokenValidator for InMemoryValidator {
    async fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        let presented = request.credential.token.as_bytes();
        // Check every entry in constant time, so the answer time does not
        // reveal how much of a token matched.
        let mut found = None;
        for (token, principal) in &self.tokens {
            if constant_time_eq(token.as_bytes(), presented) {
                found = Some(principal.clone());
            }
        }
        found.ok_or_else(AuthError::invalid_token)
    }
}

#[derive(Clone)]
struct WhoAmI {
    tool_router: ToolRouter<WhoAmI>,
}

#[tool_router(router = tool_router)]
impl WhoAmI {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Return the subject and scopes of the caller's token")]
    async fn whoami(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthenticatedPrincipal>())
            .ok_or_else(|| McpError::internal_error("no authenticated principal", None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "subject={} scopes={}",
            principal.subject.as_deref().unwrap_or("-"),
            principal.scopes.join(" ")
        ))]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WhoAmI {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let metadata = ProtectedResourceMetadata::new(RESOURCE)?
        .with_authorization_server(AUTHORIZATION_SERVER)
        .with_scopes_supported(["mcp"])
        .with_resource_name("rmcp resource server example");

    let mcp_service: StreamableHttpService<WhoAmI, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(WhoAmI::new()),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default(),
        );
    let auth =
        ResourceServerLayer::new(InMemoryValidator::new(), &metadata).with_required_scopes(["mcp"]);

    // `route_service` keeps the full path, which the layer passes to the
    // validator as the request URL.
    let app = Router::new()
        .route_service("/mcp", auth.layer(mcp_service))
        .route_service(&metadata.metadata_path(), metadata.clone().into_service())
        // Clients fall back to the bare well-known path.
        .route_service(WELL_KNOWN_PATH, metadata.into_service());

    let listener = tokio::net::TcpListener::bind(BIND_ADDRESS).await?;
    tracing::info!("listening on {BIND_ADDRESS}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;
    Ok(())
}

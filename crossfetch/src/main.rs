use std::{net::SocketAddr, time::Duration};

use axum::{
    BoxError, Router,
    body::Body,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use futures_util::TryStreamExt;
use percent_encoding::percent_decode_str;
use reqwest::{Client, Url, redirect::Policy};
use thiserror::Error;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone)]
struct AppState {
    client: Client,
}

#[tokio::main]
async fn main() {
    init_tracing();

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        .user_agent(env_or_default(
            "UPSTREAM_USER_AGENT",
            "CrossFetch/0.1 (+https://xxx.com)",
        ))
        .redirect(Policy::limited(10))
        .build()
        .expect("failed to build reqwest client");

    let bind_addr = env_or_default("BIND_ADDR", "0.0.0.0:3000");
    let addr: SocketAddr = bind_addr
        .parse()
        .unwrap_or_else(|_| panic!("invalid BIND_ADDR: {bind_addr}"));

    let state = AppState { client };
    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind on {addr}: {err}"));
    info!(%addr, "proxy server listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server encountered an unrecoverable error");
}

fn init_tracing() {
    if tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with(tracing_subscriber::fmt::layer()),
    )
    .is_err()
    {
        warn!("global subscriber already set; skipping tracing init");
    }
}

fn env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/*target", any(proxy_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

async fn root() -> impl IntoResponse {
    const MESSAGE: &str = "CrossFetch is running. Use paths like /https://example.com/file.tar.gz";
    (StatusCode::OK, MESSAGE)
}

async fn proxy_handler(
    State(state): State<AppState>,
    Path(raw_target): Path<String>,
    OriginalUri(original_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if method != Method::GET && method != Method::HEAD {
        return Err(AppError::UnsupportedMethod(method.to_string()));
    }

    let target_url = build_target_url(&raw_target, original_uri.query())?;
    info!(method = %method, %target_url, "forwarding request");

    let request = copy_request_headers(
        state.client.request(method.clone(), target_url.clone()),
        &headers,
    );

    let response = request.send().await.map_err(|err| {
        warn!(error = %err, "upstream request failed");
        AppError::Upstream(err)
    })?;

    let status = response.status();
    let mut client_response = Response::new(Body::empty());
    *client_response.status_mut() = status;

    copy_response_headers(client_response.headers_mut(), response.headers());
    rewrite_redirect_location(client_response.headers_mut(), status, &target_url, &headers);

    if method == Method::HEAD {
        return Ok(client_response);
    }

    let stream = response
        .bytes_stream()
        .map_err(|err| -> BoxError { Box::new(err) });
    let body = Body::from_stream(stream);
    *client_response.body_mut() = body;

    Ok(client_response)
}

fn copy_request_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) || name == header::HOST {
            continue;
        }
        builder = builder.header(name, value.clone());
    }
    builder
}

fn copy_response_headers(dest: &mut HeaderMap, src: &HeaderMap) {
    for (name, value) in src.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        dest.insert(name.clone(), value.clone());
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn rewrite_redirect_location(
    headers: &mut HeaderMap,
    status: StatusCode,
    base_url: &Url,
    client_headers: &HeaderMap,
) {
    if !status.is_redirection() {
        return;
    }

    let Some(original_location) = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };

    let Some(resolved) = resolve_redirect_target(base_url, original_location) else {
        return;
    };

    let Some(host) = extract_client_host(client_headers) else {
        return;
    };
    let scheme = extract_client_scheme(client_headers);

    let proxied = format!("{scheme}://{host}/{}", resolved);
    if let Ok(value) = HeaderValue::from_str(&proxied) {
        headers.insert(header::LOCATION, value);
    }
}

fn resolve_redirect_target(base_url: &Url, location: &str) -> Option<Url> {
    match base_url.join(location) {
        Ok(url) => Some(url),
        Err(_) => Url::parse(location).ok(),
    }
}

fn extract_client_host(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = value.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|host| host.to_string())
}

fn extract_client_scheme(headers: &HeaderMap) -> String {
    if let Some(value) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Some(value) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for entry in value.split(',') {
            for part in entry.split(';') {
                let trimmed = part.trim();
                if let Some(proto) = trimmed.strip_prefix("proto=") {
                    let proto = proto.trim_matches('"');
                    if !proto.is_empty() {
                        return proto.to_string();
                    }
                }
            }
        }
    }

    if let Some(value) = headers
        .get("x-forwarded-protocol")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Some(value) = headers
        .get("x-forwarded-scheme")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    "https".to_string()
}

fn build_target_url(raw_target: &str, request_query: Option<&str>) -> Result<Url, AppError> {
    if raw_target.trim().is_empty() {
        return Err(AppError::MissingTarget);
    }

    let decoded = percent_decode_str(raw_target)
        .decode_utf8()
        .map_err(|_| AppError::InvalidTarget(raw_target.to_string()))?
        .into_owned();
    let trimmed = decoded.trim();

    let mut url = Url::parse(trimmed).map_err(|_| AppError::InvalidTarget(decoded.clone()))?;

    match url.scheme() {
        "http" | "https" => {}
        other => return Err(AppError::UnsupportedScheme(other.to_string())),
    }

    if let Some(extra_query) = request_query {
        if !extra_query.is_empty() {
            let merged = match url.query() {
                Some(existing) if !existing.is_empty() => format!("{existing}&{extra_query}"),
                _ => extra_query.to_string(),
            };
            url.set_query(Some(&merged));
        }
    }

    Ok(url)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install ctrl+c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        if let Ok(mut stream) = signal(SignalKind::terminate()) {
            stream.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("missing target URL in request path")]
    MissingTarget,
    #[error("invalid target URL: {0}")]
    InvalidTarget(String),
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("unsupported HTTP method: {0}")]
    UnsupportedMethod(String),
    #[error("failed to contact upstream: {0}")]
    Upstream(#[from] reqwest::Error),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingTarget | Self::InvalidTarget(_) | Self::UnsupportedScheme(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::UnsupportedMethod(_) => StatusCode::METHOD_NOT_ALLOWED,
            Self::Upstream(err) if err.is_timeout() => StatusCode::GATEWAY_TIMEOUT,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let is_method_not_allowed = matches!(&self, Self::UnsupportedMethod(_));
        let body = Body::from(format!("{}: {}\n", status.as_u16(), self));
        let mut response = (status, body).into_response();

        if is_method_not_allowed {
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_target_url_with_query() {
        let url = build_target_url("https://example.com/file", Some("version=1")).unwrap();
        assert_eq!(url.as_str(), "https://example.com/file?version=1");
    }

    #[test]
    fn build_target_url_merges_existing_query() {
        let url = build_target_url("https://example.com/file?foo=bar", Some("token=abc")).unwrap();
        assert_eq!(url.as_str(), "https://example.com/file?foo=bar&token=abc");
    }

    #[test]
    fn build_target_url_rejects_non_http() {
        let err = build_target_url("ftp://example.com/file", None).unwrap_err();
        assert!(matches!(err, AppError::UnsupportedScheme(_)));
    }

    #[test]
    fn build_target_url_empty_fails() {
        let err = build_target_url("", None).unwrap_err();
        assert!(matches!(err, AppError::MissingTarget));
    }

    #[test]
    fn rewrite_redirect_location_preserves_custom_domain() {
        let base = Url::parse("https://github.com/user/repo/releases/download/v1/app.zip").unwrap();
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            header::LOCATION,
            HeaderValue::from_static("https://objects.githubusercontent.com/package"),
        );

        let mut request_headers = HeaderMap::new();
        request_headers.insert(header::HOST, HeaderValue::from_static("proxy.example.com"));
        request_headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        rewrite_redirect_location(
            &mut response_headers,
            StatusCode::FOUND,
            &base,
            &request_headers,
        );

        let location = response_headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap();

        assert_eq!(
            location,
            "https://proxy.example.com/https://objects.githubusercontent.com/package"
        );
    }

    #[test]
    fn rewrite_redirect_location_handles_relative_paths() {
        let base = Url::parse("https://example.com/download/file").unwrap();
        let mut response_headers = HeaderMap::new();
        response_headers.insert(header::LOCATION, HeaderValue::from_static("/next"));

        let mut request_headers = HeaderMap::new();
        request_headers.insert(header::HOST, HeaderValue::from_static("proxy.test"));

        rewrite_redirect_location(
            &mut response_headers,
            StatusCode::MOVED_PERMANENTLY,
            &base,
            &request_headers,
        );

        let location = response_headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert_eq!(location, "https://proxy.test/https://example.com/next");
    }

    #[test]
    fn rewrite_redirect_location_skips_without_host() {
        let base = Url::parse("https://example.com/download/file").unwrap();
        let mut response_headers = HeaderMap::new();
        response_headers.insert(header::LOCATION, HeaderValue::from_static("/next"));
        let request_headers = HeaderMap::new();

        rewrite_redirect_location(
            &mut response_headers,
            StatusCode::TEMPORARY_REDIRECT,
            &base,
            &request_headers,
        );

        let location = response_headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert_eq!(location, "/next");
    }
}

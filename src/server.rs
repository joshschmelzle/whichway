//! Local HTTP server. Serves embedded assets at `/` and the JSON API under
//! `/api/*`. Every API call requires a session token, supplied either via
//! `?token=` or `X-Whichway-Token`. The server binds 127.0.0.1 only.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, Response, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::get,
};
use include_dir::{Dir, include_dir};
use serde::Serialize;

use whichway::collect;
use whichway::exec::is_root;
use whichway::model::{LookupResult, Section};

static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/assets");

#[derive(Clone)]
pub(crate) struct AppState {
    pub token: Arc<String>,
    pub dev_assets: Option<PathBuf>,
    pub privileged: bool,
}

pub(crate) async fn serve(
    port: u16,
    dev_assets: Option<PathBuf>,
    open_browser: bool,
) -> Result<()> {
    let token = generate_token();
    let state = AppState {
        token: Arc::new(token.clone()),
        dev_assets,
        privileged: is_root(),
    };

    let api = Router::new()
        .route("/summary", get(api_summary))
        .route("/refresh", get(api_summary))
        .route("/lookup", get(api_lookup))
        .route("/sockets", get(api_sockets))
        .route("/throughput", get(api_throughput))
        .route("/pf", get(api_pf))
        .route_layer(middleware::from_fn_with_state(state.clone(), token_check));

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/*path", get(serve_asset))
        .nest("/api", api)
        .with_state(state.clone());

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}; is port {port} already in use?"))?;

    let url = format!("http://127.0.0.1:{port}/?token={token}");
    eprintln!("whichway serving at {url}");
    if state.privileged {
        eprintln!("(running as root: sockets/throughput/pf endpoints enabled)");
    } else {
        eprintln!("(running unprivileged: run with sudo to enable sockets/throughput/pf)");
    }

    if open_browser {
        open_in_default_browser(&url);
    }

    axum::serve(listener, app).await.context("server crashed")
}

/// Fire-and-forget launch of the macOS default browser via `/usr/bin/open`.
///
/// We do not wait for the child or check its exit status; a failed browser
/// launch must never block the server. The TCP listener is already bound
/// (the kernel will queue the SYN) so the browser can connect even before
/// `axum::serve` polls its first accept.
fn open_in_default_browser(url: &str) {
    match std::process::Command::new("/usr/bin/open").arg(url).spawn() {
        Ok(_) => {}
        Err(e) => eprintln!("note: could not launch browser via `open`: {e}"),
    }
}

fn generate_token() -> String {
    use rand::RngCore;
    use std::fmt::Write as _;
    let mut buf = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut buf);
    // URL-safe base16 is fine for our purposes; no padding.
    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        let _ = write!(s, "{b:02x}");
    }
    s
}

async fn token_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let header_tok = headers
        .get("X-Whichway-Token")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let query_tok = params.get("token").cloned();
    let supplied = header_tok.or(query_tok);
    match supplied {
        Some(t) if t == *state.token => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[derive(Serialize)]
struct PrivilegedError {
    error: &'static str,
    hint: &'static str,
}

async fn api_summary(State(state): State<AppState>) -> impl IntoResponse {
    let summary = collect::collect_summary(state.privileged).await;
    Json(summary)
}

#[derive(serde::Deserialize)]
struct LookupParams {
    target: String,
    // token is consumed by middleware; tolerate it here.
    #[allow(dead_code)]
    #[serde(default)]
    token: Option<String>,
}

async fn api_lookup(
    State(state): State<AppState>,
    Query(params): Query<LookupParams>,
) -> Response<Body> {
    let summary = collect::collect_summary(state.privileged).await;
    let resolvers = summary.dns.data.clone().unwrap_or_default();
    let tunnels = summary.tunnels.data.clone().unwrap_or_default();
    let result = match collect::lookup::lookup(&params.target, &resolvers, &tunnels).await {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::json!({ "error": e.to_string() });
            return Json(body).into_response();
        }
    };
    Json::<LookupResult>(result).into_response()
}

async fn api_sockets(State(state): State<AppState>) -> Response<Body> {
    if !state.privileged {
        return privileged_error("sockets").into_response();
    }
    let section: Section<_> = match collect::collect_sockets().await {
        Ok(d) => Section::ok(d),
        Err(e) => Section::err(e.to_string()),
    };
    Json(section).into_response()
}

async fn api_throughput(State(state): State<AppState>) -> Response<Body> {
    if !state.privileged {
        return privileged_error("throughput").into_response();
    }
    let section: Section<_> = match collect::collect_throughput().await {
        Ok(d) => Section::ok(d),
        Err(e) => Section::err(e.to_string()),
    };
    Json(section).into_response()
}

async fn api_pf(State(state): State<AppState>) -> Response<Body> {
    if !state.privileged {
        return privileged_error("pf").into_response();
    }
    Json(collect::collect_pf().await).into_response()
}

const fn privileged_error(_name: &'static str) -> (StatusCode, Json<PrivilegedError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(PrivilegedError {
            error: "requires root",
            hint: "run whichway with sudo to enable this endpoint",
        }),
    )
}

async fn serve_index(State(state): State<AppState>) -> Response<Body> {
    let raw = load_asset(&state, "index.html").unwrap_or_else(|| {
        b"<!doctype html><meta charset=utf-8><title>whichway</title>missing assets\n".to_vec()
    });
    let injected = inject_token(&raw, &state.token);
    build_response(StatusCode::OK, "text/html; charset=utf-8", injected)
}

async fn serve_asset(
    State(state): State<AppState>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response<Body> {
    // Disallow escapes; we are serving from a contained tree.
    if path.contains("..") {
        return (StatusCode::BAD_REQUEST, "bad path").into_response();
    }
    let Some(bytes) = load_asset(&state, &path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let ctype = guess_content_type(&path);
    build_response(StatusCode::OK, ctype, bytes)
}

/// Build a fixed-shape `Response` that cannot fail.
///
/// Avoids the `.unwrap()` on `Response::builder()` because every call site
/// supplies a known-valid status code, header, and `Body::from(Vec<u8>)`,
/// none of which can fail. We construct the response directly instead.
fn build_response(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    resp
}

fn load_asset(state: &AppState, path: &str) -> Option<Vec<u8>> {
    if let Some(dir) = &state.dev_assets {
        let p = dir.join(path);
        if let Ok(b) = std::fs::read(&p) {
            return Some(b);
        }
    }
    ASSETS.get_file(path).map(|f| f.contents().to_vec())
}

fn inject_token(html: &[u8], token: &str) -> Vec<u8> {
    let needle = b"<!--TOKEN-->";
    html.windows(needle.len())
        .position(|w| w == needle)
        .map_or_else(
            || html.to_vec(),
            |pos| {
                let replacement = format!(
                    r#"<meta name="whichway-token" content="{}">"#,
                    html_escape(token)
                );
                let (prefix, rest) = html.split_at(pos);
                let suffix = rest.get(needle.len()..).unwrap_or(&[]);
                let mut out = Vec::with_capacity(html.len() + replacement.len());
                out.extend_from_slice(prefix);
                out.extend_from_slice(replacement.as_bytes());
                out.extend_from_slice(suffix);
                out
            },
        )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn guess_content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

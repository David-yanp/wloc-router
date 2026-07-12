use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::SecondsFormat;
use reqwest::Client;
use serde::Serialize;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    config::{canonical_host, is_allowed_host, validate_lat, validate_lon, Config, State as WlocState},
    wloc::patch_response_body,
};

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    client: Client,
}

pub async fn serve(config_path: PathBuf) -> Result<()> {
    let cfg = Config::load(config_path).await?;
    init_logging(&cfg.log_level);

    let client = build_client(&cfg)?;
    let tls = RustlsConfig::from_pem_file(&cfg.cert_path, &cfg.key_path)
        .await
        .with_context(|| {
            format!(
                "load tls cert={}, key={}",
                cfg.cert_path.display(),
                cfg.key_path.display()
            )
        })?;

    let listen = cfg.listen;
    info!(
        listen = %listen,
        state = %cfg.state_path.display(),
        "starting wloc-router"
    );

    let app_state = AppState {
        cfg: Arc::new(cfg),
        client,
    };
    let max_body_bytes = app_state.cfg.max_body_bytes;
    let app = Router::new()
        .route("/*path", any(handle))
        .with_state(app_state)
        .layer(RequestBodyLimitLayer::new(max_body_bytes));

    axum_server::bind_rustls(listen, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("wloc_router={level},tower_http=warn")))
        .unwrap_or_else(|_| EnvFilter::new("wloc_router=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn build_client(cfg: &Config) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(cfg.upstream_timeout())
        .https_only(true)
        .user_agent("wloc-router/0.1");

    for (host, addrs) in &cfg.upstream_resolve {
        builder = builder.resolve_to_addrs(host, addrs);
    }

    Ok(builder.build()?)
}

async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    req: Request<Body>,
) -> Response {
    let start = Instant::now();
    let path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let query = req
        .uri()
        .query()
        .map(parse_query)
        .unwrap_or_default();

    let host = match request_host(&headers) {
        Some(host) if is_allowed_host(host) => canonical_host(host).to_ascii_lowercase(),
        Some(host) => {
            warn!(%host, "rejecting unsupported host");
            return (StatusCode::MISDIRECTED_REQUEST, "unsupported host").into_response();
        }
        None => return (StatusCode::BAD_REQUEST, "missing host").into_response(),
    };

    if path == "/wloc-settings/save" {
        return settings_response(state, &query).await.into_response();
    }

    if method != Method::POST || path != "/clls/wloc" {
        warn!(%host, %path, %method, "rejecting unsupported path");
        return (StatusCode::NOT_FOUND, "unsupported path").into_response();
    }

    let body = match hyper::body::to_bytes(req.into_body()).await {
        Ok(body) => body,
        Err(err) => {
            warn!(%host, %path, error = %err, "failed to read request body");
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };
    if body.len() > state.cfg.max_body_bytes {
        warn!(
            %host,
            %path,
            bytes = body.len(),
            limit = state.cfg.max_body_bytes,
            "request body exceeded configured limit"
        );
        return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
    }

    match proxy_wloc(&state, &host, &path_and_query, &headers, body).await {
        Ok(resp) => {
            info!(%host, %path, elapsed_ms = start.elapsed().as_millis(), "handled wloc");
            resp
        }
        Err(err) => {
            error!(%host, %path, error = %err, "wloc upstream failed");
            (StatusCode::BAD_GATEWAY, "upstream failed").into_response()
        }
    }
}

async fn proxy_wloc(
    state: &AppState,
    host: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let url = format!("https://{host}{path_and_query}");
    let mut req = state.client.post(&url);

    for (name, value) in headers {
        if should_forward_header(name.as_str()) {
            req = req.header(name, value);
        }
    }
    req = req.header(header::HOST, host).body(body);

    let started = Instant::now();
    let upstream = req.send().await?;
    let status = upstream.status();
    let mut response_headers = upstream.headers().clone();
    let upstream_body = upstream.bytes().await?;
    info!(
        %host,
        status = status.as_u16(),
        upstream_ms = started.elapsed().as_millis(),
        bytes = upstream_body.len(),
        "upstream response"
    );

    let location = state.cfg.current_location().await;
    let output = if let Some(location) = location {
        match patch_response_body(&upstream_body, location) {
            Ok((patched, stats)) => {
                info!(
                    %host,
                    locations = stats.locations,
                    wifi = stats.wifi,
                    cell = stats.cell,
                    skipped = stats.skipped,
                    "patched wloc response"
                );
                Bytes::from(patched)
            }
            Err(err) => {
                warn!(%host, error = %err, "wloc patch failed; passing upstream body through");
                upstream_body
            }
        }
    } else {
        debug!(%host, "no configured location; passing upstream body through");
        upstream_body
    };

    response_headers.remove(header::CONTENT_ENCODING);
    response_headers.remove(header::TRANSFER_ENCODING);
    response_headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&output.len().to_string())?,
    );

    let mut response = Response::new(Body::from(output));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    Ok(response)
}

async fn settings_response(state: AppState, query: &[(String, String)]) -> Response {
    let action = query_value(query, "action").unwrap_or("save");
    let result = match action {
        "query" => query_settings(&state).await,
        "clear" => clear_settings(&state).await,
        _ => save_settings(&state, query).await,
    };

    let status = if result.success {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    let body = serde_json::to_vec(&result).unwrap_or_else(|_| b"{\"success\":false}".to_vec());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

async fn query_settings(state: &AppState) -> SettingsResult {
    let stored = state.cfg.load_state().await;
    match (stored.longitude, stored.latitude) {
        (Some(longitude), Some(latitude)) => SettingsResult {
            success: true,
            longitude: Some(longitude),
            latitude: Some(latitude),
            accuracy: Some(stored.accuracy.unwrap_or(state.cfg.accuracy)),
            updated_at: stored.updated_at,
            error: None,
        },
        _ => SettingsResult::err("no saved coordinates"),
    }
}

async fn clear_settings(state: &AppState) -> SettingsResult {
    match state.cfg.save_state(&WlocState::default()).await {
        Ok(_) => SettingsResult {
            success: true,
            ..SettingsResult::default()
        },
        Err(err) => SettingsResult::err(err.to_string()),
    }
}

async fn save_settings(state: &AppState, query: &[(String, String)]) -> SettingsResult {
    let longitude = query_value(query, "lon")
        .or_else(|| query_value(query, "longitude"))
        .and_then(|v| v.parse::<f64>().ok());
    let latitude = query_value(query, "lat")
        .or_else(|| query_value(query, "latitude"))
        .and_then(|v| v.parse::<f64>().ok());
    let accuracy = query_value(query, "acc")
        .or_else(|| query_value(query, "accuracy"))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(25);

    let (Some(longitude), Some(latitude)) = (longitude, latitude) else {
        return SettingsResult::err("missing lon/lat parameters");
    };
    if let Err(err) = validate_lon(longitude).and_then(|_| validate_lat(latitude)) {
        return SettingsResult::err(err.to_string());
    }

    let now = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let stored = WlocState {
        longitude: Some(longitude),
        latitude: Some(latitude),
        accuracy: Some(accuracy),
        updated_at: Some(now.clone()),
    };

    match state.cfg.save_state(&stored).await {
        Ok(_) => {
            info!(longitude, latitude, accuracy, "saved wloc settings");
            SettingsResult {
                success: true,
                longitude: Some(longitude),
                latitude: Some(latitude),
                accuracy: Some(accuracy),
                updated_at: Some(now),
                error: None,
            }
        }
        Err(err) => SettingsResult::err(err.to_string()),
    }
}

fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST)?.to_str().ok()
}

fn should_forward_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "connection" | "proxy-connection" | "transfer-encoding"
    )
}

fn query_value<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.as_str())
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

#[derive(Debug, Default, Serialize)]
struct SettingsResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accuracy: Option<u32>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SettingsResult {
    fn err(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_only_safe_headers() {
        assert!(!should_forward_header("host"));
        assert!(!should_forward_header("Content-Length"));
        assert!(should_forward_header("user-agent"));
    }

    #[test]
    fn reads_query_values() {
        let query = parse_query("lon=1.2&lat=3.4");
        assert_eq!(query_value(&query, "lon"), Some("1.2"));
        assert_eq!(query_value(&query, "lat"), Some("3.4"));
    }
}

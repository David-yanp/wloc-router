use std::{collections::HashMap, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const HOSTS: [&str; 2] = ["gs-loc.apple.com", "gs-loc-cn.apple.com"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub config_path: PathBuf,
    pub state_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub longitude: Option<f64>,
    pub latitude: Option<f64>,
    pub accuracy: u32,
    pub log_level: String,
    pub upstream_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub upstream_resolve: HashMap<String, Vec<SocketAddr>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct State {
    pub longitude: Option<f64>,
    pub latitude: Option<f64>,
    pub accuracy: Option<u32>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Location {
    pub longitude: f64,
    pub latitude: f64,
    pub accuracy: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "192.168.1.254:9443".parse().expect("valid default listen"),
            config_path: "/etc/wloc-router/config.toml".into(),
            state_path: "/etc/wloc-router/state.json".into(),
            cert_path: "/etc/wloc-router/certs/server.pem".into(),
            key_path: "/etc/wloc-router/certs/server-key.pem".into(),
            longitude: None,
            latitude: None,
            accuracy: 25,
            log_level: "info".to_string(),
            upstream_timeout_ms: 10_000,
            max_body_bytes: 1_048_576,
            upstream_resolve: HashMap::new(),
        }
    }
}

impl Config {
    pub async fn load(path: PathBuf) -> Result<Self> {
        let data = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&data).context("parse config toml")?;
        cfg.config_path = path;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.max_body_bytes < 1024 {
            anyhow::bail!("max_body_bytes is too small");
        }
        if self.upstream_timeout_ms < 1000 {
            anyhow::bail!("upstream_timeout_ms is too small");
        }
        if let Some(lon) = self.longitude {
            validate_lon(lon)?;
        }
        if let Some(lat) = self.latitude {
            validate_lat(lat)?;
        }
        Ok(())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_timeout_ms)
    }

    pub async fn load_state(&self) -> State {
        match tokio::fs::read_to_string(&self.state_path).await {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => State::default(),
        }
    }

    pub async fn save_state(&self, state: &State) -> Result<()> {
        if let Some(parent) = self.state_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let data = serde_json::to_vec_pretty(state)?;
        tokio::fs::write(&self.state_path, data).await?;
        Ok(())
    }

    pub async fn current_location(&self) -> Option<Location> {
        let state = self.load_state().await;
        let longitude = state.longitude.or(self.longitude)?;
        let latitude = state.latitude.or(self.latitude)?;
        let accuracy = state.accuracy.unwrap_or(self.accuracy);

        if validate_lon(longitude).is_ok() && validate_lat(latitude).is_ok() {
            Some(Location {
                longitude,
                latitude,
                accuracy,
            })
        } else {
            None
        }
    }
}

pub fn validate_lon(v: f64) -> Result<()> {
    if (-180.0..=180.0).contains(&v) {
        Ok(())
    } else {
        anyhow::bail!("longitude out of range")
    }
}

pub fn validate_lat(v: f64) -> Result<()> {
    if (-90.0..=90.0).contains(&v) {
        Ok(())
    } else {
        anyhow::bail!("latitude out of range")
    }
}

pub fn canonical_host(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

pub fn is_allowed_host(host: &str) -> bool {
    let host = canonical_host(host).to_ascii_lowercase();
    HOSTS.iter().any(|allowed| host == *allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matching_strips_port() {
        assert!(is_allowed_host("gs-loc.apple.com:443"));
        assert!(is_allowed_host("gs-loc-cn.apple.com"));
        assert!(!is_allowed_host("example.com"));
    }

    #[test]
    fn location_ranges_are_checked() {
        assert!(validate_lon(113.0).is_ok());
        assert!(validate_lon(181.0).is_err());
        assert!(validate_lat(22.0).is_ok());
        assert!(validate_lat(-91.0).is_err());
    }
}

use anyhow::{Context, Result};
use base64::Engine;

pub struct AppConfig {
    pub database_url: String,
    pub master_key: [u8; 32],
    pub host: String,
    pub port: u16,
    pub storage_path: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

        let master_key_b64 = std::env::var("MASTER_KEY").context("MASTER_KEY must be set")?;
        let master_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&master_key_b64)
            .context("MASTER_KEY must be valid base64")?;
        let master_key: [u8; 32] = master_key_bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("MASTER_KEY must be exactly 32 bytes, got {}", v.len())
        })?;

        let host = std::env::var("HOST").unwrap_or_else(|_| String::from("0.0.0.0"));

        let port: u16 = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .context("PORT must be a valid u16")?;

        let storage_path =
            std::env::var("STORAGE_PATH").unwrap_or_else(|_| "./data/blobs".to_string());

        Ok(Self {
            database_url,
            master_key,
            host,
            port,
            storage_path,
        })
    }
}

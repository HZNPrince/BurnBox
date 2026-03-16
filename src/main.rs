use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::{
    routes::{
        health::health_check,
        secrets::{create_secret, delete_secret, get_secret, AppState},
    },
    storage::{BlobStorage, LocalStorage},
};

mod config;
mod crypto;
mod db;
mod errors;
mod routes;
mod storage;
mod worker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Init Structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "burnbox=debug,tower_http=debug".into()),
        )
        .init();

    // Parse Config from env
    let config = config::AppConfig::from_env()?;
    tracing::info!("Starting BurnBox on {}:{}", config.host, config.port);

    // Init DB and run migrations
    let pool = db::init_pool(&config.database_url).await?;

    // Init Local File Storage
    let storage: Arc<dyn BlobStorage> = Arc::new(LocalStorage::new(&config.storage_path).await?);

    // Spawn background cleanup worker
    worker::spawn_cleanup_worker(pool.clone(), storage.clone());

    // Build shared app state
    let app = Arc::new(AppState {
        pool,
        master_key: config.master_key,
        storage,
    });

    // Build router
    let routes = Router::new()
        .route("/health", get(health_check))
        .route("/secrets", post(create_secret))
        .route("/secrets/{id}", get(get_secret).delete(delete_secret))
        .with_state(app);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);
    axum::serve(listener, routes).await?;

    Ok(())
}

use crate::{errors::AppError, storage::BlobStorage};
use sqlx::PgPool;
use std::sync::Arc;

pub fn spawn_cleanup_worker(pool: PgPool, storage: Arc<dyn BlobStorage>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            interval.tick().await;
            tracing::debug!("Running expiry cleanup worker...");

            if let Err(e) = cleanup_expired(&pool, &storage).await {
                tracing::error!("Cleanup worker error: {}", e);
            }
        }
    });
}

async fn cleanup_expired(pool: &PgPool, storage: &Arc<dyn BlobStorage>) -> anyhow::Result<()> {
    let expired = sqlx::query!("SELECT id, blob_path FROM secrets WHERE expires_at < now()")
        .fetch_all(pool)
        .await?;

    if expired.is_empty() {
        return Ok(());
    }
    tracing::info!("Found {} expired secrets to clean up", expired.len());

    // For Each record
    for secret in expired {
        // If the secret is a file
        if let Some(blob_path) = secret.blob_path {
            // Delete the file from storage
            if let Err(e) = storage.delete(&blob_path).await {
                tracing::warn!("Failed to delete blob for  {}: {}", secret.id, e);
            }
        }
        // Delete the secret
        if let Err(e) = sqlx::query!("DELETE FROM secrets WHERE id = $1", secret.id)
            .execute(pool)
            .await
        {
            tracing::warn!("Failed to delete expired secret  {}: {}", secret.id, e);
        } else {
            tracing::info!("Deleted expired secret: {}", secret.id);
        }
    }

    Ok(())
}

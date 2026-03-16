use crate::{crypto, errors::AppError, storage::BlobStorage};
use anyhow::anyhow;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

// Shared application state passed to every route handler
pub struct AppState {
    pub pool: PgPool,
    pub master_key: [u8; 32],
    pub storage: Arc<dyn BlobStorage>,
}

//  Request - Response Types
#[derive(Deserialize)]
pub struct CreateSecretRequest {
    pub content: String,
    pub content_type: String,
    pub password: Option<String>,
    pub burn_on_read: Option<bool>,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateSecretResponse {
    pub id: Uuid,
    pub url: String,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ViewSecretResponse {
    pub content_type: String,
    pub content: String,
    pub viewed_at: chrono::DateTime<Utc>,
}

// Handlers

// POST /secrets - create a new encrypted secret
pub async fn create_secret(
    State(app): State<Arc<AppState>>,
    Json(req): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, AppError> {
    // Validate content type
    if req.content_type != "text" && req.content_type != "file" {
        return Err(AppError::BadRequest(
            "content_type must be 'text' or 'file'".to_string(),
        ));
    }

    // Hash password if provided
    let password_hash = match req.password {
        Some(pw) => {
            if pw.len() > 30 || pw.len() < 5 {
                return Err(AppError::BadRequest(
                    "Password provided must be between 5 to 30 characters".to_string(),
                ));
            }
            Some(crypto::hash_password(&pw).map_err(|e| return AppError::Internal(e))?)
        }
        None => None,
    };

    // get burn_on_read and expiry time with following conditions
    let (expiry_time, burn_on_read) = match req.burn_on_read {
        Some(true) => {
            let secs = req.expires_in_seconds.unwrap_or(86400);
            (Utc::now() + Duration::seconds(secs), true)
        }
        Some(false) => {
            let expiry_time = req.expires_in_seconds.ok_or(AppError::BadRequest(
                "When burn_on_read is false, expiry must be provided".to_string(),
            ))?;
            (Utc::now() + Duration::seconds(expiry_time), false)
        }
        None => (Utc::now() + Duration::seconds(86400), true),
    };

    // Encrypt the content
    let payload = crypto::encrypt_secret(&app.master_key, req.content.as_bytes())
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    // For content_type = 'file' store on disk and for 'text' store inline in db
    let (ciphertext_db, blob_path) = if req.content_type == "file" {
        let id = Uuid::new_v4();
        let path = app
            .storage
            .save(id, &payload.ciphertext)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        (None, Some(path))
    } else {
        (Some(payload.ciphertext.as_slice()), None)
    };
    let id = sqlx::query_scalar!(
        r#"
            INSERT INTO secrets (
                content_type, encrypted_dek, dek_nonce,
                ciphertext, blob_path, content_nonce,
                password_hash, burn_on_read, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        "#,
        req.content_type,
        &payload.encrypted_dek,
        &payload.dek_nonce,
        ciphertext_db.as_deref(),
        blob_path,
        &payload.content_nonce,
        password_hash,
        burn_on_read,
        expiry_time,
    )
    .fetch_one(&app.pool)
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let url = format!("/secrets/{}", id);

    Ok(Json(CreateSecretResponse {
        id,
        url,
        expires_at: Some(expiry_time),
    }))
}

pub async fn get_secret(
    State(app): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ViewSecretResponse>, AppError> {
    // Fetch the secret
    let secret = sqlx::query!(
        r#"
            SELECT content_type, encrypted_dek, dek_nonce,
                ciphertext, blob_path, content_nonce,
                password_hash, burn_on_read, expires_at, viewed_at
            FROM secrets WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&app.pool)
    .await
    .map_err(|e| AppError::Internal(e.into()))?
    .ok_or(AppError::NotFound)?;

    // Security Checks
    // NOTE: these checks are being done to enforce the intervals between workers managing db and user fetching in between that interval
    if secret
        .expires_at
        .is_some_and(|expires_at| expires_at < Utc::now())
    {
        // Log the failed access
        log_access(&app.pool, id, "expired").await;
        return Err(AppError::Expired);
    }

    if secret.viewed_at.is_some() && secret.burn_on_read {
        log_access(&app.pool, id, "already_burned").await;
        return Err(AppError::AlreadyBurned);
    }

    // Check if secret is password protected
    if let Some(ref hash) = secret.password_hash {
        let password = headers
            .get("X-Secret-Password")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::PasswordRequired)?;
        let valid = crypto::verify_password(password, hash)
            .map_err(|e| AppError::BadRequest(format!("Error verifying password: {}", e)))?;

        if !valid {
            log_access(&app.pool, id, "wrong_password").await;
            return Err(AppError::Unauthorized);
        }
    }

    // Get the encrypted content (inline or from blob)
    let encrypted_content = if let Some(ref ciphertext) = secret.ciphertext {
        ciphertext.clone()
    } else if let Some(ref blob_path) = secret.blob_path {
        app.storage
            .load(blob_path)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?
    } else {
        return Err(AppError::Internal(anyhow!(
            "Secret has neither ciphertext nor blob_path"
        )));
    };

    // Decrypt the content
    let plaintext = crypto::decrypt_secret(
        &app.master_key,
        &secret.encrypted_dek,
        &secret.dek_nonce,
        &encrypted_content,
        &secret.content_nonce,
    )
    .map_err(|e| AppError::Crypto(e.to_string()))?;

    let content = String::from_utf8(plaintext).map_err(|e| AppError::Internal(e.into()))?;

    let now = Utc::now();

    if !secret.burn_on_read {
        // Mark as viewed
        sqlx::query!("UPDATE secrets SET viewed_at = $1 WHERE id = $2", now, id)
            .execute(&app.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // Log successful access
        log_access(&app.pool, id, "success").await;
    } else {
        if let Some(blob_path) = secret.blob_path {
            app.storage.delete(&blob_path).await.map_err(|e| {
                AppError::Storage(format!(
                    "Error deleting file from blob id :{}, error: {}",
                    id, e
                ))
            })?;
        }

        sqlx::query!("DELETE FROM secrets WHERE id = $1", id)
            .execute(&app.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    Ok(Json(ViewSecretResponse {
        content_type: secret.content_type,
        content: content,
        viewed_at: now,
    }))
}

// DELETE /secrets/:id -- Manually revoke a secret
pub async fn delete_secret(
    State(app): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let secret = sqlx::query!("SELECT blob_path FROM secrets WHERE id = $1", id)
        .fetch_optional(&app.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    // Delete blob if it exists
    if let Some(path) = secret.blob_path {
        app.storage
            .delete(&path)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
    }

    // DELETE from db
    sqlx::query!("DELETE FROM secrets WHERE id = $1", id)
        .execute(&app.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Json(json!({
        "status": "deleted"
    })))
}

// Helper: To log an access attempt
async fn log_access(pool: &PgPool, secret_id: Uuid, outcome: &str) {
    let _ = sqlx::query!(
        r#"
            INSERT INTO access_log (secret_id, outcome)
            VALUES ($1, $2)
        "#,
        secret_id,
        outcome,
    )
    .execute(pool)
    .await;
}

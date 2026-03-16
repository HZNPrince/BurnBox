use crate::{crypto, errors::AppError, storage::BlobStorage};
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

pub struct CreateSecretRequest {
    pub content: String,
    pub content_type: String,
    pub password: Option<String>,
    pub burn_on_read: Option<bool>,
    pub expires_in_seconds: Option<i64>,
}

pub struct CreateSecretResponse {
    pub id: Uuid,
    pub url: String,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

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
        &payload.ciphertext,
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

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Secrets not found")]
    NotFound,
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Password required")]
    PasswordRequired,
    #[error("Invalid password")]
    Unauthorized,
    #[error("Secret has already been viewed ")]
    AlreadyBurned,
    #[error("Secret has expired")]
    Expired,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Match the errors and get its corresponding status code and message
        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::PasswordRequired => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::AlreadyBurned => (StatusCode::GONE, self.to_string()),
            AppError::Expired => (StatusCode::GONE, self.to_string()),
            AppError::Crypto(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".to_string(),
            ),
            AppError::Storage(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".to_string(),
            ),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".to_string(),
            ),
        };

        let body = axum::Json(json!({
            "error": message,
        }));
        (status, body).into_response()
    }
}

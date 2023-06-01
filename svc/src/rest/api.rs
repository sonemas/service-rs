use std::sync::PoisonError;

use actix_web::{
    http::{header::ContentType, StatusCode},
    HttpResponse, ResponseError,
};
use libsvc::domain::user::{logic::UserLogicError, repository::UserRepositoryError};
use serde::Serialize;
use strum_macros::Display;

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

#[derive(Debug, Display)]
pub enum ApiError {
    NotFound,
    InvalidRequest(String),
    Unauthorized,
    Other(String),
}

impl ResponseError for ApiError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let body = match self {
            ApiError::Other(err) => ErrorResponse { error: err.clone() },
            ApiError::InvalidRequest(err) => ErrorResponse { error: err.clone() },
            _ => ErrorResponse {
                error: self.to_string(),
            },
        };

        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(serde_json::to_string(&body).expect("Couldn't create JSON body"))
    }
}

impl From<UserLogicError> for ApiError {
    fn from(value: UserLogicError) -> Self {
        match value {
            UserLogicError::Unauthorized => ApiError::Unauthorized,
            UserLogicError::ArgonError(err) => ApiError::Other(err),
            UserLogicError::ValidationError(err) => ApiError::InvalidRequest(err),
            UserLogicError::UserRepositoryError(err) => match err {
                UserRepositoryError::NotFound => ApiError::NotFound,
                UserRepositoryError::DuplicateEmail => ApiError::InvalidRequest(err.to_string()),
                UserRepositoryError::DuplicateID => ApiError::InvalidRequest(err.to_string()),
                UserRepositoryError::Other(err) => ApiError::Other(err),
            },
            UserLogicError::PoisonError(err) => ApiError::Other(err),
        }
    }
}

impl<T> From<PoisonError<T>> for ApiError {
    fn from(value: PoisonError<T>) -> Self {
        ApiError::Other(value.to_string())
    }
}

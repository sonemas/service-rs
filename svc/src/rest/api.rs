use actix_web::{middleware::Logger, App, ResponseError, http::{StatusCode, header::ContentType}, web::Json, HttpResponse, body::BoxBody, dev::Response};
use libsvc::domain::user::{logic::UserLogicError, repository::UserRepositoryError};
use serde::Serialize;
use strum_macros::Display;

use crate::Store;

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String
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
            _ => ErrorResponse{ error: self.to_string() }
        };

        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(serde_json::to_string(&body).unwrap())
    }
}

impl From<UserLogicError> for ApiError {
    fn from(value: UserLogicError) -> Self {
        match value {
            UserLogicError::Unauthorized => ApiError::Unauthorized,
            UserLogicError::BcryptError(err) => ApiError::Other(err.to_string()),
            UserLogicError::ValidationError(err) => ApiError::InvalidRequest(err.to_string()),
            UserLogicError::UserRepositoryError(err) => match err {
                UserRepositoryError::NotFound => ApiError::NotFound,
                UserRepositoryError::DuplicateEmail => ApiError::InvalidRequest(err.to_string()),
                UserRepositoryError::DuplicateID => ApiError::InvalidRequest(err.to_string()),
                UserRepositoryError::Other(err) => ApiError::Other(err.to_string()),
            }
        }
    }
}
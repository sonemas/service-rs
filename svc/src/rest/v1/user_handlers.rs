use actix_web::{get, post, put, delete, Responder, HttpResponse, web::{Data, Json}, HttpRequest, http::header};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use libsvc::domain::user::User;
use serde::Deserialize;

use crate::{Store, rest::api::ApiError};

#[derive(Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
    password_confirm: String,
}

#[post("/v1/user/register")]
pub async fn post_register(store: Data<Store>, request: Json<RegisterRequest>) -> Result<Json<User>, ApiError> {
    println!("project_get thread: {:?}", std::thread::current().id());
    let store = match store.user_logic.write() {
        Ok(store) => store,
        Err(err) => return Err(ApiError::Other(err.to_string()))
    };

    let user = store.register(&request.email, &request.password, Utc::now())?;
    Ok(Json(user))
}

#[get("/v1/user/authenticate")]
pub async fn get_authentication(store: Data<Store>, request: HttpRequest) -> Result<Json<String>, ApiError> {
    println!("project_get thread: {:?}", std::thread::current().id());
    // TODO: Check if there is a less verbose way to get the credentials.
    // Get the credentials
    let credentials = match request.headers().get(header::AUTHORIZATION) {
        Some(authorization) => {
            match authorization.to_str() {
                Ok(authorization) => match authorization.strip_prefix("Basic ") {
                    Some(encoded) => match base64::prelude::BASE64_STANDARD.decode(encoded) {
                        Ok(bytes) => match String::from_utf8(bytes) {
                            Ok(credentials) => credentials,
                            Err(err) => return Err(ApiError::Other(err.to_string()))
                        }
                        Err(err) => return Err(ApiError::Other(err.to_string()))
                    }
                    None => return Err(ApiError::InvalidRequest("Basic auth credentials missing in authorization header".to_string())),
                }
                Err(err) => return Err(ApiError::Other(err.to_string()))
            }
            
        },
        None => return Err(ApiError::InvalidRequest("Basic auth credentials missing in authorization header".to_string()))
    };

    // Split the credentials into login and password.
    let credentials: Vec<&str> = credentials.split(":").collect();
    if credentials.len() != 2 {
        return Err(ApiError::InvalidRequest("Basic auth credentials should be the base64 value of username:passsword".to_string()));
    }

    let store = match store.user_logic.read() {
        Ok(store) => store,
        Err(err) => return Err(ApiError::Other(err.to_string()))
    };


    let session = store.authenticate(&credentials[0], &credentials[1])?;
    Ok(Json("token".to_string()))
}
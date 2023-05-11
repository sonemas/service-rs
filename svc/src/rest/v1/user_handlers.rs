use actix_web::{get, post, put, delete, Responder, HttpResponse, web::{Data, Json}, HttpRequest, http::header, HttpMessage};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use jsonwebtoken::{encode, Header, EncodingKey};
use libsvc::domain::user::{User, session::{Session, Signed}};
use serde::{Deserialize, Serialize};

use crate::{Store, rest::{api::ApiError, jwt::{TokenClaims, JwtMiddleware}}};

#[derive(Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
    password_confirm: String,
}

#[post("/v1/user/register")]
pub async fn post_register(store: Data<Store>, request: Json<RegisterRequest>) -> Result<Json<User>, ApiError> {
    let store = match store.user_logic.write() {
        Ok(store) => store,
        Err(err) => return Err(ApiError::Other(err.to_string()))
    };

    let user = store.register(&request.email, &request.password, Utc::now())?;
    Ok(Json(user))
}

#[derive(Serialize)]
pub struct AuthenticationResponse{token: String}

#[get("/v1/user/authenticate")]
pub async fn get_authentication(store: Data<Store>, request: HttpRequest) -> Result<Json<AuthenticationResponse>, ApiError> {
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

    let session = match store.user_logic.read() {
        Ok(store) => store.authenticate(&credentials[0], &credentials[1])?,
        Err(err) => return Err(ApiError::Other(err.to_string()))
    };

    let iat = session.issued_at().timestamp();
    let exp = session.expires_at().timestamp();
    let sub = session.user_id();
    let iss: String = session.issuer();
    let id = session.id();
    let sig = session.signature().to_owned();
    let claims  = TokenClaims {
        sub,
        exp,
        iat,
        iss,
        id,
        sig,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(store.jwt_secret.as_ref()),
    )
    .unwrap();
    Ok(Json(AuthenticationResponse{token}))
}

#[get("/v1/user/test")]
pub async fn get_test(raw: HttpRequest, store: Data<Store>,_: JwtMiddleware) -> Result<Json<String>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().unwrap();
    Ok(Json(session.user_id()))
}
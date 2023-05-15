use actix_web::{get, post, put, delete, Responder, HttpResponse, web::{Data, Json}, HttpRequest, http::header, HttpMessage};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use jsonwebtoken::{encode, Header, EncodingKey};
use libsvc::domain::user::{User, session::{Session, Signed}};
use serde::{Deserialize, Serialize};

use crate::{Store, rest::{api::ApiError, middleware::{jwt_auth::{TokenClaims, JwtMiddleware}, basic_auth::BasicAuthMiddleware}}};

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
pub async fn get_authentication(store: Data<Store>, raw: HttpRequest,_: BasicAuthMiddleware) -> Result<Json<AuthenticationResponse>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");

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
    ).expect("Couldn't encode token");
    Ok(Json(AuthenticationResponse{token}))
}

#[get("/v1/user/test")]
pub async fn get_test(store: Data<Store>, raw: HttpRequest,_: JwtMiddleware) -> Result<Json<String>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(session.user_id()))
}
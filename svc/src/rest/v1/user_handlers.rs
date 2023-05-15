use actix_web::{get, post, put, delete, web::{Data, Json}, HttpRequest, HttpMessage};
use chrono::Utc;
use jsonwebtoken::{encode, Header, EncodingKey};
use libsvc::domain::user::{User, session::{Session, Signed}};
use serde::{Deserialize, Serialize};

use crate::{Store, rest::{api::ApiError, middleware::{jwt_auth::{TokenClaims, JwtMiddleware}, basic_auth::BasicAuthMiddleware}}};

#[derive(Deserialize)]
pub struct CreateRequest {
    email: String,
    password: String,
    password_confirm: String,
}

// TODO: Request tracing containing now and tracing values.
#[post("/v1/user")]
pub async fn post_create(store: Data<Store>, req: Json<CreateRequest>, raw: HttpRequest,_: JwtMiddleware) -> Result<Json<User>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(store.user_logic.write()?.create(&session, &req.email, &req.password, Utc::now())?))
}

#[get("/v1/user")]
pub async fn get_read(store: Data<Store>, raw: HttpRequest,_: JwtMiddleware) -> Result<Json<Vec<User>>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(store.user_logic.read()?.read(session)?))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
    password_confirm: String,
}

#[post("/v1/user/register")]
pub async fn post_register(store: Data<Store>, request: Json<RegisterRequest>) -> Result<Json<User>, ApiError> {
    Ok(Json(store.user_logic.write()?.register(&request.email, &request.password, Utc::now())?))
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

// #[get("/v1/user/test")]
// pub async fn get_test(store: Data<Store>, raw: HttpRequest,_: JwtMiddleware) -> Result<Json<String>, ApiError> {
//     let ext = raw.extensions();
//     let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
//     Ok(Json(session.user_id()))
// }
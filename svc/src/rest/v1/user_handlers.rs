use actix_web::{
    delete, get, post, put,
    web::{self, Data, Json, Path},
    HttpMessage, HttpRequest, Scope,
};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use libsvc::domain::user::{
    logic::UserUpdate,
    session::{Id, Session, Signed},
    User,
};
use serde::{Deserialize, Serialize};

use crate::{
    rest::{
        api::ApiError,
        middleware::{
            basic_auth::BasicAuthMiddleware,
            jwt_auth::{JwtMiddleware, TokenClaims},
        },
    },
    store::Store,
};

#[derive(Deserialize)]
pub struct CreateRequest {
    email: String,
    password: String,
    password_confirm: String,
}

// TODO: Request tracing containing now and tracing values.
#[post("/")]
pub async fn post_create(
    store: Data<Store>,
    req: Json<CreateRequest>,
    raw: HttpRequest,
    _: JwtMiddleware,
) -> Result<Json<User>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(store.user_logic.write()?.create(
        session,
        &req.email,
        &req.password,
        Utc::now(),
    )?))
}

#[get("/")]
pub async fn get_read(
    store: Data<Store>,
    raw: HttpRequest,
    _: JwtMiddleware,
) -> Result<Json<Vec<User>>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(store.user_logic.read()?.read(session)?))
}

#[get("/{id}")]
pub async fn get_read_by_id(
    store: Data<Store>,
    path: Path<(Id,)>,
    raw: HttpRequest,
    _: JwtMiddleware,
) -> Result<Json<User>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(
        store
            .user_logic
            .read()?
            .read_by_id(session, path.into_inner().0)?,
    ))
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    email: Option<String>,
    password: Option<String>,
    password_confirm: Option<String>,
}

#[put("/{id}")]
pub async fn put_update(
    store: Data<Store>,
    req: Json<UpdateRequest>,
    path: Path<(Id,)>,
    raw: HttpRequest,
    _: JwtMiddleware,
) -> Result<Json<User>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    let update = UserUpdate {
        id: path.into_inner().0,
        email: req.email.clone(),
        password: req.password.clone(),
        now: Utc::now(),
    };
    Ok(Json(store.user_logic.write()?.update(session, update)?))
}

#[delete("/{id}")]
pub async fn delete(
    store: Data<Store>,
    path: Path<(Id,)>,
    raw: HttpRequest,
    _: JwtMiddleware,
) -> Result<Json<()>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
    Ok(Json(
        store
            .user_logic
            .write()?
            .delete(session, path.into_inner().0)?,
    ))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
    password_confirm: String,
}

#[post("/register")]
pub async fn post_register(
    store: Data<Store>,
    request: Json<RegisterRequest>,
) -> Result<Json<User>, ApiError> {
    Ok(Json(store.user_logic.write()?.register(
        &request.email,
        &request.password,
        Utc::now(),
    )?))
}

#[derive(Serialize)]
pub struct AuthenticationResponse {
    token: String,
}

#[get("/authenticate")]
pub async fn get_authentication(
    store: Data<Store>,
    raw: HttpRequest,
    _: BasicAuthMiddleware,
) -> Result<Json<AuthenticationResponse>, ApiError> {
    let ext = raw.extensions();
    let session = ext.get::<Session<Signed>>().expect("Couldn't get session");

    let iat = session.issued_at().timestamp();
    let exp = session.expires_at().timestamp();
    let sub = session.user_id();
    let iss: String = session.issuer();
    let id = session.id();
    let sig = session.signature().to_owned();
    let claims = TokenClaims {
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
    .expect("Couldn't encode token");
    Ok(Json(AuthenticationResponse { token }))
}

// #[get("/v1/user/test")]
// pub async fn get_test(store: Data<Store>, raw: HttpRequest,_: JwtMiddleware) -> Result<Json<String>, ApiError> {
//     let ext = raw.extensions();
//     let session = ext.get::<Session<Signed>>().expect("Couldn't get session");
//     Ok(Json(session.user_id()))
// }

pub fn scope() -> Scope {
    web::scope("/users")
        .service(post_register)
        .service(get_authentication)
        .service(post_create)
        .service(get_read)
        .service(get_read_by_id)
        .service(put_update)
        .service(delete)
}

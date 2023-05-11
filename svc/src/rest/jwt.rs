use core::fmt;
use std::future::{ready, Ready};
use std::time::{UNIX_EPOCH, Duration};

use actix_web::error::ErrorUnauthorized;
use actix_web::web::Json;
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpMessage, HttpRequest};
use chrono::{Utc, TimeZone, DateTime};
use jsonwebtoken::{decode, DecodingKey, Validation};
use libsvc::domain::user::session::{Session, Signed, Id};
use serde::{Serialize, Deserialize};

use crate::Store;

use super::api::{ApiError, ErrorResponse};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub id: Id,
    pub sig: Vec<u8>,
}

pub struct JwtMiddleware {
    pub session: Session<Signed>,
}

impl FromRequest for JwtMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // Get the store.
        let store = req.app_data::<web::Data<Store>>().unwrap();

        // Get the token from the request.
        let token = req
            .headers()
                .get(http::header::AUTHORIZATION)
                .map(|h| h.to_str().unwrap().split_at(7).1.to_string());

        // Return an error if there is no token.
        if token.is_none() {
            return ready(Err(ErrorUnauthorized("no token")));
        }

        // Get the claims from the token.
        let claims = match decode::<TokenClaims>(
            &token.unwrap(),
            &DecodingKey::from_secret(store.jwt_secret.as_ref()),
            &Validation::default(),
        ) {
            Ok(c) => c.claims,
            Err(_) => {
                return ready(Err(ErrorUnauthorized("invalid token")));
            }
        };

        // Restore the session.
        let issued_at = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(claims.iat.try_into().unwrap()));
        let expires_at = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(claims.exp.try_into().unwrap()));
        let session = Session::restore(claims.id, claims.sub, &claims.iss, issued_at, expires_at, &claims.sig);
        if !store.user_logic.read().unwrap().is_valid_session(&session) { return ready(Err(ErrorUnauthorized("invalid session"))); }
        
        // Add the session to the request, so that handlers can access it.
        req.extensions_mut()
            .insert::<Session<Signed>>(session.clone());

        // Return the session.
        ready(Ok(JwtMiddleware { session }))
    }
}
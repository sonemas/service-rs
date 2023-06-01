use std::future::{ready, Ready};
use std::time::{Duration, UNIX_EPOCH};

use actix_web::error::{ErrorBadRequest, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpMessage, HttpRequest};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, DecodingKey, Validation};
use libsvc::domain::user::session::{Id, Session, Signed};
use serde::{Deserialize, Serialize};

use crate::store::Store;

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
        let store = req
            .app_data::<web::Data<Store>>()
            .expect("Couldn't get store");

        // Get the token from the request.
        let token = req.headers().get(http::header::AUTHORIZATION).map(|h| {
            h.to_str()
                .expect("Couldn't get header string")
                .split_at(7)
                .1
                .to_string()
        });

        // Return an error if there is no token.
        if token.is_none() {
            return ready(Err(ErrorBadRequest("no token")));
        }

        // Get the claims from the token.
        let claims = match decode::<TokenClaims>(
            &token.expect("Couldn't get value"),
            &DecodingKey::from_secret(store.jwt_secret.as_ref()),
            &Validation::default(),
        ) {
            Ok(c) => c.claims,
            Err(_) => {
                return ready(Err(ErrorBadRequest("invalid token")));
            }
        };

        // Restore the session.
        let issued_at = DateTime::<Utc>::from(
            UNIX_EPOCH
                + Duration::from_secs(claims.iat.try_into().expect("Couldn't convert datetime")),
        );
        let expires_at = DateTime::<Utc>::from(
            UNIX_EPOCH
                + Duration::from_secs(claims.exp.try_into().expect("Couldn't convert datetime")),
        );
        let session = Session::restore(
            claims.id,
            claims.sub,
            &claims.iss,
            issued_at,
            expires_at,
            &claims.sig,
        );
        if !store
            .user_logic
            .read()
            .expect("Couldn't get user logic")
            .is_valid_session(&session)
        {
            return ready(Err(ErrorUnauthorized("invalid session")));
        }

        // Add the session to the request, so that handlers can access it.
        req.extensions_mut()
            .insert::<Session<Signed>>(session.clone());

        // Return the session.
        ready(Ok(JwtMiddleware { session }))
    }
}

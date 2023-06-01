use std::future::{ready, Ready};

use actix_web::error::{ErrorBadRequest, ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpMessage, HttpRequest};
use base64::Engine;
use libsvc::domain::user::session::{Session, Signed};

use crate::store::Store;

pub struct BasicAuthMiddleware {
    pub session: Session<Signed>,
}

impl FromRequest for BasicAuthMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // Get the store.
        let store = req
            .app_data::<web::Data<Store>>()
            .expect("Couldn't get store");

        // Get the credentials from the request.
        let encoded = req.headers().get(http::header::AUTHORIZATION).map(|h| {
            h.to_str()
                .expect("Couldn't get header string")
                .split_at(6)
                .1
                .to_string()
        });

        // Return an error if there is no token.
        if encoded.is_none() {
            return ready(Err(ErrorBadRequest("no token")));
        }

        let credentials =
            match base64::prelude::BASE64_STANDARD.decode(encoded.expect("Couldn't get value")) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(credentials) => credentials,
                    Err(err) => return ready(Err(ErrorBadRequest(err.to_string()))),
                },
                Err(err) => return ready(Err(ErrorBadRequest(err.to_string()))),
            };
        // Removed the split from the match statement, due to lifetime problem.
        // TODO: Improve this code.
        let credentials = credentials.split(':').collect::<Vec<&str>>();

        // Return an error if there is no token.
        if credentials.len() != 2 {
            return ready(Err(ErrorBadRequest(
                "Authorization header should be Basic with base64 encoded login:password",
            )));
        }

        let session = match store.user_logic.read() {
            Ok(store) => match store.authenticate(credentials[0], credentials[1]) {
                Ok(session) => session,
                Err(_) => return ready(Err(ErrorUnauthorized("Unauthorized"))),
            },
            Err(err) => {
                return ready(Err(ErrorInternalServerError(err.to_string())));
            }
        };

        // Add the session to the request, so that handlers can access it.
        req.extensions_mut()
            .insert::<Session<Signed>>(session.clone());

        // Return the session.
        ready(Ok(BasicAuthMiddleware { session }))
    }
}

use warp::{http::Method, Filter};

use crate::Store;
use super::{return_error, user_handlers, user_requests::UserRegistrationRequest};

fn with_store(
    store: Store,
) -> impl Filter<Extract = (Store,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || store.clone())
}

fn with_json_user_registration_request() -> impl Filter<Extract = (UserRegistrationRequest,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub fn api(
    store: Store,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_header("content-type")
        .allow_methods(&[Method::PUT, Method::DELETE, Method::GET, Method::POST]);
    
    let post_register_user = warp::post()
        .and(warp::path("user"))
        .and(warp::path("register"))
        .and(warp::path::end())
        .and(with_store(store.clone()))
        .and(with_json_user_registration_request())
        .and_then(user_handlers::register);

    post_register_user
        .with(cors)
        .recover(return_error)
}
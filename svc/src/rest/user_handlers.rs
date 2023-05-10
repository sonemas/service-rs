use chrono::Utc;

use crate::Store;

use super::user_requests::UserRegistrationRequest;

pub async fn register(store: Store, request: UserRegistrationRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // TODO: Error handling instead of unwrap.
    match store.authentication_logic.write().unwrap().register(&request.email, &request.password, Utc::now()) {
        Err(err) => panic!("{}", err),
        Ok(user) => Ok(warp::reply::json(&user))
    }
}
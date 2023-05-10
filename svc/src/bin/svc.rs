use std::{error::Error, sync::{Arc, RwLock}};
use libsvc::domain::user::{service::{UserService, AuthenticationService}, session::{manager::SessionManager}, repository::memory::Memory};
use svc::{Store, rest::api::api};
use warp::{
    filters::{body::BodyDeserializeError, cors::CorsForbidden},
    http::{StatusCode, Method},
    reject::Reject,
    Rejection, Reply, Filter,
};

#[tokio::main]
async fn main() -> Result<(), &'static dyn Error> {
    run().await
}

async fn run() -> Result<(), &'static dyn Error> {
    let session_manager = SessionManager::new()
        .with_issuer("Sonemas LLC")
        .build();

    let user_repo = Arc::new(RwLock::new(Memory::new()));

    let user_service = Arc::new(RwLock::new(UserService::new(user_repo.clone())));
    let authentication_service = Arc::new(RwLock::new(AuthenticationService::new(user_repo, session_manager)));

    let store = Store::new(
        authentication_service, 
        user_service,
    );
    
    warp::serve(api(store)).run(([127, 0, 0, 1], 3000)).await;
    Ok(())
}

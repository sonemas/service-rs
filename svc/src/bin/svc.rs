use std::{sync::{Arc, RwLock}};
use libsvc::domain::user::{service::UserService, session::{manager::SessionManager}, repository::memory::Memory};
use actix_web::{HttpServer, App, web::Data, middleware::Logger};
use svc::{Store, rest::v1::user_handlers};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let session_manager = Arc::new(SessionManager::new()
        .with_issuer("Sonemas LLC")
        .build());

    let user_repo = Arc::new(RwLock::new(Memory::new()));
    let user_service = Arc::new(RwLock::new(UserService::new(user_repo.clone(), session_manager.clone())));
    let store = Store::new(user_service);

    HttpServer::new(move || {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .app_data(Data::new(store.clone()))
            .service(user_handlers::post_register)
            .service(user_handlers::get_authentication)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

// pub fn prepare_store() -> Store {
//     let session_manager = SessionManager::new()
//         .with_issuer("Sonemas LLC")
//         .build();

//     let user_repo = Arc::new(RwLock::new(Memory::new()));

//     let user_service = Arc::new(RwLock::new(UserService::new(user_repo.clone(), session_manager)));

//     Store::new(
//         user_service,
//     )
// }

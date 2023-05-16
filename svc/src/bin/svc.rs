use std::{sync::{Arc, RwLock}};
use actix_cors::Cors;
use libsvc::domain::user::{service::UserService, session::{manager::SessionManager}, repository::memory::Memory};
use actix_web::{HttpServer, App, web::Data, middleware::Logger, http::header};
use svc::{Store, rest::v1};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let store = prepare_store();

    HttpServer::new(move || {
        let logger = Logger::default();
        let cors = Cors::default()
            //.allowed_origin("*")
            .send_wildcard()
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ])
            .supports_credentials();

        App::new()
            .wrap(logger)
            .wrap(cors)
            .app_data(Data::new(store.clone()))
            .service(v1::api())
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

pub fn prepare_store() -> Store {
    let session_manager = SessionManager::new()
        .with_issuer("Sonemas LLC")
        .build();

    let user_repo = Arc::new(RwLock::new(Memory::new()));
    let user_service = Arc::new(RwLock::new(UserService::new(user_repo.clone(), Arc::new(session_manager))));
    // TODO: Set better seed phrase.
    Store::new(user_service, "blablabla")
}

use actix_cors::Cors;
use actix_web::{dev::Server, http::header, web::Data, App, HttpServer};
use futures::future;
use libsvc::domain::user::{
    repository::memory::Memory, service::UserService, session::manager::SessionManager,
};
use secrecy::ExposeSecret;
use std::{
    net::TcpListener,
    sync::{Arc, RwLock},
};
use tracing_actix_web::TracingLogger;

use crate::{rest::v1, store::Store};

pub struct Application {
    application_port: u16,
    debug_port: u16,
    application_server: Server,
    debug_server: Server,
}

#[derive(Debug)]
pub enum ApplicationError {
    IoError(std::io::Error),
}

impl From<std::io::Error> for ApplicationError {
    fn from(value: std::io::Error) -> Self {
        ApplicationError::IoError(value)
    }
}

impl Application {
    pub async fn build(
        configuration: crate::configuration::Configuration,
    ) -> Result<Self, ApplicationError> {
        let application_address =
            format_address(&configuration.server.host, configuration.server.api_port);
        let application_listener = TcpListener::bind(application_address)?;
        let application_port = application_listener.local_addr().unwrap().port();
        let application_server =
            run_application_server(application_listener, &configuration.authentication).await?;

        let debug_address =
            format_address(&configuration.server.host, configuration.server.debug_port);
        let debug_listener = TcpListener::bind(debug_address)?;
        let debug_port = debug_listener.local_addr().unwrap().port();
        let debug_server = run_debug_server(debug_listener).await?;

        let application = Self {
            application_port,
            debug_port,
            application_server,
            debug_server,
        };

        Ok(application)
    }

    pub async fn serve(self) -> Result<(), ApplicationError> {
        future::try_join(self.application_server, self.debug_server).await?;
        Ok(())
    }
}

fn format_address(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

async fn run_application_server(
    listener: TcpListener,
    auth_conf: &crate::configuration::Authentication,
) -> Result<Server, ApplicationError> {
    let store = Data::new(prepare_store(auth_conf));

    let server = HttpServer::new(move || {
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
            .wrap(TracingLogger::default())
            .wrap(cors)
            .app_data(store.clone())
            .service(v1::api())
    })
    .listen(listener)?
    .run();
    Ok(server)
}

async fn run_debug_server(listener: TcpListener) -> Result<Server, ApplicationError> {
    let server = HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .service(v1::debug_handlers::api())
    })
    .listen(listener)?
    .run();
    Ok(server)
}

pub fn prepare_store(auth_conf: &crate::configuration::Authentication) -> Store {
    let session_manager = SessionManager::build().with_issuer("Sonemas LLC").finish();

    let user_repo = Arc::new(RwLock::new(Memory::new()));
    let user_service = Arc::new(RwLock::new(UserService::new(
        user_repo,
        Arc::new(session_manager),
    )));
    Store::new(user_service, auth_conf.jwt_seed.expose_secret())
}

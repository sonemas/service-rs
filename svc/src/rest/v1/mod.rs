use actix_web::{Scope, web};

pub mod user_handlers;
pub mod debug_handlers;

pub fn api() -> Scope {
    web::scope("v1")
        .service(user_handlers::scope())
}
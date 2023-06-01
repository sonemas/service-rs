use actix_web::{web, Scope};

pub mod debug_handlers;
pub mod user_handlers;

pub fn api() -> Scope {
    web::scope("v1").service(user_handlers::scope())
}

use std::sync::{Arc, RwLock};

use libsvc::domain::user::logic::{UserLogic, AuthenticationLogic};

pub mod rest;

#[derive(Clone)]
pub struct Store {
    pub authentication_logic: Arc<RwLock<dyn AuthenticationLogic + Send + Sync>>,
    pub user_logic: Arc<RwLock<dyn UserLogic + Send + Sync>>,
}

impl Store {
    pub fn new(
        authentication_logic: Arc<RwLock<dyn AuthenticationLogic + Send + Sync>>,
        user_logic: Arc<RwLock<dyn UserLogic + Send + Sync>>) -> Self {
        Self { authentication_logic, user_logic }
    }
}
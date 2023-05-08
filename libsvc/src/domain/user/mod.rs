//! Provides functionality for dealing with users.
pub use bcrypt::BcryptError;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::foundation::id::Id;

pub mod logic;
pub mod repository;
pub mod service;
pub mod session;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct User {
    id: Id,
    email: String,
    password: String,
    date_created: DateTime<Utc>,
    date_updated: DateTime<Utc>,
}

impl User {
    pub fn new(
        id: Id,
        email: &str,
        password: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, BcryptError> {
        let password = hash(password, DEFAULT_COST)?;
        Ok(Self {
            id,
            email: email.to_string(),
            password,
            date_created: now,
            date_updated: now,
        })
    }

    pub fn validate_password(&self, password: &str) -> Result<bool, BcryptError> {
        verify(password, &self.password)
    }

    pub fn set_password(&mut self, password: &str) -> Result<(), BcryptError> {
        self.password = hash(password, DEFAULT_COST)?;
        Ok(())
    }
}

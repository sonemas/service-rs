//! Provides functionality for dealing with users.
use argon2::{
    password_hash::{Error, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::foundation::id::Id;

pub mod logic;
pub mod repository;
pub mod service;
pub mod session;

fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());

    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None)?,
    )
    .hash_password(password.as_bytes(), &salt)?
    .to_string();

    Ok(password_hash)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct User {
    id: Id,
    email: String,
    #[serde(skip_serializing)]
    password_hash: String,
    date_created: DateTime<Utc>,
    date_updated: DateTime<Utc>,
}

impl User {
    pub fn new(id: Id, email: &str, password: &str, now: DateTime<Utc>) -> Result<Self, Error> {
        // let password = hash(password, DEFAULT_COST)?;
        let password_hash = hash_password(password)?;
        Ok(Self {
            id,
            email: email.to_string(),
            password_hash,
            date_created: now,
            date_updated: now,
        })
    }

    pub fn validate_password(&self, password: &str) -> Result<bool, Error> {
        let expected_password_hash = PasswordHash::new(&self.password_hash)?;

        match Argon2::default().verify_password(password.as_bytes(), &expected_password_hash) {
            Ok(_) => Ok(true),
            Err(Error::Password) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn set_password(&mut self, password: &str) -> Result<(), Error> {
        self.password_hash = hash_password(password)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn user_can_hash_and_validate_passwords() {
        let user = User::new(Id::new(), "test@example.com", "testtest", Utc::now())
            .expect("Should be able to create new user");
        user.validate_password("testtest")
            .expect("Should be able to validate password");
    }
}

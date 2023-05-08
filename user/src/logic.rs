use std::{fmt::Display, error::Error};
use auth::session::{Session, Signed};
use chrono::{DateTime, Utc};
use foundation::id::Id;

use crate::{User, BcryptError};
pub use crate::repository::RepositoryError;

#[derive(Debug, PartialEq)]
pub enum LogicError {
    BcryptError(String),
    ValidationError(String),
    RepositoryError(RepositoryError)
}

impl From<BcryptError> for LogicError {
    fn from(value: BcryptError) -> Self {
        LogicError::BcryptError(format!("{}", value))
    }
}

impl From<RepositoryError> for LogicError {
    fn from(value: RepositoryError) -> Self {
        LogicError::RepositoryError(value)
    }
}

impl Display for LogicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogicError::BcryptError(err) => write!(f, "{}", err),
            LogicError::ValidationError(err) => write!(f, "{}", err),
            LogicError::RepositoryError(err) => write!(f, "{}", err),
        }
    }
}

impl Error for LogicError {}

/// Uses options to indicate which fields are updated.
pub struct Update {
    pub id: Id,
    pub email: Option<&'static str> ,
    pub password: Option<&'static str>,
    pub now: DateTime<Utc>,
}

/// Business logic that's to be implemented by every BL provider.
pub trait Logic {
    /// Add a new user to the service.
    fn create(&self, session: &Session<Signed>, email: &str, password: &str, now: DateTime<Utc>) -> Result<User, LogicError>;
    
    /// Read users from the service.
    fn read(&self, session: &Session<Signed>) -> Result<Vec<User>, LogicError>;
    
    /// Read a single user by id.
    fn read_by_id(&self, session: &Session<Signed>, id: Id) -> Result<User, LogicError>;
    
    /// Read a single user by email.
    fn read_by_email(&self, session: &Session<Signed>, email: &str) -> Result<User, LogicError>;
    
    /// Update a user with the provided data.
    fn update(&self, session: &Session<Signed>, update: Update) -> Result<(), LogicError>;
    
    /// Delete a user from the service.
    fn delete(&self,  session: &Session<Signed>, id: Id) -> Result<(), LogicError>;
    
    // TODO: Purge feature.
}
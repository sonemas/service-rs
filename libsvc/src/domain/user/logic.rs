use bcrypt::BcryptError;
use chrono::{DateTime, Utc};
use std::{error::Error, fmt::Display};

use crate::foundation::id::Id;

use super::{repository::UserRepositoryError, session::{Session, Signed}, User};

#[derive(Debug, PartialEq)]
pub enum UserLogicError {
    BcryptError(String),
    ValidationError(String),
    UserRepositoryError(UserRepositoryError),
    Unauthorized,
}

impl From<BcryptError> for UserLogicError {
    fn from(value: BcryptError) -> Self {
        UserLogicError::BcryptError(format!("{}", value))
    }
}

impl From<UserRepositoryError> for UserLogicError {
    fn from(value: UserRepositoryError) -> Self {
        UserLogicError::UserRepositoryError(value)
    }
}

impl Display for UserLogicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserLogicError::BcryptError(err) => write!(f, "{}", err),
            UserLogicError::ValidationError(err) => write!(f, "{}", err),
            UserLogicError::UserRepositoryError(err) => write!(f, "{}", err),
            UserLogicError::Unauthorized => write!(f, "Unauthorized"),
        }
    }
}

impl Error for UserLogicError {}

/// Uses options to indicate which fields are updated.
pub struct UserUpdate {
    pub id: Id,
    pub email: Option<&'static str>,
    pub password: Option<&'static str>,
    pub now: DateTime<Utc>,
}

/// Business logic that's to be implemented by every BL provider.
pub trait UserLogic {
    /// Add a new user to the service.
    fn create(
        &self,
        session: &Session<Signed>,
        email: &str,
        password: &str,
        now: DateTime<Utc>,
    ) -> Result<User, UserLogicError>;

    /// Read users from the service.
    fn read(&self, session: &Session<Signed>) -> Result<Vec<User>, UserLogicError>;

    /// Read a single user by id.
    fn read_by_id(&self, session: &Session<Signed>, id: Id) -> Result<User, UserLogicError>;

    /// Read a single user by email.
    fn read_by_email(&self, session: &Session<Signed>, email: &str) -> Result<User, UserLogicError>;

    /// Update a user with the provided data.
    fn update(&self, session: &Session<Signed>, user_update: UserUpdate) -> Result<(), UserLogicError>;

    /// Delete a user from the service.
    fn delete(&self, session: &Session<Signed>, id: Id) -> Result<(), UserLogicError>;

    // TODO: Purge feature.

    fn authenticate(
        &self,
        login: &str,
        password: &str,
    ) -> Result<Session<Signed>, UserLogicError>;

    fn is_valid_session(&self, session: &Session<Signed>) -> bool;

    #[cfg(feature = "registration")]
    fn register(&self, email: &str, password: &str, now: DateTime<Utc>) -> Result<User, UserLogicError>;
}
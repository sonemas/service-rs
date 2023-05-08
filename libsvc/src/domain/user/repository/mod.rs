use std::{error::Error, fmt::Display};

use crate::foundation::id::Id;

use super::User;

pub mod memory;

/// Repository related errors.
#[derive(Debug, PartialEq)]
pub enum UserRepositoryError {
    NotFound,
    DuplicateID,
    DuplicateEmail,
    Other(String),
}

impl Display for UserRepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output: &str = match self {
            UserRepositoryError::NotFound => "not found",
            UserRepositoryError::DuplicateID => "invalid ID",
            UserRepositoryError::DuplicateEmail => "invalid email",
            UserRepositoryError::Other(err) => err,
        };
        write!(f, "{}", output)
    }
}

impl Error for UserRepositoryError {}

impl From<&str> for UserRepositoryError {
    fn from(value: &str) -> Self {
        UserRepositoryError::Other(value.to_owned())
    }
}

impl From<String> for UserRepositoryError {
    fn from(value: String) -> Self {
        UserRepositoryError::Other(value)
    }
}

/// Trait to be implemented by user repositories.
pub trait UserRepository {
    /// Add a new user to the repository.
    fn create(&self, user: &User) -> Result<(), UserRepositoryError>;

    /// Read users from the repository.
    fn read(&self) -> Result<Vec<User>, UserRepositoryError>;

    /// Read a single user by id.
    fn read_by_id(&self, id: Id) -> Result<User, UserRepositoryError>;

    /// Read a single user by email.
    fn read_by_email(&self, email: &str) -> Result<User, UserRepositoryError>;

    /// Update a user with the provided data.
    fn update(&self, user: &User) -> Result<(), UserRepositoryError>;

    /// Delete a user from the repository.
    fn delete(&self, id: Id) -> Result<(), UserRepositoryError>;
}

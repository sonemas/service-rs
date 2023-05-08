use crate::User;
pub use foundation::id::Id;
use std::{error::Error, fmt::Display};

pub mod memory;

/// Repository related errors.
#[derive(Debug, PartialEq)]
pub enum RepositoryError {
    NotFound,
    DuplicateID,
    DuplicateEmail,
    Other(String),
}

impl Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output: &str = match self {
            RepositoryError::NotFound => "not found",
            RepositoryError::DuplicateID => "invalid ID",
            RepositoryError::DuplicateEmail => "invalid email",
            RepositoryError::Other(err) => err,
        };
        write!(f, "{}", output)
    }
}

impl Error for RepositoryError {}

impl From<&str> for RepositoryError {
    fn from(value: &str) -> Self {
        RepositoryError::Other(value.to_owned())
    }
}

impl From<String> for RepositoryError {
    fn from(value: String) -> Self {
        RepositoryError::Other(value)
    }
}

/// Trait to be implemented by user repositories.
pub trait Repository {
    /// Add a new user to the repository.
    fn create(&self, user: &User) -> Result<(), RepositoryError>;

    /// Read users from the repository.
    fn read(&self) -> Result<Vec<User>, RepositoryError>;

    /// Read a single user by id.
    fn read_by_id(&self, id: Id) -> Result<User, RepositoryError>;

    /// Read a single user by email.
    fn read_by_email(&self, email: &str) -> Result<User, RepositoryError>;

    /// Update a user with the provided data.
    fn update(&self, user: &User) -> Result<(), RepositoryError>;

    /// Delete a user from the repository.
    fn delete(&self, id: Id) -> Result<(), RepositoryError>;
}

use super::{Session, Signed};

#[derive(PartialEq)]
pub enum AuthenticationError {
    UserNotFound,
    WrongPassword,
}

pub trait Authenticator {
    fn authenticate(
        &self,
        login: &str,
        password: &str,
    ) -> Result<Session<Signed>, AuthenticationError>;
}

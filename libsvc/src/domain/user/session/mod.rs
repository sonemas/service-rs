//! Provides functionality for user sessions.

pub mod manager;

use chrono::{DateTime, Duration, Utc};
use std::{
    default::Default,
    error::Error,
    fmt::{self, Display},
    ops::Add,
};

use crate::foundation::id::Id;

/// Holds all session related errors.
#[derive(Debug)]
pub enum SessionError {
    BuildErr(&'static str),
    InvalidSession,
    ExpiredSession,
}

impl Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SessionError::BuildErr(err) => write!(f, "Couldn't build session: {}", err),
            SessionError::InvalidSession => write!(f, "Session is invalud"),
            SessionError::ExpiredSession => write!(f, "Session is expired"),
        }
    }
}

impl Error for SessionError {}

/// A state type representing an unsigned session.
pub struct Unsigned;

/// A state type representing a signed session.
pub struct Signed {
    signature: Vec<u8>,
}

/// Contains properties and functionality of user sessions.
pub struct Session<SignState> {
    id: Id,
    user_id: String,
    // TODO: Roles
    issuer: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    sign_state: SignState,
}

/// Contains properties and functionality to build a valid user session.
pub struct SessionBuilder {
    id: Id,
    user_id: String,
    issuer: String,
    issued_at: DateTime<Utc>,
    duration: Duration,
}

// Implement the Default trait for SessionBuilder.
// TODO: Consider using a default issuer and builder option to change.
impl Default for SessionBuilder {
    fn default() -> Self {
        Self {
            id: Id::new(),
            user_id: "".to_string(),
            issuer: "auth service".to_string(),
            issued_at: Utc::now(),
            duration: Duration::hours(1),
        }
    }
}

impl SessionBuilder {
    /// Overrides the default uuid for a session.
    pub fn with_id(self, id: Id) -> Self {
        Self {
            id,
            user_id: self.user_id,
            issuer: self.issuer,
            issued_at: self.issued_at,
            duration: self.duration,
        }
    }

    /// Overrides the default issuer for a session.
    pub fn with_issuer(self, issuer: &str) -> Self {
        Self {
            id: self.id,
            user_id: self.user_id,
            issuer: issuer.to_string(),
            issued_at: self.issued_at,
            duration: self.duration,
        }
    }

    /// Overrides the default time of issue for a session.
    pub fn issued_at(self, issued_at: DateTime<Utc>) -> Self {
        Self {
            id: self.id,
            user_id: self.user_id,
            issuer: self.issuer,
            issued_at,
            duration: self.duration,
        }
    }

    /// Overrides the default duration of an hour for a session.
    pub fn with_duration(self, duration: Duration) -> Self {
        Self {
            id: self.id,
            user_id: self.user_id,
            issuer: self.issuer,
            issued_at: self.issued_at,
            duration,
        }
    }

    /// Builds a session based upon the builder's configuration.
    pub fn build(self) -> Session<Unsigned> {
        // If user_id is empty here then shit really hit the fan, thus it's only fair to panic.
        assert!(!self.user_id.is_empty());

        let id = self.id;
        let user_id = self.user_id;
        let issuer = self.issuer;
        let issued_at = self.issued_at;
        let expires_at = issued_at.add(self.duration);

        Session {
            id,
            user_id,
            issuer,
            issued_at,
            expires_at,
            sign_state: Unsigned,
        }
    }
}

impl<SignState> Session<SignState> {
    /// Returns true if a session is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Returns the sha256 hash of the session.
    pub fn hash(&self, nonce: &str) -> String {
        sha256::digest(format!("{}:{}", self, nonce))
    }
}

/// Methods and associated functions for unsigned sessions.
impl Session<Unsigned> {
    /// Returns a SessionBuilder with default values.
    /// Requires a user id.
    ///
    /// The default settings are:
    /// - issuer: auth service
    /// - id: a random uuid
    /// - issued_at: the current time
    /// - duration: 1 hour
    ///
    /// The default settings can be overridden with
    /// the builder functions.
    ///
    /// Example:
    /// ```
    /// use libsvc::domain::user::session::Session;
    /// use chrono::{Utc, Duration};
    ///
    /// let _session = Session::new("1234")
    ///     .with_issuer("Sonemas LLC")
    ///     .with_id("9876".into())
    ///     .with_duration(Duration::hours(2))
    ///     .issued_at(Utc::now())
    ///     .build();
    /// ```
    pub fn new(user_id: &str) -> SessionBuilder {
        SessionBuilder {
            user_id: user_id.to_string(),
            ..Default::default()
        }
    }

    /// Returns false, since it's an unsigned session.
    pub fn is_signed(&self) -> bool {
        false
    }

    /// Returns false, because unsigned sessions are never valid.
    pub fn is_valid(&self) -> bool {
        false
    }

    /// Add a signature to the session. Returns a Session with a Signed session state.
    pub fn add_signature(self, signature: &[u8]) -> Session<Signed> {
        let sign_state = Signed {
            signature: signature.to_owned(),
        };
        Session {
            id: self.id,
            user_id: self.user_id,
            issuer: self.issuer,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            sign_state,
        }
    }
}

/// Methods and associated functions for signed sessions.
impl Session<Signed> {
    /// Returns true, since this is a signed session.
    pub fn is_signed(&self) -> bool {
        true
    }

    /// Returns the session's signature.
    pub fn signature(&self) -> &[u8] {
        &self.sign_state.signature
    }

    /// Returns true if a session is valid.
    ///
    /// A session is considered valid when:
    /// - it's signed
    /// - it's not expired
    /// - id, user_id and issuer are not empty
    /// - issued_at is in the past
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
            && !self.user_id.is_empty()
            && !self.issuer.is_empty()
            && Utc::now() > self.issued_at
    }
}

// Implement the display trait for Session. This is important, because the result will be used for signing sessions.
impl<SignState> Display for Session<SignState> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}",
            self.id, self.user_id, self.issuer, self.issued_at, self.expires_at
        )
    }
}

#[cfg(test)]
mod test {
    use std::ops::Sub;

    use super::*;

    #[test]
    fn it_can_create_a_valid_session_with_defaults() {
        let session = Session::new("0000").build();

        assert_eq!(session.user_id, "0000");
        assert_eq!(session.is_expired(), false);
        assert_eq!(session.is_valid(), false);

        let session = session.add_signature(b"test signature");
        assert_eq!(session.is_valid(), true);
    }

    #[test]
    fn it_can_create_a_valid_session_with_custom_values() {
        let issuer = "Sonemas LLC";
        let id = Id::from("e295a278-f7c6-4f93-b53e-69187fc2eb79");
        let user_id = "1234";
        let issued_at = Utc::now().sub(Duration::minutes(20));
        let duration = Duration::hours(2);
        let expires_at = issued_at.add(duration);

        let session = Session::new(&user_id)
            .with_issuer(&issuer)
            .with_id(id.clone())
            .with_duration(duration)
            .issued_at(issued_at)
            .build();

        assert_eq!(session.id, id);
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.issuer, issuer);
        assert_eq!(session.issued_at, issued_at);
        assert_eq!(session.expires_at, expires_at);
        assert_eq!(session.is_expired(), false);
        assert_eq!(session.is_valid(), false);

        let session = session.add_signature(b"test signature");
        assert_eq!(session.is_valid(), true);
    }

    #[test]
    fn it_can_detect_invalid_sessions() {
        let issued_at = Utc::now().sub(Duration::hours(2));

        let session = Session::new("1234").issued_at(issued_at).build();

        assert_eq!(session.is_expired(), true);
        assert_eq!(session.is_valid(), false);

        let session = session.add_signature(b"test signature");
        assert_eq!(session.is_valid(), false);
    }
}

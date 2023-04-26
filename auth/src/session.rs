//! Provides functionality for user sessions.
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::{default::Default, error::Error, fmt::{Display, self}, ops::Add};

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
            SessionError::ExpiredSession => write!(f, "Session is expired")
        }
    }
}

impl Error for SessionError {}

/// Contains properties and functionality of user sessions.
pub struct Session {
    id: String,
    user_id: String,
    // TODO: Roles
    issuer: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Contains properties and functionality to build a valid user session.
pub struct SessionBuilder {
    id: String,
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
            id: Uuid::new_v4().to_string(), 
            user_id: "".to_string(),
            issuer: "auth service".to_string(),
            issued_at: Utc::now(),
            duration: Duration::hours(1),
        }
     }
}

impl SessionBuilder {
    /// Overrides the default uuid for a session.
    pub fn with_id(self, id: &str) -> Self {
        Self {
            id: id.to_string(),
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
            issued_at: issued_at,
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
            duration: duration,
        }
    }

    /// Builds a session based upon the builder's configuration.
    pub fn build(self) -> Session {
        // If user_id is empty here then shit really hit the fan, thus it's only fair to panic.
        assert!(!self.user_id.is_empty());

        let id = self.id;
        let user_id = self.user_id;
        let issuer = self.issuer;
        let issued_at = self.issued_at;
        let expires_at = issued_at.add(self.duration);

        Session{id, user_id, issuer, issued_at, expires_at}
    }
}

impl Session {
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
    /// use auth::session::Session;
    /// use chrono::{Utc, Duration};
    /// 
    /// let _session = Session::new("1234")
    ///     .with_issuer("Sonemas LLC")
    ///     .with_id("9876")
    ///     .with_duration(Duration::hours(2))
    ///     .issued_at(Utc::now())
    ///     .build();
    /// ``` 
    pub fn new(user_id: &str) -> SessionBuilder {
        let mut builder = SessionBuilder::default();
        builder.user_id = user_id.to_string();
        builder
    }

    /// Returns true if a session is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Returns true if a session is valid.
    /// 
    /// A session is considered valid when:
    /// - it's not expired
    /// - id, user_id and issuer are not empty
    /// - issued_at is in the past
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && 
        !self.id.is_empty() &&
        !self.user_id.is_empty() &&
        !self.issuer.is_empty() &&
        Utc::now() > self.issued_at
    }
}

#[cfg(test)]
mod test {
    use std::ops::Sub;

    use super::*;

    #[test]
    fn it_can_create_a_valid_session_with_defaults() {
        let session = Session::new("0000").build();
        
        assert_eq!(session.id.is_empty(), false);
        assert_eq!(session.user_id, "0000");
        assert_eq!(session.is_expired(), false); 
        assert_eq!(session.is_valid(), true);  
    }

    #[test]
    fn it_can_create_a_valid_session_with_custom_values() {
        let issuer = "Sonemas LLC";
        let id = "9876";
        let user_id = "1234";
        let issued_at = Utc::now().sub(Duration::minutes(20));
        let duration = Duration::hours(2);
        let expires_at = issued_at.add(duration);

        let session = Session::new(&user_id)
         .with_issuer(&issuer)
         .with_id(&id)
         .with_duration(duration)
         .issued_at(issued_at)
         .build();

        assert_eq!(session.id, id);
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.issuer, issuer);
        assert_eq!(session.issued_at, issued_at);
        assert_eq!(session.expires_at, expires_at);
        assert_eq!(session.is_expired(), false); 
        assert_eq!(session.is_valid(), true); 
    }

    #[test]
    fn it_can_detect_invalid_sessions() {
        let issued_at = Utc::now().sub(Duration::hours(2));

        let session = Session::new("1234")
         .issued_at(issued_at)
         .build();

        assert_eq!(session.is_expired(), true);
        assert_eq!(session.is_valid(), false);
    }
}
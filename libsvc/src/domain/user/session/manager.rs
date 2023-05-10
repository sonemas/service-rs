//! Provides a session manager with functionality to manage sessions.
use std::{collections::HashMap, sync::Mutex};

use chrono::{DateTime, Utc, Duration};
use rand::{distributions::Alphanumeric, Rng};

use crate::foundation::key::{SigningKey, Key, KeyError};

use super::{Session, Signed};

// Returns a randomly generated nonce of the provided size.
fn rand_nonce(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect::<String>()
}

// Holds data about issued sessions to combat stealing of session tokens.
struct SessionData {
    expires_at: DateTime<Utc>,
}

impl SessionData {
    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Contains properties and functionality to manage sessions.
pub struct SessionManager {
    key_file: String,
    nonce: String,
    issuer: String,
    session_duration: Duration,
    // TODO: Cleaning up expired sessions.
    issued_sessions: Mutex<HashMap<String, SessionData>>,
}

pub struct SessionManagerBuilder {
    key_file: String,
    nonce: String,
    issuer: String,
    session_duration: Duration,
}

impl Default for SessionManagerBuilder {
    fn default() -> Self {
        let key_file = "key.der".to_string();
        let nonce = rand_nonce(30);
        let issuer = "auth service".to_string();
        let session_duration = Duration::hours(1);
        Self {
            key_file,
            nonce,
            issuer,
            session_duration,
        }
    }
}

impl SessionManager {
    /// Returns a SessionManagerBuilder with default values.
    ///
    /// The default settings are:
    /// - issuer: auth service
    /// - session duration: 1 hour
    /// - nonce: random nonce of 30 characters
    /// - key: newly created key
    ///
    /// Generating a new key is a safety consideration, because
    /// it would invalidate all sessions if a service would be restarted.
    /// To use a stored key override with the `with_key` builder function.
    ///
    /// The default settings can be overridden with
    /// the builder functions.
    ///
    /// Example:
    /// ```
    /// use libsvc::domain::user::session::manager::SessionManager;
    /// use chrono::Duration;
    ///
    /// let _session_manager = SessionManager::new()
    ///     .with_issuer("Sonemas LLC")
    ///     .with_session_duration(Duration::hours(2))
    ///     .with_nonce("9876abcd")
    ///     .build();
    /// ```
    pub fn new() -> SessionManagerBuilder {
        SessionManagerBuilder::default()
    }

    fn get_signing_key(&self) -> Result<impl SigningKey, KeyError> {
        match std::path::Path::new(&self.key_file).exists() {
            true => {
                let key = Key::open(&self.key_file)?;
                Ok(key)
            }
            false => {
                let key = Key::new()?;
                key.save(&self.key_file)?;
                Ok(key)
            }
        } 
    }

    // Helper function to create new sessions with or without a time of issuing.
    fn _new_session(
        &self,
        user_id: &str,
        issued_at: Option<DateTime<Utc>>,
    ) -> Result<Session<Signed>, KeyError> {
        // Get a session builder.
        let mut builder = Session::new(user_id)
            .with_issuer(&self.issuer)
            .with_duration(self.session_duration);

        // If issued_at has been provided, configure the builder with the value.
        if let Some(issued_at) = issued_at {
            builder = builder.issued_at(issued_at);
        }

        // Build the session.
        let session = builder.build();

        // Sign the session.
        let payload = format! {"{}:{}", &session, self.nonce};
        let signature = self.get_signing_key()?.sign(payload.as_ref())?;

        // Store session data.
        // TODO: Error handling.
        self.issued_sessions.lock().unwrap().insert(
            session.hash(&self.nonce),
            SessionData {
                expires_at: session.expires_at,
            },
        );

        Ok(session.add_signature(&signature))
    }

    /// Returns a new signed session for the provided user.
    pub fn new_session(&self, user_id: &str) -> Result<Session<Signed>, KeyError> {
        self._new_session(user_id, None)
    }

    /// Returns a new signed session for the provided user with the provided issuing time.
    pub fn new_session_with_issued_time(
        &self,
        user_id: &str,
        issued_at: DateTime<Utc>,
    ) -> Result<Session<Signed>, KeyError> {
        self._new_session(user_id, Some(issued_at))
    }

    /// Verifies whether a session is:
    /// 1) valid
    /// 2) issued by the manager
    /// 3) signed with a valid signature from the manager
    // TODO: Custom errors.
    pub fn verify_session(&self, session: &Session<Signed>) -> Result<(), ()> {
        if !session.is_valid() {
            return Err(());
        }

        if !self
            .issued_sessions
            // TODO: Error handling.
            .lock().unwrap()
            .contains_key(&session.hash(&self.nonce))
        {
            return Err(());
        }

        let payload = format! {"{}:{}", &session, self.nonce};
        if !self.get_signing_key().unwrap().has_signed(payload.as_ref(), session.signature()) {
            return Err(());
        }

        Ok(())
    }
}

impl SessionManagerBuilder {
    /// Overrides the default nonce for a session manager.
    pub fn with_nonce(self, nonce: &str) -> Self {
        Self {
            nonce: nonce.to_string(),
            key_file: self.key_file,
            issuer: self.issuer,
            session_duration: self.session_duration,
        }
    }

    /// Overrides the default key for a session manager.
    pub fn with_key_file(self, key_file: &str) -> Self {
        Self {
            key_file: key_file.to_string(),
            nonce: self.nonce,
            issuer: self.issuer,
            session_duration: self.session_duration,
        }
    }

    /// Overrides the default issuer for a session manager.
    pub fn with_issuer(self, issuer: &str) -> Self {
        Self {
            key_file: self.key_file,
            nonce: self.nonce,
            issuer: issuer.to_string(),
            session_duration: self.session_duration,
        }
    }

    /// Overrides the default session duration for a session manager.
    pub fn with_session_duration(self, session_duration: Duration) -> Self {
        Self {
            key_file: self.key_file,
            nonce: self.nonce,
            issuer: self.issuer,
            session_duration,
        }
    }

    /// Builds a session manager based upon the builder's configuration.
    pub fn build(self) -> SessionManager {
        SessionManager {
            key_file: self.key_file,
            nonce: self.nonce,
            issuer: self.issuer,
            session_duration: self.session_duration,
            issued_sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ops::{Add, Sub};

    #[test]
    fn it_can_create_a_valid_session_with_defaults() {
        let session_manager = SessionManager::new().build();
        let session = session_manager
            .new_session("0000")
            .expect("should be able to create new session");

        assert_eq!(session.user_id, "0000");
        assert_eq!(session.is_expired(), false);
        assert_eq!(session.is_valid(), true);
        assert_eq!(session.is_signed(), true);
        assert!(session_manager.verify_session(&session).is_ok());
    }

    #[test]
    fn it_can_create_a_valid_session_with_custom_values() {
        let issuer = "Sonemas LLC";
        let user_id = "1234";
        let issued_at = Utc::now().sub(Duration::minutes(20));
        let duration = Duration::hours(2);
        let expires_at = issued_at.add(duration);

        let session_manager = SessionManager::new()
            .with_issuer(&issuer)
            .with_session_duration(duration)
            .build();

        let session = session_manager
            .new_session_with_issued_time(&user_id, issued_at)
            .expect("should be able to create new session");

        assert_eq!(session.user_id, user_id);
        assert_eq!(session.issuer, issuer);
        assert_eq!(session.issued_at, issued_at);
        assert_eq!(session.expires_at, expires_at);
        assert_eq!(session.is_expired(), false);
        assert_eq!(session.is_valid(), true);
        assert_eq!(session.is_signed(), true);
        assert!(session_manager.verify_session(&session).is_ok());
    }
}

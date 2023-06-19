//! Provides functionality for user sessions.

pub mod manager;
pub mod session;

#[cfg(test)]
mod test {
    use std::ops::Sub;

    use super::*;

    #[test]
    fn it_can_create_a_valid_session_with_defaults() {
        let session = Session::build("0000").finish();

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

        let session = Session::build(&user_id)
            .with_issuer(&issuer)
            .with_id(id.clone())
            .with_duration(duration)
            .issued_at(issued_at)
            .finish();

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

        let session = Session::build("1234").issued_at(issued_at).finish();

        assert_eq!(session.is_expired(), true);
        assert_eq!(session.is_valid(), false);

        let session = session.add_signature(b"test signature");
        assert_eq!(session.is_valid(), false);
    }

    #[test]
    fn it_can_restore_sessions() {
        let issued_at = Utc::now();
        let orig_session = Session::build("1234")
            .issued_at(issued_at)
            .finish()
            .add_signature(b"test signature");
        assert!(!orig_session.is_expired());
        assert!(orig_session.is_valid());

        let session = Session::restore(
            orig_session.id.clone(),
            orig_session.user_id.clone(),
            &orig_session.issuer.clone(),
            orig_session.issued_at.clone(),
            orig_session.expires_at.clone(),
            &orig_session.sign_state.signature,
        );
        assert_eq!(session, orig_session);
        assert!(!session.is_expired());
        assert!(session.is_valid());
    }
}

use chrono::{DateTime, Utc};
use crate::foundation::id::Id;

use super::{repository::UserRepository, session::{manager::SessionManager, Session, Signed}, logic::{UserLogic, UserLogicError, UserUpdate, AuthenticationLogic}, User};

pub struct UserService<'a> {
    repo: &'a dyn UserRepository,
    session_manager: SessionManager,
}

impl<'a> UserService<'a> {
    pub fn new(repo: &'a dyn UserRepository, session_manager: SessionManager) -> Self {
        Self {
            repo,
            session_manager,
        }
    }
}

impl<'a> UserLogic for UserService<'a> {
    fn create(
        &self,
        session: &Session<Signed>,
        email: &str,
        password: &str,
        now: DateTime<Utc>,
    ) -> Result<User, UserLogicError> {
        // TODO: Authorization
        let user = User::new(Id::new(), email, password, now)?;
        self.repo.create(&user)?;
        Ok(user)
    }

    fn read(&self, session: &Session<Signed>) -> Result<Vec<User>, UserLogicError> {
        // TODO: Authorization
        let users = self.repo.read()?;
        Ok(users)
    }

    fn read_by_id(&self, session: &Session<Signed>, id: Id) -> Result<User, UserLogicError> {
        // TODO: Authorization
        let user = self.repo.read_by_id(id)?;
        Ok(user)
    }

    fn read_by_email(&self, session: &Session<Signed>, email: &str) -> Result<User, UserLogicError> {
        // TODO: Authorization
        let user = self.repo.read_by_email(email)?;
        Ok(user)
    }

    fn update(&self, session: &Session<Signed>, user_update: UserUpdate) -> Result<(), UserLogicError> {
        // TODO: Authorization
        let mut user = self.repo.read_by_id(user_update.id)?;
        if let Some(email) = user_update.email {
            user.email = email.to_string()
        };
        if let Some(password) = user_update.password {
            user.set_password(password)?
        };
        user.date_updated = user_update.now;
        self.repo.update(&user)?;
        Ok(())
    }

    fn delete(&self, session: &Session<Signed>, id: Id) -> Result<(), UserLogicError> {
        // TODO: Authorization
        self.repo.delete(id)?;
        Ok(())
    }
}

impl<'a> AuthenticationLogic for UserService<'a> {
    // TODO: Change the error type.
    fn authenticate(
        &self,
        login: &str,
        password: &str,
    ) -> Result<Session<Signed>, UserLogicError> {
        let user = self.repo.read_by_email(login)?;

        match user.validate_password(password) {
            Ok(true) => {},
            _ => return Err(UserLogicError::Unauthorized),
        }

        Ok(self
            .session_manager
            .new_session(&user.id.to_string())
            .expect("should be able to create session"))
    }

    #[cfg(feature = "registration")]
    fn register(&self, email: &str, password: &str, now: DateTime<Utc>) -> Result<User, UserLogicError> {
        let user = User::new(Id::new(), email, password, now)?;
        self.repo.create(&user)?;
        Ok(user)
    }
}

#[cfg(test)]
mod test {
    use chrono::Utc;
    use crate::domain::user::repository::{memory::Memory, UserRepositoryError};
    use super::*;

    #[test]
    fn it_can_crud() {
        let repo = Memory::new();
        let service = UserService::new(&repo, SessionManager::new().build());
        let now = Utc::now();
        let session_manager = SessionManager::new().build();
        let session = session_manager.new_session("1234").unwrap();

        let user = service
            .create(&session, "test@example.com", "password", now)
            .unwrap();
        let mut expected = user.clone();
        expected.email = "test@example.com".to_string();
        assert_eq!(user, expected);

        assert_eq!(
            service.read_by_id(&session, user.id.clone()).unwrap(),
            user.clone()
        );
        assert_eq!(
            service.read_by_email(&session, "test@example.com").unwrap(),
            user.clone()
        );
        assert_eq!(service.read(&session).unwrap(), vec![user.clone()]);

        assert!(service
            .update(
                &session,
                UserUpdate {
                    id: user.id.clone(),
                    email: Some("new.email@example.com"),
                    password: None,
                    now
                },
            )
            .is_ok());
        expected.email = "new.email@example.com".to_string();
        assert_eq!(
            service.read_by_id(&session, user.id.clone()).unwrap(),
            expected.clone()
        );
        assert_eq!(
            service
                .read_by_email(&session, "new.email@example.com")
                .unwrap(),
            expected.clone()
        );

        assert!(service.delete(&session, user.id.clone()).is_ok());
        assert!(service
            .read_by_id(&session, user.id.clone())
            .is_err_and(|err| err == UserLogicError::UserRepositoryError(UserRepositoryError::NotFound)));
    }

    #[test]
    fn it_can_authenticate() {
        let repo = Memory::new();
        let service = UserService::new(&repo, SessionManager::new().build());
        let now = Utc::now();
        let session_manager = SessionManager::new().build();
        let session = session_manager.new_session("1234").unwrap();
        service
            .create(&session, "test@example.com", "password", now)
            .unwrap();

        assert!(service.authenticate("test@example.com", "password").is_ok());
        assert!(service
            .authenticate("bla@example.com", "password")
            .is_err_and(|err| err == UserLogicError::UserRepositoryError(UserRepositoryError::NotFound)));
        assert!(service
            .authenticate("test@example.com", "bla")
            .is_err_and(|err| err == UserLogicError::Unauthorized));
    }
}

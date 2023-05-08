use auth::session::{self, logic::Authenticator, Session, Signed};
use chrono::{DateTime, Utc};
use foundation::id::Id;

use crate::{
    logic::{Logic, LogicError, Update},
    repository::Repository,
    User,
};

pub struct UserService<'a> {
    repo: &'a dyn Repository,
    session_manager: session::manager::Manager,
}

impl<'a> UserService<'a> {
    pub fn new(repo: &'a dyn Repository, session_manager: session::manager::Manager) -> Self {
        Self {
            repo,
            session_manager,
        }
    }
}

impl<'a> Logic for UserService<'a> {
    fn create(
        &self,
        session: &Session<Signed>,
        email: &str,
        password: &str,
        now: DateTime<Utc>,
    ) -> Result<User, LogicError> {
        // TODO: Authorization
        let user = User::new(Id::new(), email, password, now)?;
        self.repo.create(&user)?;
        Ok(user)
    }

    fn read(&self, session: &Session<Signed>) -> Result<Vec<User>, LogicError> {
        // TODO: Authorization
        let users = self.repo.read()?;
        Ok(users)
    }

    fn read_by_id(&self, session: &Session<Signed>, id: Id) -> Result<User, LogicError> {
        // TODO: Authorization
        let user = self.repo.read_by_id(id)?;
        Ok(user)
    }

    fn read_by_email(&self, session: &Session<Signed>, email: &str) -> Result<User, LogicError> {
        // TODO: Authorization
        let user = self.repo.read_by_email(email)?;
        Ok(user)
    }

    fn update(&self, session: &Session<Signed>, update: Update) -> Result<(), LogicError> {
        // TODO: Authorization
        let mut user = self.repo.read_by_id(update.id)?;
        if let Some(email) = update.email {
            user.email = email.to_string()
        };
        if let Some(password) = update.password {
            user.set_password(password)?
        };
        user.date_updated = update.now;
        self.repo.update(&user)?;
        Ok(())
    }

    fn delete(&self, session: &Session<Signed>, id: Id) -> Result<(), LogicError> {
        // TODO: Authorization
        self.repo.delete(id)?;
        Ok(())
    }
}

impl<'a> Authenticator for UserService<'a> {
    // TODO: Change the error type.
    fn authenticate(
        &self,
        login: &str,
        password: &str,
    ) -> Result<Session<Signed>, auth::session::logic::AuthenticationError> {
        let user = match self.repo.read_by_email(login) {
            Ok(user) => user,
            Err(_) => return Err(auth::session::logic::AuthenticationError::UserNotFound),
        };

        match user.validate_password(password) {
            Ok(true) | Err(_) => {}
            _ => return Err(auth::session::logic::AuthenticationError::WrongPassword),
        }

        Ok(self
            .session_manager
            .new_session(&user.id.to_string())
            .expect("should be able to create session"))
    }
}

#[cfg(test)]
mod test {
    use auth::session::{logic::AuthenticationError, manager::Manager};
    use chrono::Utc;

    use super::*;
    use crate::{logic::RepositoryError, repository::memory::Memory};

    #[test]
    fn it_can_crud() {
        let repo = Memory::new();
        let service = UserService::new(&repo, Manager::new().build());
        let now = Utc::now();
        let session_manager = Manager::new().build();
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
                Update {
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
            .is_err_and(|err| err == LogicError::RepositoryError(RepositoryError::NotFound)));
    }

    #[test]
    fn it_can_authenticate() {
        let repo = Memory::new();
        let service = UserService::new(&repo, Manager::new().build());
        let now = Utc::now();
        let session_manager = Manager::new().build();
        let session = session_manager.new_session("1234").unwrap();
        service
            .create(&session, "test@example.com", "password", now)
            .unwrap();

        assert!(service.authenticate("test@example.com", "password").is_ok());
        assert!(service
            .authenticate("bla@example.com", "password")
            .is_err_and(|err| err == AuthenticationError::UserNotFound));
        assert!(service
            .authenticate("test@example.com", "bla")
            .is_err_and(|err| err == AuthenticationError::WrongPassword));
    }
}

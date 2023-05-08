use auth::session::{Session, Signed};
use chrono::{DateTime, Utc};
use foundation::id::Id;

use crate::{logic::{Logic, LogicError, Update}, repository::{Repository}, User};


pub struct UserService<'a> {
    _repo: &'a dyn Repository,
}

impl<'a> UserService<'a> {
    pub fn new(_repo: &'a dyn Repository) -> Self {
        Self { _repo }
    }
}

impl<'a> Logic for UserService<'a> {
    fn create(&self, session: &Session<Signed>, email: &str, password: &str, now: DateTime<Utc>) -> Result<User, LogicError> {
        // TODO: Authorization
        let user = User::new(Id::new(), email, password, now)?;
        self._repo.create(&user)?;
        Ok(user)
    }

    fn read(&self, session: &Session<Signed>) -> Result<Vec<User>, LogicError> {
        // TODO: Authorization
        let users = self._repo.read()?;
        Ok(users)
    }

    fn read_by_id(&self, session: &Session<Signed>, id: Id) -> Result<User, LogicError> {
        // TODO: Authorization
        let user = self._repo.read_by_id(id)?;
        Ok(user)
    }

    fn read_by_email(&self, session: &Session<Signed>, email: &str) -> Result<User, LogicError> {
        // TODO: Authorization
        let user = self._repo.read_by_email(email)?;
        Ok(user)
    }

    fn update(&self, session: &Session<Signed>, update: Update) -> Result<(), LogicError> {
        // TODO: Authorization
        let mut user = self._repo.read_by_id(update.id)?;
        if let Some(email) = update.email { user.email = email.to_string() };
        if let Some(password) = update.password { user.set_password(password)? };
        user.date_updated = update.now;
        self._repo.update(&user)?;
        Ok(())
    }

    fn delete(&self,  session: &Session<Signed>, id: Id) -> Result<(), LogicError> {
        // TODO: Authorization
        self._repo.delete(id)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use auth::session::manager::Manager;
    use chrono::Utc;

    use super::*;
    use crate::{User, repository::{memory::Memory}, logic::RepositoryError};

    #[test]
    fn it_can_crud() {
        let _repo = Memory::new();
        let service = UserService::new(&_repo);
        
        let now = Utc::now();

        let session_manager = Manager::new().build();
        let session = session_manager.new_session("1234").unwrap();

        let user = service.create(&session, "test@example.com", "password", now).unwrap();
        let mut expected = user.clone();
        expected.email = "test@example.com".to_string();
        assert_eq!(user, expected);

        assert_eq!(service.read_by_id(&session, user.id.clone()).unwrap(), user.clone());
        assert_eq!(service.read_by_email(&session, "test@example.com").unwrap(), user.clone());
        assert_eq!(service.read(&session).unwrap(), vec![user.clone()]);

        assert!(service.update(
            &session,
            Update { id: user.id.clone(), email: Some("new.email@example.com"), password: None, now },
        ).is_ok());
        expected.email = "new.email@example.com".to_string();
        assert_eq!(service.read_by_id(&session, user.id.clone()).unwrap(), expected.clone());
        assert_eq!(service.read_by_email(&session, "new.email@example.com").unwrap(), expected.clone());

        assert!(service.delete(&session, user.id.clone()).is_ok());
        assert!(service.read_by_id(&session, user.id.clone()).is_err_and(|err| err == LogicError::RepositoryError(RepositoryError::NotFound)));
    }
}
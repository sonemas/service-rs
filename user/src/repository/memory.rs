use super::{Id, Repository, RepositoryError};
use crate::User;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

pub struct Memory {
    users: Arc<RwLock<HashMap<Id, User>>>,
    email_index: Arc<RwLock<HashMap<String, Id>>>,
}

/// In memory storage.
impl Memory {
    pub fn new() -> Self {
        let users = Arc::new(RwLock::new(HashMap::<Id, User>::new()));
        let email_index = Arc::new(RwLock::new(HashMap::<String, Id>::new()));
        Self { users, email_index }
    }

    fn exists(&self, id: Option<&Id>, email: Option<&str>) -> (bool, bool) {
        // TODO: Check whether panicing is really ok here.
        let users = self.users.read().expect("couldn't get user store");
        let user_exists = match id {
            Some(id) => users.contains_key(id),
            None => false,
        };

        let email_index = self
            .email_index
            .read()
            .expect("couldn't get email index store");
        let email_exists = match email {
            Some(email) => email_index.contains_key(email),
            None => false,
        };

        (user_exists, email_exists)
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Repository for Memory {
    fn create(&self, user: &User) -> Result<(), super::RepositoryError> {
        match self.exists(Some(&user.id), Some(&user.email)) {
            (true, false) => return Err(RepositoryError::DuplicateID),
            (false, true) => return Err(RepositoryError::DuplicateEmail),
            _ => {}
        }
        self.users
            .write()
            .expect("couldn't get user store")
            .insert(user.id.clone(), user.clone());
        self.email_index
            .write()
            .expect("couldn't get email index store")
            .insert(user.email.clone(), user.id.clone());
        Ok(())
    }

    fn read(&self) -> Result<Vec<User>, super::RepositoryError> {
        Ok(Vec::from_iter(
            self.users
                .read()
                .expect("couldn't get user store")
                .values()
                .cloned(),
        ))
    }

    fn read_by_id(&self, id: Id) -> Result<User, super::RepositoryError> {
        match self.users.read().expect("couldn't get user store").get(&id) {
            None => Err(RepositoryError::NotFound),
            Some(v) => Ok(v.clone()),
        }
    }

    fn read_by_email(&self, email: &str) -> Result<User, super::RepositoryError> {
        match self
            .email_index
            .read()
            .expect("couldn't get email index store")
            .get(email)
        {
            None => Err(RepositoryError::NotFound),
            Some(id) => self.read_by_id(id.clone()),
        }
    }

    fn update(&self, user: &User) -> Result<(), super::RepositoryError> {
        if let (false, _) = self.exists(Some(&user.id), None) {
            return Err(RepositoryError::NotFound);
        }
        let old_email = self
            .users
            .read()
            .expect("couldn't get user store")
            .get(&user.id.clone())
            .unwrap()
            .email
            .clone();

        self.users
            .write()
            .expect("couldn't get user store")
            .entry(user.id.clone())
            .and_modify(|u| *u = user.clone());
        if user.email != old_email {
            let mut email_index = self
                .email_index
                .write()
                .expect("couldn't get email index store");
            email_index.remove(&old_email);
            email_index.insert(user.email.clone(), user.id.clone());
        }
        Ok(())
    }

    fn delete(&self, id: Id) -> Result<(), super::RepositoryError> {
        if let (false, _) = self.exists(Some(&id), None) {
            return Err(RepositoryError::NotFound);
        }
        let email = self
            .users
            .read()
            .expect("couldn't get user store")
            .get(&id)
            .unwrap()
            .email
            .clone();
        self.users
            .write()
            .expect("couldn't get user store")
            .remove(&id);
        self.email_index
            .write()
            .expect("couldn't get email index store")
            .remove(&email);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use chrono::Utc;

    use super::*;
    use crate::User;

    #[test]
    fn it_can_crud() {
        let store = Memory::new();
        let now = Utc::now();
        let user = User::new(Id::from("1234"), "test@example.com", "password", now).unwrap();

        assert!(store.create(&user).is_ok());

        assert_eq!(store.read_by_id(Id::from("1234")).unwrap(), user.clone());
        assert_eq!(
            store.read_by_email("test@example.com").unwrap(),
            user.clone()
        );
        assert_eq!(store.read().unwrap(), vec![user.clone()]);

        let mut update_user = user.clone();
        update_user.email = "new.email@example.com".to_string();
        assert!(store.update(&update_user).is_ok());
        assert_eq!(
            store.read_by_id(Id::from("1234")).unwrap(),
            update_user.clone()
        );
        assert_eq!(
            store.read_by_email("new.email@example.com").unwrap(),
            update_user.clone()
        );

        assert!(store.delete(Id::from("1234")).is_ok());
        assert!(store
            .read_by_id(Id::from("1234"))
            .is_err_and(|err| err == RepositoryError::NotFound));
    }
}

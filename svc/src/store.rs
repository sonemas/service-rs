use libsvc::domain::user::logic::UserLogic;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct Store {
    pub user_logic: Arc<RwLock<dyn UserLogic + Send + Sync>>,
    pub jwt_secret: String,
}

impl Store {
    pub fn new(user_logic: Arc<RwLock<dyn UserLogic + Send + Sync>>, jwt_secret: &str) -> Self {
        Self {
            user_logic,
            jwt_secret: jwt_secret.to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use chrono::Utc;
    use libsvc::domain::user::{
        repository::memory::Memory, service::UserService, session::manager::SessionManager,
    };

    use super::*;

    fn prepare_store() -> Store {
        let session_manager = SessionManager::build().with_issuer("Sonemas LLC").finish();

        let user_repo = Arc::new(RwLock::new(Memory::new()));

        let user_service = Arc::new(RwLock::new(UserService::new(
            user_repo.clone(),
            Arc::new(session_manager),
        )));

        Store {
            user_logic: user_service.clone(),
            jwt_secret: "blabla".to_string(),
        }
    }

    #[test]
    fn store_can_register_and_authenticate() {
        let store = prepare_store();
        assert!(store
            .user_logic
            .write()
            .expect("Should be able to get user logic")
            .register("test@example.com", "testtest", Utc::now())
            .is_ok());
        assert!(store
            .user_logic
            .read()
            .expect("Shoudl be able to get user logic")
            .authenticate("test@example.com", "testtest")
            .is_ok());
    }
}

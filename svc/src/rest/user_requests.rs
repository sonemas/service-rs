use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct UserRegistrationRequest {
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}
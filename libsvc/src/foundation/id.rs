use std::fmt::Display;
use uuid::Uuid;

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
#[cfg(feature = "serde")] #[derive(serde::Serialize, serde::Deserialize)]
pub struct Id(String);

impl Id {
    pub fn new() -> Self {
        Id(Uuid::new_v4().to_string())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Id(value.to_string())
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

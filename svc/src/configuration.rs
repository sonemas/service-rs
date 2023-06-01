use std::time::Duration;

use secrecy::{ExposeSecret, Secret};
use serde_aux::field_attributes::deserialize_number_from_string;

const DEFAULT_JWT_SEED: &str = "jKqj5mt0eTRUDtojFXQryv8NObjhvbGfyXK4DaowZHjeIvPyfNjQmEprWTrZ2q1XxB0ojwhypnXSAVAOEaP7Ip8NXKt5RzosVTy4sR6QYoH4MJj4MLfJvAcbErN5FIscPhPdEemyAVy2bC6iJzSZp6PLhBIf90NatFosEtBu0ANK6oISITpnYzohCd2GCcPMz1Itmi9IKZf6jLd9RkmGkj12pCcblWx0zxzV1LFFdnBe8is6M84LJBhctpXBtGeO";

/// Runtime environment for the service.
#[derive(PartialEq)]
pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not a supported environment. Use either `local` or `production`.",
                other
            )),
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct Server {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub api_port: u16,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub debug_port: u16,
    pub host: String,
}

#[derive(serde::Deserialize, Clone)]
pub struct Authentication {
    pub jwt_seed: Secret<String>,
    pub session_duration_ms: u64,
}

impl Authentication {
    pub fn session_duration(&self) -> Duration {
        Duration::from_millis(self.session_duration_ms)
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct Configuration {
    pub server: Server,
    pub authentication: Authentication,
}

impl Configuration {
    pub fn parse(key: &str) -> Result<Configuration, config::ConfigError> {
        let key = key.to_uppercase();
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let configuration_directory = base_path.join("configuration");

        // Detect the runtime environment, if none is provided use local.
        let environment: Environment = std::env::var(&key)
            .unwrap_or_else(|_| "local".into())
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to parse {}.", &key));
        let environment_filename = format!("{}.yaml", environment.as_str());

        let conf = config::Config::builder()
            .add_source(config::File::from(
                configuration_directory.join("base.yaml"),
            ))
            .add_source(config::File::from(
                configuration_directory.join(environment_filename),
            ))
            // Add in settings from environment variables (with a prefix of key and '__' as separator)
            // E.g. `<key>__PORT=5001 would set `Settings.application.port`
            .add_source(
                config::Environment::with_prefix(&key)
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?;

        let conf = conf.try_deserialize::<Configuration>()?;

        // Panic if the default jwt seed is used in production.
        if environment == Environment::Production
            && conf.authentication.jwt_seed.expose_secret() == DEFAULT_JWT_SEED
        {
            panic!("Don't use the default JWT seed in production.")
        }
        Ok(conf)
    }
}

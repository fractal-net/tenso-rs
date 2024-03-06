pub mod error;

use figment::providers::Format;
use figment::value::{Dict, Map};
use figment::Provider;
use figment::{error::Error, Figment, Metadata, Profile};
use serde_derive::{Deserialize, Serialize};

use crate::commands;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub config_path: String,
    pub key_path: String,
    pub subtensor_endpoint: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_path: "~/.bittensor/tensors.toml".to_string(),
            key_path: "~/.bittensor".to_string(),
            subtensor_endpoint: "wss://entrypoint-finney.opentensor.ai:443".to_string(),
        }
    }
}

impl Provider for Config {
    fn metadata(&self) -> Metadata {
        Metadata::named("tenso-rs config")
    }

    fn data(&self) -> Result<Map<Profile, Dict>, Error> {
        figment::providers::Serialized::defaults(Config::default()).data()
    }

    fn profile(&self) -> Option<Profile> {
        None
    }
}

impl Config {
    pub fn merge_with_args(&mut self, args: &commands::CliArgs) {
        if let Some(config_path) = &args.config_path {
            self.config_path = config_path.clone();
        }

        if let Some(key_path) = &args.key_path {
            self.key_path = key_path.clone();
        }
        if let Some(subtensor_endpoint) = &args.subtensor_endpoint {
            self.subtensor_endpoint = subtensor_endpoint.clone();
        }
    }

    pub fn reload_from_path(&mut self) -> Result<(), error::ConfigError> {
        use figment::providers::{Env, Toml};

        let figment = Figment::from(Config::default())
            .merge(Toml::file(&self.config_path.clone()))
            .merge(Env::prefixed("TENSORS_"));

        let mut new_config: Config = figment.extract().map_err(error::ConfigError::Invalid)?;

        // make sure user cannot re-configure path from path
        new_config.config_path = self.config_path.clone();

        *self = new_config;

        Ok(())
    }

    pub fn from<T: Provider>(provider: T) -> Result<Config, error::ConfigError> {
        Figment::from(provider)
            .extract()
            .map_err(error::ConfigError::Invalid)
    }

    pub fn figment() -> Figment {
        use figment::providers::{Env, Toml};
        Figment::from(Self::default())
            .merge(Toml::file("~/.bittensor/tensors.toml"))
            .merge(Env::prefixed("TENSORS_"))
    }
}

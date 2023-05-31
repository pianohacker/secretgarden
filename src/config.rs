use anyhow::Result as AHResult;
use serde::Deserialize;
use std::{fs::read_to_string, path::Path};
use toml;

use crate::types::{ConfigType, SecretType};

#[derive(Deserialize)]
pub struct Config(toml::Table);

impl Config {
    pub fn load() -> AHResult<Self> {
        if Path::new("secretgarden.toml").exists() {
            Ok(Self(toml::from_str(&read_to_string("secretgarden.toml")?)?))
        } else {
            Ok(Self(toml::Table::new().into()))
        }
    }

    pub fn get<'a, T>(&self, secret_type: SecretType, name: &str) -> AHResult<T>
    where
        T: ConfigType<'a>,
    {
        let default_secret_type_config = &toml::Table::new().into();
        let default_secret_config = &toml::Table::new().into();
        let secret_config = self
            .0
            .get(&secret_type.to_string())
            .unwrap_or(default_secret_type_config)
            .get(name)
            .unwrap_or(default_secret_config);

        Ok(secret_config.clone().try_into()?)
    }
}

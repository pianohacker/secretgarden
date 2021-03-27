use anyhow::{anyhow, Context, Result as AHResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::types::{GenerateOpt, Secret, SecretMap, WithCommonOpts};

const DEFAULT_FILENAME: &str = "secretgarden.dat";

#[derive(Serialize, Deserialize)]
struct SecretFile {
    secrets: SecretMap,
}

pub trait SecretStore {
    fn get_or_generate<OptsT: WithCommonOpts>(
        &mut self,
        f: impl Fn(&OptsT) -> AHResult<String>,
        secret_type: &str,
        opts: &OptsT,
    ) -> AHResult<String>;

    fn set_opaque(&mut self, key: String, value: String) -> AHResult<()>;
}

pub struct ContainedSecretStore<S: SecretContainerFile> {
    _secrets: Option<SecretMap>,
    secret_container_file: S,
}

pub trait SecretContainerFile {
    fn decrypt<P: AsRef<Path>>(&mut self, path: P) -> AHResult<Vec<u8>>;
    fn encrypt<P: AsRef<Path>>(&mut self, path: P, data: Vec<u8>) -> AHResult<()>;
}

impl<S: SecretContainerFile> ContainedSecretStore<S> {
    pub fn new(secret_container_file: S) -> ContainedSecretStore<S> {
        ContainedSecretStore {
            _secrets: None,
            secret_container_file,
        }
    }

    fn _load_secrets(&mut self) -> AHResult<&mut SecretMap> {
        if let Some(ref mut _secrets) = self._secrets {
            return Ok(_secrets);
        }

        let mut _secrets;

        let secrets_location = Path::new(DEFAULT_FILENAME);

        if secrets_location.is_file() {
            let existing_contents = self.secret_container_file.decrypt(secrets_location)?;

            let existing_secrets: SecretFile = serde_json::from_slice(&existing_contents)
                .context("Could not parse secrets JSON")?;

            _secrets = existing_secrets.secrets;
        } else {
            _secrets = HashMap::new();
        }

        self._secrets = Some(_secrets);
        Ok(self._secrets.as_mut().unwrap())
    }

    fn _store_secrets(&mut self) -> AHResult<()> {
        let serialized_secrets = serde_json::to_vec(&SecretFile {
            secrets: self._secrets.to_owned().unwrap(),
        })
        .context("Failed to serialize secrets")?;

        self.secret_container_file
            .encrypt(DEFAULT_FILENAME, serialized_secrets)
    }
}

impl<S: SecretContainerFile> SecretStore for ContainedSecretStore<S> {
    fn get_or_generate<OptsT: WithCommonOpts>(
        &mut self,
        f: impl Fn(&OptsT) -> AHResult<String>,
        secret_type: &str,
        opts: &OptsT,
    ) -> AHResult<String> {
        let secrets = self._load_secrets()?;
        let common_opts = opts.common_opts();
        let serialized_opts: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(opts).context("Failed to serialize options")?,
        )
        .context("Failed to deserialize options")?;

        if let Some(secret) = secrets.get(&common_opts.name) {
            if secret.options == serialized_opts || common_opts.generate == GenerateOpt::Once {
                return Ok(secret.value.to_string());
            }
        }

        if common_opts.generate == GenerateOpt::Never {
            return Err(anyhow!(
                "Secret {} does not exist and generation is disabled",
                common_opts.name
            ));
        }

        let value = f(opts)?;
        secrets.insert(
            common_opts.name.to_owned(),
            Secret {
                _secret_type: secret_type.to_string(),
                value: value.to_owned(),
                options: serialized_opts.clone(),
            },
        );
        self._store_secrets()?;

        Ok(value)
    }

    fn set_opaque(&mut self, key: String, value: String) -> AHResult<()> {
        let secrets = self._load_secrets()?;

        secrets.insert(
            key,
            Secret {
                _secret_type: "opaque".to_string(),
                value: value.clone(),
                options: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        self._store_secrets()?;

        Ok(())
    }
}

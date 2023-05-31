use anyhow::Result as AHResult;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Copy, Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretType {
    Opaque,
    Password,
    SshKey,
    X509,
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Self::Opaque => "opaque",
                Self::Password => "password",
                Self::SshKey => "ssh-key",
                Self::X509 => "x509",
            }
        )
    }
}

#[derive(Parser, Clone, Debug, Default, PartialEq)]
pub struct CommonOpts {
    #[clap()]
    pub name: String,
    #[clap(short = 'B', long, help = "Output secrets encoded with base64")]
    pub base64: bool,
    #[clap(
        value_enum,
        short,
        long,
        default_value = "converge",
        help = "Whether to generate the secret if needed",
        long_help = "Whether to generate the secret if needed. `converge` will regenerate an existing secret if it has expired or a different config is used."
    )]
    pub generate: GenerateOpt,
}

pub trait WithCommonOpts {
    fn common_opts(&self) -> &CommonOpts;
}

pub trait OptionsType<'a>: WithCommonOpts + Debug {}

impl<'a, T> OptionsType<'a> for T where T: WithCommonOpts + Debug {}

pub trait ConfigType<'a>: Deserialize<'a> + Serialize + Debug + PartialEq {
    fn should_cause_secret_regeneration(&self, secret: &Secret) -> AHResult<bool> {
        let serialized_self = serde_json::to_value(&self)?;

        Ok(serialized_self != secret.config)
    }
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum GenerateOpt {
    Never,
    Once,
    Converge,
}

impl Default for GenerateOpt {
    fn default() -> Self {
        GenerateOpt::Converge
    }
}

pub type SecretMap = HashMap<String, Secret>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    // Compatibility with the old name
    #[serde(alias = "_secret_type")]
    pub secret_type: SecretType,
    pub value: String,
    #[serde(alias = "options")]
    pub config: serde_json::Value,
}

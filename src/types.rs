use anyhow::Result as AHResult;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

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
        long_help = "Whether to generate the secret if needed. `converge` will regenerate an existing secret if different options are used or it is no longer valid."
    )]
    pub generate: GenerateOpt,
}

pub trait WithCommonOpts: Serialize {
    fn common_opts(&self) -> &CommonOpts;
}

pub trait OptionsType<'a>:
    WithCommonOpts + ShouldCauseSecretRegeneration + Deserialize<'a> + Debug
{
}

impl<'a, T> OptionsType<'a> for T where
    T: WithCommonOpts + ShouldCauseSecretRegeneration + Deserialize<'a> + Debug
{
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

pub trait ShouldCauseSecretRegeneration {
    fn should_cause_secret_regeneration(&self, secret: &Secret) -> AHResult<bool>;
}

impl<T> ShouldCauseSecretRegeneration for T
where
    T: PartialEq + Serialize + std::fmt::Debug,
{
    fn should_cause_secret_regeneration(&self, secret: &Secret) -> AHResult<bool> {
        let serialized_self = serde_json::to_value(&self)?;

        Ok(serialized_self != secret.options)
    }
}

pub type SecretMap = HashMap<String, Secret>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    // Compatibility with the old name
    #[serde(alias = "_secret_type")]
    pub secret_type: String,
    pub value: String,
    pub options: serde_json::Value,
}

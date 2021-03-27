use clap::Clap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clap, Clone, Default, PartialEq)]
pub struct CommonOpts {
    #[clap()]
    pub name: String,
    #[clap(long)]
    pub base64: bool,
    #[clap(arg_enum, long, default_value = "converge")]
    pub generate: GenerateOpt,
}

pub trait WithCommonOpts: Serialize {
    fn common_opts(&self) -> &CommonOpts;
}

#[derive(Clap, Clone, PartialEq)]
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
    pub _secret_type: String,
    pub value: String,
    pub options: serde_json::Value,
}

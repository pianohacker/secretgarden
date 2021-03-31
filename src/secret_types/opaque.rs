use anyhow::{anyhow, Context, Result as AHResult};
use clap::Clap;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

use crate::secret_store::SecretStore;
use crate::types::{CommonOpts, WithCommonOpts};

#[derive(Clap, Serialize, Deserialize)]
pub struct OpaqueOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
}

impl WithCommonOpts for OpaqueOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

pub fn generate_opaque(_: &OpaqueOpts) -> AHResult<String> {
    Err(anyhow!("Cannot generate opaque value"))
}

#[derive(Clap)]
pub struct SetOpaqueOpts {
    #[clap(about = "Name of the secret to set")]
    name: String,
    #[clap(about = "The new value of the secret; if not provided, will be read on stdin")]
    value: Option<String>,
    #[clap(long, about = "Decode the secret's value with base64")]
    base64: bool,
}

pub fn run_set_opaque(store: &mut impl SecretStore, s: SetOpaqueOpts) -> AHResult<()> {
    let mut value: String;

    match s.value {
        Some(v) => value = v,
        None => {
            value = String::new();

            io::stdin()
                .read_to_string(&mut value)
                .context("Failed to read value from stdin")?;

            value = value.trim_end().to_string();
        }
    }

    if s.base64 {
        value = base64::decode(value)
            .context("Failed to decode provided value as base64")?
            .iter()
            .map(|c| *c as char)
            .collect();
    }

    store.set_opaque(s.name, value)
}

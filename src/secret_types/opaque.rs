use anyhow::{anyhow, Context, Result as AHResult};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::io::{self, Read};

use crate::secret_store::SecretStore;
use crate::types::{CommonOpts, WithCommonOpts};

#[derive(Parser, Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Parser)]
pub struct SetOpaqueOpts {
    #[clap(help = "Name of the secret to set")]
    name: String,
    #[clap(help = "The new value of the secret; if not provided, will be read on stdin")]
    value: Option<String>,
    #[clap(long, help = "Decode the secret's value with base64")]
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
        value = STANDARD
            .decode(value)
            .context("Failed to decode provided value as base64")?
            .iter()
            .map(|c| *c as char)
            .collect();
    }

    store.set_opaque(s.name, value)
}

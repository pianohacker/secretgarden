use anyhow::Result as AHResult;
use clap::Parser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::types::{CommonOpts, ConfigType, WithCommonOpts};

#[derive(Parser, Debug, PartialEq)]
/// Get or generate a password.
///
/// Available config options:
///   * `length`: the length of the generated password (defaults to 32).
#[clap(verbatim_doc_comment)]
pub struct PasswordOpts {
    #[clap(flatten)]
    common: CommonOpts,
}

impl WithCommonOpts for PasswordOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfig {
    #[serde(default = "PasswordConfig::default_length")]
    length: usize,
}

impl ConfigType<'_> for PasswordConfig {}

impl PasswordConfig {
    fn default_length() -> usize {
        32
    }
}

const PASSWORD_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PASSWORD_FIRST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub fn generate_password(_: &PasswordOpts, c: &PasswordConfig) -> AHResult<String> {
    let mut result: String = String::new();
    let mut rng = rand::thread_rng();

    result.push(PASSWORD_FIRST_CHARS[rng.gen_range(0..PASSWORD_FIRST_CHARS.len())] as char);

    for _ in 1..c.length {
        result.push(PASSWORD_CHARS[rng.gen_range(0..PASSWORD_CHARS.len())] as char);
    }

    Ok(result)
}

use anyhow::Result as AHResult;
use clap::Parser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::types::{CommonOpts, WithCommonOpts};

#[derive(Parser, Debug, Serialize, Deserialize, PartialEq)]
pub struct PasswordOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
    #[clap(
        short,
        long,
        default_value = "32",
        help = "Length of the generated password."
    )]
    length: usize,
}

impl WithCommonOpts for PasswordOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

const PASSWORD_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PASSWORD_FIRST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub fn generate_password(p: &PasswordOpts) -> AHResult<String> {
    let mut result: String = String::new();
    let mut rng = rand::thread_rng();

    result.push(PASSWORD_FIRST_CHARS[rng.gen_range(0..PASSWORD_FIRST_CHARS.len())] as char);

    for _ in 1..p.length {
        result.push(PASSWORD_CHARS[rng.gen_range(0..PASSWORD_CHARS.len())] as char);
    }

    Ok(result)
}

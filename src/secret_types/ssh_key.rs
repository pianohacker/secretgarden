use anyhow::{anyhow, Context, Result as AHResult};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::types::{CommonOpts, ConfigType, WithCommonOpts};
use osshkeys::{cipher, keys};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
enum SshKeyType {
    Rsa,
    Dsa,
    Ecdsa,
    #[serde(rename = "ed-25519")]
    Ed25519,
}

#[derive(Parser, Debug, PartialEq)]
pub struct SshKeyOpts {
    #[clap(flatten)]
    common: CommonOpts,
    #[clap(long)]
    public: bool,
}

impl WithCommonOpts for SshKeyOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SshKeyConfig {
    type_: SshKeyType,
    // Number of bits in the generated SSH key. Cannot be changed for ED25519 or DSA keys.
    bits: Option<usize>,
}

impl ConfigType<'_> for SshKeyConfig {}

impl SshKeyConfig {
    fn default_type() -> SshKeyType {
        SshKeyType::Ed25519
    }
}

pub fn transform_ssh_key(private_key: String, opts: &SshKeyOpts) -> AHResult<String> {
    if !opts.public {
        return Ok(private_key);
    }

    let key_pair = keys::KeyPair::from_keystr(&private_key, None)
        .context("Failed to decode SSH private key")?;

    key_pair
        .serialize_publickey()
        .context("Failed to encode SSH public key")
}

pub fn generate_ssh_key(_: &SshKeyOpts, c: &SshKeyConfig) -> AHResult<String> {
    let key_type = match &c.type_ {
        SshKeyType::Rsa => keys::KeyType::RSA,
        SshKeyType::Dsa => keys::KeyType::DSA,
        SshKeyType::Ecdsa => keys::KeyType::ECDSA,
        SshKeyType::Ed25519 => keys::KeyType::ED25519,
    };

    if c.type_ == SshKeyType::Dsa && c.bits.unwrap_or(1024) != 1024 {
        return Err(anyhow!("DSA SSH keys can only have 1024 bits"));
    }

    if c.type_ == SshKeyType::Ed25519 && c.bits.is_some() {
        return Err(anyhow!("Bits cannot be specified for ED25519 SSH keys"));
    }

    let key_pair = keys::KeyPair::generate(key_type, c.bits.unwrap_or(0))
        .context("Failed to generate SSH key")?;

    key_pair
        .serialize_openssh(None, cipher::Cipher::Null)
        .context("Failed to encode SSH key")
}

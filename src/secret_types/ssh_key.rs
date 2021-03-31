use anyhow::{anyhow, Context, Result as AHResult};
use clap::Clap;
use serde::{Deserialize, Serialize};

use crate::types::{CommonOpts, WithCommonOpts};
use osshkeys::{cipher, keys};

#[derive(Clap, Serialize, Deserialize, PartialEq)]
enum SshKeyType {
    Rsa,
    Dsa,
    Ecdsa,
    #[clap(name = "ed-25519")]
    Ed25519,
}

#[derive(Clap, Serialize, Deserialize)]
pub struct SshKeyOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
    #[serde(skip)]
    #[clap(long)]
    public: bool,
    #[clap(
        arg_enum,
        short,
        long,
        default_value = "ed-25519",
        about = "Type of the generated SSH key."
    )]
    type_: SshKeyType,
    #[clap(
        short,
        long,
        about = "Number of bits in the generated SSH key. Cannot be changed for ED25519 or DSA keys."
    )]
    bits: Option<usize>,
}

impl WithCommonOpts for SshKeyOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
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

pub fn generate_ssh_key(o: &SshKeyOpts) -> AHResult<String> {
    let key_type = match &o.type_ {
        SshKeyType::Rsa => keys::KeyType::RSA,
        SshKeyType::Dsa => keys::KeyType::DSA,
        SshKeyType::Ecdsa => keys::KeyType::ECDSA,
        SshKeyType::Ed25519 => keys::KeyType::ED25519,
    };

    if o.type_ == SshKeyType::Dsa && o.bits.unwrap_or(1024) != 1024 {
        return Err(anyhow!("DSA SSH keys can only have 1024 bits"));
    }

    if o.type_ == SshKeyType::Ed25519 && o.bits.is_some() {
        return Err(anyhow!("Bits cannot be specified for ED25519 SSH keys"));
    }

    let key_pair = keys::KeyPair::generate(key_type, o.bits.unwrap_or(0))
        .context("Failed to generate SSH key")?;

    key_pair
        .serialize_openssh(None, cipher::Cipher::Null)
        .context("Failed to encode SSH key")
}

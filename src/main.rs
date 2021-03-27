// Copyright (c) 2020 Jesse Weaver.
//
// This file is part of secretgarden.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result as AHResult};
use base64::{self};
use clap::Clap;
use dirs_next;
use osshkeys::{cipher, keys};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Read};

mod secret_store;
mod ssh_agent_decryptor;
mod types;

use crate::secret_store::{ContainedSecretStore, SecretStore};
use crate::ssh_agent_decryptor::SshAgentSecretContainerFile;
use crate::types::{CommonOpts, WithCommonOpts};

#[derive(Clap)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    #[clap(version = env!("CARGO_PKG_VERSION"), about = "Get or generate a password")]
    Password(PasswordOpts),

    #[clap(version = env!("CARGO_PKG_VERSION"), about = "Get an opaque value")]
    Opaque(OpaqueOpts),

    #[clap(version = env!("CARGO_PKG_VERSION"), about = "Get or generate an SSH key")]
    SshKey(SshKeyOpts),

    #[clap(version = env!("CARGO_PKG_VERSION"), about = "Set an opaque value")]
    SetOpaque(SetOpaqueOpts),

    #[clap(version = env!("CARGO_PKG_VERSION"), about = "Install the Ansible plugin to our home directory")]
    InstallAnsiblePlugin,
}

fn run_secret_type_with_transform<OptsT: WithCommonOpts>(
    store: &mut impl SecretStore,
    secret_type: &str,
    generator: impl Fn(&OptsT) -> AHResult<String>,
    transformer: impl Fn(String, &OptsT) -> AHResult<String>,
    opts: &OptsT,
) -> AHResult<()> {
    let mut value = store.get_or_generate(generator, secret_type, &opts)?;

    if opts.common_opts().base64 {
        value = base64::encode(value.chars().map(|c| c as u8).collect::<Vec<u8>>());
    }

    println!("{}", transformer(value, opts)?);

    Ok(())
}

fn run_secret_type<OptsT: WithCommonOpts>(
    store: &mut impl SecretStore,
    secret_type: &str,
    generator: impl Fn(&OptsT) -> AHResult<String>,
    opts: &OptsT,
) -> AHResult<()> {
    run_secret_type_with_transform(store, secret_type, generator, |x, _| Ok(x), opts)
}

#[derive(Clap, Serialize, Deserialize, PartialEq)]
struct PasswordOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
    #[clap(short, long, default_value = "32")]
    length: usize,
}

impl WithCommonOpts for PasswordOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

const PASSWORD_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PASSWORD_FIRST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn generate_password(p: &PasswordOpts) -> AHResult<String> {
    let mut result: String = String::new();
    let mut rng = rand::thread_rng();

    result.push(PASSWORD_FIRST_CHARS[rng.gen_range(0..PASSWORD_FIRST_CHARS.len())] as char);

    for _ in 1..p.length {
        result.push(PASSWORD_CHARS[rng.gen_range(0..PASSWORD_CHARS.len())] as char);
    }

    Ok(result)
}

#[derive(Clap, Serialize, Deserialize)]
struct OpaqueOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
}

impl WithCommonOpts for OpaqueOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

fn generate_opaque(_: &OpaqueOpts) -> AHResult<String> {
    Err(anyhow!("Cannot generate opaque value"))
}

#[derive(Clap, Serialize, Deserialize, PartialEq)]
enum SshKeyType {
    Rsa,
    Dsa,
    Ecdsa,
    #[clap(name = "ed-25519")]
    Ed25519,
}

#[derive(Clap, Serialize, Deserialize)]
struct SshKeyOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
    #[serde(skip)]
    #[clap(long)]
    public: bool,
    #[clap(arg_enum, short, long, default_value = "ed-25519")]
    type_: SshKeyType,
    #[clap(short, long)]
    bits: Option<usize>,
}

impl WithCommonOpts for SshKeyOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

fn transform_ssh_key(private_key: String, opts: &SshKeyOpts) -> AHResult<String> {
    if !opts.public {
        return Ok(private_key);
    }

    let key_pair = keys::KeyPair::from_keystr(&private_key, None)
        .context("Failed to decode SSH private key")?;

    key_pair
        .serialize_publickey()
        .context("Failed to encode SSH public key")
}

fn generate_ssh_key(o: &SshKeyOpts) -> AHResult<String> {
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

#[derive(Clap)]
struct SetOpaqueOpts {
    #[clap()]
    name: String,
    #[clap()]
    value: Option<String>,
    #[clap(long)]
    base64: bool,
}

fn run_set_opaque(store: &mut impl SecretStore, s: SetOpaqueOpts) -> AHResult<()> {
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

fn run_install_ansible_plugin() -> AHResult<()> {
    let home_dir_path = dirs_next::home_dir().ok_or(anyhow!(
        "Could not determine your home directory; is $HOME set?"
    ))?;

    let ansible_lookup_plugin_directory = format!(
        "{}/.ansible/plugins/lookup",
        home_dir_path.to_str().unwrap(),
    );

    let ansible_lookup_plugin_path =
        format!("{}/secretgarden.py", ansible_lookup_plugin_directory,);

    fs::create_dir_all(ansible_lookup_plugin_directory)
        .context("Failed to create directory {} for Ansible lookup plugin")?;

    fs::write(
        &ansible_lookup_plugin_path,
        include_bytes!("ansible_lookup_plugin.py").to_vec(),
    )
    .context(format!(
        "Failed to write Ansible plugin to {}",
        &ansible_lookup_plugin_path
    ))
}

fn main() -> AHResult<()> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    let opt = Opts::parse();

    let ssh_auth_sock_path = env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK not set; ssh-agent not running?"))?;

    let mut store = ContainedSecretStore::new(SshAgentSecretContainerFile::new(ssh_auth_sock_path));

    match opt.subcmd {
        SubCommand::Password(o) => run_secret_type(&mut store, "password", generate_password, &o),
        SubCommand::Opaque(o) => run_secret_type(&mut store, "opaque", generate_opaque, &o),
        SubCommand::SshKey(o) => run_secret_type_with_transform(
            &mut store,
            "ssh-key",
            generate_ssh_key,
            transform_ssh_key,
            &o,
        ),
        SubCommand::SetOpaque(o) => run_set_opaque(&mut store, o),
        SubCommand::InstallAnsiblePlugin => run_install_ansible_plugin(),
    }
}

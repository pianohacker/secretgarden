// Copyright (c) 2020 Jesse Weaver.
//
// This file is part of secretgarden.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result as AHResult};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use dirs_next;
use git_version::git_version;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use types::ConfigType;
use types::SecretType;
use types::WithCommonOpts;

mod config;
mod secret_store;
mod secret_types;
mod ssh_agent_decryptor;
mod types;

use crate::secret_store::{ContainedSecretStore, SecretStore};
use crate::secret_types::opaque::{generate_opaque, run_set_opaque, OpaqueOpts, SetOpaqueOpts};
use crate::secret_types::password::{generate_password, PasswordOpts};
use crate::secret_types::ssh_key::{generate_ssh_key, transform_ssh_key, SshKeyOpts};
use crate::secret_types::x509::{run_x509, X509Opts};
use crate::ssh_agent_decryptor::SshAgentSecretContainerFile;
use crate::types::OptionsType;

const SECRETGARDEN_VERSION: &str = git_version!(
    prefix = "",
    suffix = "",
    cargo_prefix = "",
    cargo_suffix = "",
    fallback = "unknown"
);

#[derive(Parser)]
#[clap(version = SECRETGARDEN_VERSION)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    #[clap(version = SECRETGARDEN_VERSION)]
    Opaque(OpaqueOpts),

    #[clap(version = SECRETGARDEN_VERSION)]
    Password(PasswordOpts),

    #[clap(version = SECRETGARDEN_VERSION)]
    SetOpaque(SetOpaqueOpts),

    #[clap(version = SECRETGARDEN_VERSION)]
    SshKey(SshKeyOpts),

    #[clap(version = SECRETGARDEN_VERSION)]
    X509(X509Opts),

    #[clap(version = SECRETGARDEN_VERSION)]
    List(ListOpts),

    /// Install the Ansible plugin to your home directory.
    #[clap(version = SECRETGARDEN_VERSION)]
    InstallAnsiblePlugin,
}

fn run_secret_type_with_transform<'a, OptsT: OptionsType<'a>, ConfigT: ConfigType<'a>>(
    store: &mut impl SecretStore,
    config: &config::Config,
    secret_type: SecretType,
    generator: impl Fn(&OptsT, &ConfigT) -> AHResult<String>,
    transformer: impl Fn(String, &OptsT) -> AHResult<String>,
    opts: &OptsT,
) -> AHResult<()> {
    let config = config.get(secret_type, &opts.common_opts().name)?;
    let mut value = store.get_or_generate(generator, secret_type, &opts, &config)?;

    if opts.common_opts().base64 {
        value = STANDARD.encode(value.chars().map(|c| c as u8).collect::<Vec<u8>>());
    }

    println!("{}", transformer(value, opts)?);

    Ok(())
}

fn run_secret_type<'a, OptsT: OptionsType<'a>, ConfigT: ConfigType<'a>>(
    store: &mut impl SecretStore,
    config: &config::Config,
    secret_type: SecretType,
    generator: impl Fn(&OptsT, &ConfigT) -> AHResult<String>,
    opts: &OptsT,
) -> AHResult<()> {
    run_secret_type_with_transform(store, config, secret_type, generator, |x, _| Ok(x), opts)
}

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
/// List all known secrets.
pub struct ListOpts {}

fn run_list(store: &mut impl SecretStore, _: ListOpts) -> AHResult<()> {
    let mut secrets: Vec<_> = store.get_secrets()?.iter().collect();

    secrets.sort_by(|(a_name, _), (b_name, _)| a_name.cmp(b_name));

    for (name, secret) in secrets {
        println!("{}\t{}", name, secret.secret_type);
    }

    Ok(())
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

    let opts = Opts::parse();

    let ssh_auth_sock_path = env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK not set; ssh-agent not running?"))?;

    let config = config::Config::load()?;

    let mut store = ContainedSecretStore::new(SshAgentSecretContainerFile::new(ssh_auth_sock_path));

    match opts.subcmd {
        SubCommand::Opaque(o) => {
            run_secret_type(&mut store, &config, SecretType::Opaque, generate_opaque, &o)
        }
        SubCommand::Password(o) => run_secret_type(
            &mut store,
            &config,
            SecretType::Password,
            generate_password,
            &o,
        ),

        SubCommand::SetOpaque(o) => run_set_opaque(&mut store, o),
        SubCommand::SshKey(o) => run_secret_type_with_transform(
            &mut store,
            &config,
            SecretType::SshKey,
            generate_ssh_key,
            transform_ssh_key,
            &o,
        ),
        SubCommand::X509(o) => {
            let config = config.get(SecretType::X509, &o.common_opts().name)?;
            run_x509(&mut store, &o, &config)
        }

        SubCommand::List(o) => run_list(&mut store, o),

        SubCommand::InstallAnsiblePlugin => run_install_ansible_plugin(),
    }
}

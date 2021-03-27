// Copyright (c) 2020 Jesse Weaver.
//
// This file is part of secretgarden.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result as AHResult};
use base64;
use clap::Clap;
use dirs_next;
use std::env;
use std::fs;

mod secret_store;
mod secret_types;
mod ssh_agent_decryptor;
mod types;

use crate::secret_store::{ContainedSecretStore, SecretStore};
use crate::secret_types::opaque::{generate_opaque, run_set_opaque, OpaqueOpts, SetOpaqueOpts};
use crate::secret_types::password::{generate_password, PasswordOpts};
use crate::secret_types::ssh_key::{generate_ssh_key, transform_ssh_key, SshKeyOpts};
use crate::ssh_agent_decryptor::SshAgentSecretContainerFile;
use crate::types::WithCommonOpts;

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

    let mut store = ContainedSecretStore::new(SshAgentSecretContainerFile::new(ssh_auth_sock_path));

    match opts.subcmd {
        SubCommand::Password(o) => run_secret_type(&mut store, "password", generate_password, &o),

        SubCommand::Opaque(o) => run_secret_type(&mut store, "opaque", generate_opaque, &o),
        SubCommand::SetOpaque(o) => run_set_opaque(&mut store, o),

        SubCommand::SshKey(o) => run_secret_type_with_transform(
            &mut store,
            "ssh-key",
            generate_ssh_key,
            transform_ssh_key,
            &o,
        ),

        SubCommand::InstallAnsiblePlugin => run_install_ansible_plugin(),
    }
}

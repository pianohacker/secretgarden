// Copyright (c) 2020 Jesse Weaver.
//
// This file is part of secretgarden.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result as AHResult};
use argon2;
use base64::{self, display::Base64Display};
use bincode;
use byteorder::{BigEndian, ByteOrder};
use clap::Clap;
use crypto::{digest::Digest, sha2::Sha256};
use osshkeys::{cipher, keys};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;
use sodiumoxide::crypto::secretbox;
use ssh_agent::proto as ssh_agent_proto;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use tempfile;

type SecretMap = HashMap<String, Secret>;
// File signature chosen a-la PNG; non-ASCII value, followed by line endings in both formats to
// check for mangling.
const MAGIC: &[u8] = b"\xffSecretGarden\r\n\032\n";
const DEFAULT_FILENAME: &str = "secretgarden.dat";
const ARGON2_HASH_LENGTH: u32 = secretbox::KEYBYTES as u32;
const ARGON2_SALT_LENGTH: usize = 16;
const ARGON2_AD: &[u8] = b"secretgarden-argon2-ad";
const SIGNED_INPUT_LENGTH: u32 = ARGON2_HASH_LENGTH + 8;

#[derive(Serialize, Deserialize)]
struct SecretsEncWrapper {
    signed_input: Vec<u8>,
    argon2_salt: [u8; ARGON2_SALT_LENGTH],
    secretbox_nonce: [u8; secretbox::NONCEBYTES],
    encrypting_ssh_identity_comment: String,
    encrypting_ssh_identity_fingerprint: Vec<u8>,
    contents: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SecretFile {
    secrets: SecretMap,
}

#[derive(Clone, Serialize, Deserialize)]
struct Secret {
    _secret_type: String,
    value: String,
    options: serde_json::Value,
}

struct SecretStore {
    _secrets: Option<SecretMap>,
    ssh_auth_sock_path: String,
    ssh_agent_conn: Option<UnixStream>,
}

struct HashedSshIdentity {
    fingerprint: Vec<u8>,
    comment: String,
    pubkey_blob: Vec<u8>,
}

fn ssh_agent_decode(r: &mut impl Read) -> AHResult<ssh_agent_proto::Message> {
    let mut msg_len_bytes = [0; 4];
    r.read_exact(&mut msg_len_bytes)
        .context("Failed to read from SSH agent")?;

    let msg_len = BigEndian::read_u32(&msg_len_bytes) as usize;

    let mut msg_bytes = vec![0; msg_len];
    r.read_exact(&mut msg_bytes)
        .context("Failed to read from SSH agent")?;

    ssh_agent_proto::from_bytes(&msg_bytes).context("Failed to deserialize message from SSH agent")
}

fn ssh_agent_encode(r: &mut impl Write, msg: &ssh_agent_proto::Message) -> AHResult<()> {
    let msg_bytes =
        ssh_agent_proto::to_bytes(msg).context("Failed to serialize message to SSH agent")?;
    let mut msg_len_bytes = [0; 4];
    BigEndian::write_u32(&mut msg_len_bytes, msg_bytes.len() as u32);
    r.write_all(&msg_len_bytes)?;

    r.write_all(&msg_bytes)
        .context("Failed to write to SSH agent")
}

impl SecretStore {
    fn new(ssh_auth_sock_path: String) -> SecretStore {
        SecretStore {
            _secrets: None,
            ssh_auth_sock_path,
            ssh_agent_conn: None,
        }
    }

    fn _argon2_config<'b>() -> argon2::Config<'b> {
        let mut argon2_config = argon2::Config::default();
        argon2_config.ad = ARGON2_AD;
        argon2_config.hash_length = ARGON2_HASH_LENGTH;
        argon2_config.variant = argon2::Variant::Argon2id;

        argon2_config
    }

    fn get_agent_reader_writer(&mut self) -> AHResult<(impl Read, impl Write)> {
        if self.ssh_agent_conn.is_none() {
            self.ssh_agent_conn = Some({
                let conn = UnixStream::connect(&self.ssh_auth_sock_path).context(format!(
                    "Could not connect to SSH agent at {}",
                    self.ssh_auth_sock_path
                ))?;
                conn.set_read_timeout(Some(Duration::new(1, 0)))?;
                conn
            });
        }

        let conn = self.ssh_agent_conn.as_mut().unwrap();

        Ok((conn.try_clone()?, conn.try_clone()?))
    }

    fn get_agent_identities(&mut self) -> AHResult<Vec<HashedSshIdentity>> {
        let (mut reader, mut writer) = self.get_agent_reader_writer()?;

        ssh_agent_encode(&mut writer, &ssh_agent_proto::Message::RequestIdentities)?;

        let identities_reply = ssh_agent_decode(&mut reader)?;

        let identities = match identities_reply {
            ssh_agent_proto::Message::IdentitiesAnswer(i) => i,
            _ => {
                return Err(anyhow!(
                    "Unexpected reply from SSH agent: {:?}",
                    identities_reply
                ))
            }
        };

        Ok(identities
            .iter()
            .filter(|i| {
                let key_type_len = BigEndian::read_u32(&i.pubkey_blob) as usize;
                let key_type = &i.pubkey_blob[4..(key_type_len + 4)];

                key_type == b"ssh-rsa" || key_type == b"ssh-ed25519"
            })
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.input(&i.pubkey_blob);
                let mut fingerprint = vec![0; hasher.output_bytes()];
                hasher.result(&mut fingerprint);

                HashedSshIdentity {
                    fingerprint,
                    comment: i.comment.to_owned(),
                    pubkey_blob: i.pubkey_blob.to_owned(),
                }
            })
            .collect())
    }

    fn get_agent_signature(
        &mut self,
        data: &[u8],
        identity: &HashedSshIdentity,
    ) -> AHResult<Vec<u8>> {
        let (mut reader, mut writer) = self.get_agent_reader_writer()?;
        ssh_agent_encode(
            &mut writer,
            &ssh_agent_proto::Message::SignRequest(ssh_agent_proto::SignRequest {
                pubkey_blob: identity.pubkey_blob.to_owned(),
                data: data.to_vec(),
                flags: 0,
            }),
        )?;

        let sign_request_reply = ssh_agent_decode(&mut reader)?;

        let sign_response = match sign_request_reply {
            ssh_agent_proto::Message::SignResponse(s) => s,
            _ => {
                return Err(anyhow!(
                    "Unexpected reply from SSH agent: {:?}",
                    sign_request_reply
                ))
            }
        };

        Ok(sign_response)
    }

    fn _decrypt<P: AsRef<Path>>(&mut self, path: P) -> AHResult<Vec<u8>> {
        let mut file = File::open(path).context("Failed to open secrets file")?;

        let mut magic_buf = [0u8; MAGIC.len()];
        if file.read(&mut magic_buf).is_err() || magic_buf != MAGIC {
            return Err(anyhow!(
                "Invalid magic value in header; secrets file invalid or corrupted"
            ));
        }

        let secrets_wrapper: SecretsEncWrapper =
            bincode::deserialize_from(file).context("Could not read secrets file")?;

        let identities = self.get_agent_identities()?;

        let encrypting_identity = identities
            .iter()
            .find(|&identity| {
                identity.fingerprint == secrets_wrapper.encrypting_ssh_identity_fingerprint
            })
            .ok_or(anyhow!(
                "Cannot find key in agent with fingerprint SHA256:{} ({})",
                Base64Display::with_config(
                    &secrets_wrapper.encrypting_ssh_identity_fingerprint,
                    base64::STANDARD_NO_PAD
                ),
                secrets_wrapper.encrypting_ssh_identity_comment,
            ))?;

        let signed_output =
            self.get_agent_signature(&secrets_wrapper.signed_input, &encrypting_identity)?;

        let argon2_hash = argon2::hash_raw(
            &signed_output,
            &secrets_wrapper.argon2_salt,
            &Self::_argon2_config(),
        )
        .context("Failed to derive encryption key")?;

        if cfg!(feature = "crypto-trace") {
            eprintln!("Decryption parameters: ");
            eprintln!(
                "  Signed input: {}",
                Base64Display::with_config(&secrets_wrapper.signed_input, base64::STANDARD)
            );
            eprintln!(
                "  Signed output: {}",
                Base64Display::with_config(&signed_output, base64::STANDARD)
            );
            eprintln!(
                "  Argon2 salt: {}",
                Base64Display::with_config(&secrets_wrapper.argon2_salt, base64::STANDARD)
            );
            eprintln!(
                "  Argon2 hash: {}",
                Base64Display::with_config(&argon2_hash, base64::STANDARD)
            );
            eprintln!(
                "  Secretbox nonce: {}",
                Base64Display::with_config(&secrets_wrapper.secretbox_nonce, base64::STANDARD)
            );
            eprintln!();
        }

        // We have to use map_err/anyhow! because secretbox::open returns a Result<..., ()>, which
        // does not have a context() implementation.
        secretbox::open(
            &secrets_wrapper.contents,
            &secretbox::Nonce::from_slice(&secrets_wrapper.secretbox_nonce).unwrap(),
            &secretbox::Key::from_slice(&argon2_hash).unwrap(),
        )
        .map_err(|_| anyhow!("Failed to decrypt secrets"))
    }

    fn _load_secrets(&mut self) -> AHResult<&mut SecretMap> {
        if let Some(ref mut _secrets) = self._secrets {
            return Ok(_secrets);
        }

        let mut _secrets;

        let secrets_location = Path::new(DEFAULT_FILENAME);

        if secrets_location.is_file() {
            let existing_contents = self._decrypt(secrets_location)?;

            let existing_secrets: SecretFile = serde_json::from_slice(&existing_contents)
                .context("Could not parse secrets JSON")?;

            _secrets = existing_secrets.secrets;
        } else {
            _secrets = HashMap::new();
        }

        self._secrets = Some(_secrets);
        Ok(self._secrets.as_mut().unwrap())
    }

    fn _store_secrets(&mut self) -> AHResult<()> {
        let mut f =
            tempfile::NamedTempFile::new().context("Failed to open temporary file for output")?;

        let serialized_secrets = serde_json::to_vec(&SecretFile {
            secrets: self._secrets.to_owned().unwrap(),
        })
        .context("Failed to serialize secrets")?;

        let mut rng = rand::thread_rng();

        // We have to fill the signed input differently, as rand::AsByteSliceMut implementations
        // are only generated up to a certain size of array.
        let mut signed_input = [0u8; SIGNED_INPUT_LENGTH as usize];
        rng.fill(&mut signed_input as &mut [u8]);
        let argon2_salt: [u8; ARGON2_SALT_LENGTH] = rng.gen();
        let secretbox_nonce: [u8; secretbox::NONCEBYTES] = rng.gen();

        let identities = self.get_agent_identities()?;
        let encrypting_identity = identities.get(0).ok_or(anyhow!(
            "No valid keys in SSH agent to encrypt with (only RSA or ED25519 keys are accepted)"
        ))?;
        let signed_output = self.get_agent_signature(&signed_input, &encrypting_identity)?;

        let argon2_hash = argon2::hash_raw(&signed_output, &argon2_salt, &Self::_argon2_config())
            .context("Failed to derive encryption key")?;

        if cfg!(feature = "crypto-trace") {
            eprintln!("Encryption parameters: ");
            eprintln!(
                "  Signed input: {}",
                Base64Display::with_config(&signed_input, base64::STANDARD)
            );
            eprintln!(
                "  Signed output: {}",
                Base64Display::with_config(&signed_output, base64::STANDARD)
            );
            eprintln!(
                "  Argon2 salt: {}",
                Base64Display::with_config(&argon2_salt, base64::STANDARD)
            );
            eprintln!(
                "  Argon2 hash: {}",
                Base64Display::with_config(&argon2_hash, base64::STANDARD)
            );
            eprintln!(
                "  Secretbox nonce: {}",
                Base64Display::with_config(&secretbox_nonce, base64::STANDARD)
            );
            eprintln!();
        }

        let encrypted_contents = secretbox::seal(
            &serialized_secrets,
            &secretbox::Nonce::from_slice(&secretbox_nonce).unwrap(),
            &secretbox::Key::from_slice(&argon2_hash).unwrap(),
        );

        f.write(MAGIC).unwrap();

        bincode::serialize_into(
            &f,
            &SecretsEncWrapper {
                signed_input: signed_input.to_vec(),
                argon2_salt,
                secretbox_nonce,
                encrypting_ssh_identity_comment: encrypting_identity.comment.to_owned(),
                encrypting_ssh_identity_fingerprint: encrypting_identity.fingerprint.to_owned(),
                contents: encrypted_contents,
            },
        )
        .unwrap();

        f.persist(DEFAULT_FILENAME)
            .context("Failed to move new secrets to final location")?;

        Ok(())
    }

    fn get_or_generate<OptsT: WithCommonOpts>(
        &mut self,
        f: impl Fn(&OptsT) -> AHResult<String>,
        secret_type: &str,
        opts: &OptsT,
    ) -> AHResult<String> {
        let secrets = self._load_secrets()?;
        let common_opts = opts.common_opts();
        let serialized_opts: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(opts).context("Failed to serialize options")?,
        )
        .context("Failed to deserialize options")?;

        if let Some(secret) = secrets.get(&common_opts.name) {
            if secret.options == serialized_opts || common_opts.generate == GenerateOpt::Once {
                return Ok(secret.value.to_string());
            }
        }

        if common_opts.generate == GenerateOpt::Never {
            return Err(anyhow!(
                "Secret {} does not exist and generation is disabled",
                common_opts.name
            ));
        }

        let value = f(opts)?;
        secrets.insert(
            common_opts.name.to_owned(),
            Secret {
                _secret_type: secret_type.to_string(),
                value: value.to_owned(),
                options: serialized_opts.clone(),
            },
        );
        self._store_secrets()?;

        Ok(value)
    }

    fn set(&mut self, secret_type: String, key: String, value: String) -> AHResult<()> {
        let secrets = self._load_secrets()?;

        secrets.insert(
            key,
            Secret {
                _secret_type: secret_type,
                value: value.clone(),
                options: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        self._store_secrets()?;

        Ok(())
    }
}

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

    #[clap(version = env!("CARGO_PKG_VERSION"), about = "Set a value")]
    Set(SetOpts),
}

trait WithCommonOpts: Serialize {
    fn common_opts(&self) -> &CommonOpts;
}

#[derive(Clap, Clone, Default, PartialEq)]
struct CommonOpts {
    #[clap()]
    name: String,
    #[clap(long)]
    base64: bool,
    #[clap(arg_enum, long, default_value = "converge")]
    generate: GenerateOpt,
}

#[derive(Clap, Clone, PartialEq)]
enum GenerateOpt {
    Never,
    Once,
    Converge,
}

impl Default for GenerateOpt {
    fn default() -> Self {
        GenerateOpt::Converge
    }
}

fn run_secret_type_with_transform<OptsT: WithCommonOpts>(
    store: &mut SecretStore,
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
    store: &mut SecretStore,
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

    result.push(PASSWORD_FIRST_CHARS[rng.gen_range(0, PASSWORD_FIRST_CHARS.len())] as char);

    for _ in 1..p.length {
        result.push(PASSWORD_CHARS[rng.gen_range(0, PASSWORD_CHARS.len())] as char);
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
struct SetOpts {
    #[clap(name = "type")]
    type_: String,
    #[clap()]
    name: String,
    #[clap()]
    value: Option<String>,
    #[clap(long)]
    base64: bool,
}

fn run_set(store: &mut SecretStore, s: SetOpts) -> AHResult<()> {
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

    store.set(s.type_, s.name, value)
}

fn main() -> AHResult<()> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    let opt = Opts::parse();

    let ssh_auth_sock_path = env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK not set; ssh-agent not running?"))?;

    let mut store = SecretStore::new(ssh_auth_sock_path);

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
        SubCommand::Set(o) => run_set(&mut store, o),
    }
}

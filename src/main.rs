use argon2;
use bincode;
use clap::Clap;
use osshkeys::{cipher, keys};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;
use sodiumoxide::crypto::secretbox;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
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

#[derive(Default)]
struct SecretStore {
    _secrets: Option<SecretMap>,
}

impl SecretStore {
    fn _argon2_config<'a>() -> argon2::Config<'a> {
        let mut argon2_config = argon2::Config::default();
        argon2_config.ad = ARGON2_AD;
        argon2_config.hash_length = ARGON2_HASH_LENGTH;
        argon2_config.variant = argon2::Variant::Argon2id;

        argon2_config
    }

    fn _decrypt<P: AsRef<Path>>(path: P) -> Vec<u8> {
        let mut file = File::open(path).expect("Failed to open secrets file");

        let mut magic_buf = [0u8; MAGIC.len()];
        if file.read(&mut magic_buf).is_err() || magic_buf != MAGIC {
            panic!("Invalid magic value in header")
        }

        let secrets_wrapper: SecretsEncWrapper =
            bincode::deserialize_from(file).expect("Could not read secrets file");

        // TODO: replace with signature via SSH key
        let signed_output = secrets_wrapper.signed_input;

        let argon2_hash = argon2::hash_raw(
            &signed_output,
            &secrets_wrapper.argon2_salt,
            &Self::_argon2_config(),
        )
        .expect("Failed to derive encryption key");

        secretbox::open(
            &secrets_wrapper.contents,
            &secretbox::Nonce::from_slice(&secrets_wrapper.secretbox_nonce).unwrap(),
            &secretbox::Key::from_slice(&argon2_hash).unwrap(),
        )
        .expect("Failed to decrypt secrets")
    }

    fn _load_secrets(&mut self) -> &mut SecretMap {
        if let Some(ref mut _secrets) = self._secrets {
            return _secrets;
        }

        let mut _secrets;

        let secrets_location = Path::new(DEFAULT_FILENAME);

        if secrets_location.is_file() {
            let existing_contents = Self::_decrypt(secrets_location);

            let existing_secrets: SecretFile =
                serde_json::from_slice(&existing_contents).expect("Could not parse secrets JSON");

            _secrets = existing_secrets.secrets;
        } else {
            _secrets = HashMap::new();
        }

        self._secrets = Some(_secrets);
        self._secrets.as_mut().unwrap()
    }

    fn _store_secrets(&mut self) {
        let mut f =
            tempfile::NamedTempFile::new().expect("Failed to open temporary file for output");

        let serialized_secrets = serde_json::to_vec(&SecretFile {
            secrets: self._secrets.to_owned().unwrap(),
        })
        .expect("Failed to serialize secrets");

        let mut rng = rand::thread_rng();

        // We have to fill the signed input differently, as rand::AsByteSliceMut implementations
        // are only generated up to a certain size of array.
        let mut signed_input = [0u8; SIGNED_INPUT_LENGTH as usize];
        rng.fill(&mut signed_input as &mut [u8]);
        let argon2_salt: [u8; ARGON2_SALT_LENGTH] = rng.gen();
        let secretbox_nonce: [u8; secretbox::NONCEBYTES] = rng.gen();

        let signed_output = signed_input;

        let argon2_hash = argon2::hash_raw(&signed_output, &argon2_salt, &Self::_argon2_config())
            .expect("Failed to derive encryption key");

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
                contents: encrypted_contents,
            },
        )
        .unwrap();

        f.persist(DEFAULT_FILENAME)
            .expect("Failed to move new secrets to final location");
    }

    fn get_or_generate<OptsT: WithCommonOpts>(
        &mut self,
        f: impl Fn(&OptsT) -> String,
        secret_type: &str,
        opts: &OptsT,
    ) -> String {
        let secrets = self._load_secrets();
        let common_opts = opts.common_opts();
        let serialized_opts: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(opts).expect("Failed to serialize options"),
        )
        .expect("Failed to deserialize options");

        if let Some(secret) = secrets.get(&common_opts.name) {
            if secret.options == serialized_opts || common_opts.generate == GenerateOpt::Once {
                return secret.value.to_string();
            }
        }

        if common_opts.generate == GenerateOpt::Never {
            panic!(
                "Secret {} does not exist and generation is disabled",
                common_opts.name
            );
        }

        let value = f(opts);
        secrets.insert(
            common_opts.name.to_owned(),
            Secret {
                _secret_type: secret_type.to_string(),
                value: value.clone(),
                options: serialized_opts.clone(),
            },
        );
        self._store_secrets();

        value
    }

    fn set(&mut self, secret_type: String, key: String, value: String) {
        let secrets = self._load_secrets();

        secrets.insert(
            key,
            Secret {
                _secret_type: secret_type,
                value: value.clone(),
                options: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        self._store_secrets();
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
    generator: impl Fn(&OptsT) -> String,
    transformer: impl Fn(String, &OptsT) -> String,
    opts: &OptsT,
) {
    let mut value = store.get_or_generate(generator, secret_type, &opts);

    if opts.common_opts().base64 {
        value = base64::encode(value.chars().map(|c| c as u8).collect::<Vec<u8>>());
    }

    println!("{}", transformer(value, opts));
}

fn run_secret_type<OptsT: WithCommonOpts>(
    store: &mut SecretStore,
    secret_type: &str,
    generator: impl Fn(&OptsT) -> String,
    opts: &OptsT,
) {
    run_secret_type_with_transform(store, secret_type, generator, |x, _| x, opts)
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

fn generate_password(p: &PasswordOpts) -> String {
    let mut result: String = String::new();
    let mut rng = rand::thread_rng();

    result.push(PASSWORD_FIRST_CHARS[rng.gen_range(0, PASSWORD_FIRST_CHARS.len())] as char);

    for _ in 1..p.length {
        result.push(PASSWORD_CHARS[rng.gen_range(0, PASSWORD_CHARS.len())] as char);
    }

    result
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

fn generate_opaque(_: &OpaqueOpts) -> String {
    panic!("Cannot generate opaque value");
}

#[derive(Clap, Serialize, Deserialize)]
enum SshKeyType {
    Rsa,
    Dsa,
    Ecdsa,
    #[clap(alias = "ed-25519")]
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
    #[clap(short, long, default_value = "0")]
    bits: usize,
}

impl WithCommonOpts for SshKeyOpts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

fn transform_ssh_key(private_key: String, opts: &SshKeyOpts) -> String {
    if !opts.public {
        return private_key;
    }

    let key_pair =
        keys::KeyPair::from_keystr(&private_key, None).expect("Failed to decode SSH private key");

    key_pair
        .serialize_publickey()
        .expect("Failed to encode SSH public key")
}

fn generate_ssh_key(o: &SshKeyOpts) -> String {
    let key_type = match &o.type_ {
        SshKeyType::Rsa => keys::KeyType::RSA,
        SshKeyType::Dsa => keys::KeyType::DSA,
        SshKeyType::Ecdsa => keys::KeyType::ECDSA,
        SshKeyType::Ed25519 => keys::KeyType::ED25519,
    };

    let key_pair = keys::KeyPair::generate(key_type, o.bits).expect("Failed to generate SSH key");

    key_pair
        .serialize_openssh(None, cipher::Cipher::Null)
        .expect("Failed to encode SSH key")
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

fn run_set(store: &mut SecretStore, s: SetOpts) {
    let mut value: String;

    match s.value {
        Some(v) => value = v,
        None => {
            value = String::new();

            io::stdin()
                .read_to_string(&mut value)
                .expect("Failed to read value from stdin");

            value = value.trim_end().to_string();
        }
    }

    if s.base64 {
        value = base64::decode(value)
            .expect("Failed to decode provided value as base64")
            .iter()
            .map(|c| *c as char)
            .collect();
    }

    store.set(s.type_, s.name, value);
}

fn main() {
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");

    let opt = Opts::parse();
    let mut store = SecretStore::default();

    match opt.subcmd {
        SubCommand::Password(o) => {
            run_secret_type(&mut store, "password", generate_password, &o);
        }
        SubCommand::Opaque(o) => {
            run_secret_type(&mut store, "opaque", generate_opaque, &o);
        }
        SubCommand::SshKey(o) => {
            run_secret_type_with_transform(
                &mut store,
                "ssh-key",
                generate_ssh_key,
                transform_ssh_key,
                &o,
            );
        }
        SubCommand::Set(o) => {
            run_set(&mut store, o);
        }
    }
}

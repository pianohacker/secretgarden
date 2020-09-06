use clap::Clap;
use osshkeys::{cipher, keys};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use tempfile;

type SecretMap = HashMap<String, Secret>;

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
    fn _load_secrets(&mut self) -> &mut SecretMap {
        if let Some(ref mut _secrets) = self._secrets {
            return _secrets;
        }

        let mut _secrets;

        if let Ok(existing_contents) = fs::read_to_string("secrets.json.gpg") {
            let existing_secrets: SecretFile =
                serde_json::from_str(&existing_contents).expect("Could not parse secrets JSON");

            _secrets = existing_secrets.secrets;
        } else {
            _secrets = HashMap::new();
        }

        self._secrets = Some(_secrets);
        self._secrets.as_mut().unwrap()
    }

    fn _store_secrets(&mut self) {
        let f = tempfile::NamedTempFile::new().expect("Failed to open temporary file for output");

        serde_json::to_writer(
            &f,
            &SecretFile {
                secrets: self._secrets.clone().unwrap(),
            },
        )
        .unwrap();

        f.persist("secrets.json.gpg")
            .expect("Failed to move new secrets to final location");
    }

    fn get_or_generate<OptsT, F>(&mut self, f: F, secret_type: &str, opts: &OptsT) -> String
    where
        OptsT: WithCommonOpts + Clone + Serialize,
        F: Fn(&OptsT) -> String,
    {
        let secrets = self._load_secrets();
        let common_opts = opts.clone().common_opts();
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
            common_opts.name,
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

trait WithCommonOpts {
    fn common_opts(self) -> CommonOpts;
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

fn run_secret_type_with_transform<OptsT, F, TF>(
    store: &mut SecretStore,
    secret_type: &str,
    generator: F,
    transformer: TF,
    opts: &OptsT,
) where
    OptsT: WithCommonOpts + Clone + Serialize,
    F: Fn(&OptsT) -> String,
    TF: Fn(String, &OptsT) -> String,
{
    let mut value = store.get_or_generate(generator, secret_type, &opts);

    if opts.clone().common_opts().base64 {
        value = base64::encode(value.chars().map(|c| c as u8).collect::<Vec<u8>>());
    }

    println!("{}", transformer(value, opts));
}

fn run_secret_type<OptsT, F>(store: &mut SecretStore, secret_type: &str, generator: F, opts: &OptsT)
where
    OptsT: WithCommonOpts + Clone + Serialize,
    F: Fn(&OptsT) -> String,
{
    run_secret_type_with_transform(store, secret_type, generator, |x, _| x, opts)
}

#[derive(Clap, Serialize, Deserialize, Clone, PartialEq)]
struct PasswordOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
    #[clap(short, long, default_value = "32")]
    length: usize,
}

impl WithCommonOpts for PasswordOpts {
    fn common_opts(self) -> CommonOpts {
        self.common.clone()
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

#[derive(Clap, Serialize, Deserialize, Clone)]
struct OpaqueOpts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
}

impl WithCommonOpts for OpaqueOpts {
    fn common_opts(self) -> CommonOpts {
        self.common.clone()
    }
}

fn generate_opaque(_: &OpaqueOpts) -> String {
    panic!("Cannot generate opaque value");
}

#[derive(Clap, Serialize, Deserialize, Clone)]
enum SshKeyType {
    Rsa,
    Dsa,
    Ecdsa,
    #[clap(alias = "ed-25519")]
    Ed25519,
}

#[derive(Clap, Serialize, Deserialize, Clone)]
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
    fn common_opts(self) -> CommonOpts {
        self.common.clone()
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

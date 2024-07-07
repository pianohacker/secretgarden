use anyhow::{anyhow, Context, Result as AHResult};
use argon2;
use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bincode;
use byteorder::{BigEndian, ByteOrder};
use crypto::{digest::Digest, sha2::Sha256};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use ssh_agent::proto as ssh_agent_proto;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use tempfile;

use crate::secret_store::SecretContainerFile;

// File signature chosen a-la PNG; non-ASCII value, followed by line endings in both formats to
// check for mangling.
const MAGIC: &[u8] = b"\xffSecretGarden\r\n\032\n";
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

struct HashedSshIdentity {
    fingerprint: Vec<u8>,
    comment: String,
    pubkey_blob: Vec<u8>,
}

pub struct SshAgentSecretContainerFile {
    ssh_auth_sock_path: String,
    ssh_agent_conn: Option<UnixStream>,
}

impl SshAgentSecretContainerFile {
    pub fn new(ssh_auth_sock_path: String) -> SshAgentSecretContainerFile {
        SshAgentSecretContainerFile {
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
}

impl SecretContainerFile for SshAgentSecretContainerFile {
    fn decrypt<P: AsRef<Path>>(&mut self, path: P) -> AHResult<Vec<u8>> {
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
                Base64Display::new(
                    &secrets_wrapper.encrypting_ssh_identity_fingerprint,
                    &STANDARD_NO_PAD
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
                Base64Display::new(&secrets_wrapper.signed_input, &STANDARD)
            );
            eprintln!(
                "  Signed output: {}",
                Base64Display::new(&signed_output, &STANDARD)
            );
            eprintln!(
                "  Argon2 salt: {}",
                Base64Display::new(&secrets_wrapper.argon2_salt, &STANDARD)
            );
            eprintln!(
                "  Argon2 hash: {}",
                Base64Display::new(&argon2_hash, &STANDARD)
            );
            eprintln!(
                "  Secretbox nonce: {}",
                Base64Display::new(&secrets_wrapper.secretbox_nonce, &STANDARD)
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

    fn encrypt<P: AsRef<Path>>(&mut self, path: P, data: Vec<u8>) -> AHResult<()> {
        let mut f = match path.as_ref().parent() {
            Some(d) => tempfile::NamedTempFile::new_in(d),
            None => tempfile::NamedTempFile::new(),
        }
        .context("Failed to open temporary file for output")?;

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
                Base64Display::new(&signed_input, &STANDARD)
            );
            eprintln!(
                "  Signed output: {}",
                Base64Display::new(&signed_output, &STANDARD)
            );
            eprintln!(
                "  Argon2 salt: {}",
                Base64Display::new(&argon2_salt, &STANDARD)
            );
            eprintln!(
                "  Argon2 hash: {}",
                Base64Display::new(&argon2_hash, &STANDARD)
            );
            eprintln!(
                "  Secretbox nonce: {}",
                Base64Display::new(&secretbox_nonce, &STANDARD)
            );
            eprintln!();
        }

        let encrypted_contents = secretbox::seal(
            &data,
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

        f.persist(path)
            .context("Failed to move new secrets to final location")?;

        Ok(())
    }
}

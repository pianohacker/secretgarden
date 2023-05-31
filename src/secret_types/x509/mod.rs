mod rfc2253;

use anyhow::{anyhow, bail, Result as AHResult};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::secret_store::SecretStore;
use crate::types::{CommonOpts, ConfigType, Secret, SecretType, WithCommonOpts};

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
/// Get or generate an X.509 certificate.
///
/// Will output the certificate and private key by default.
///
/// Available config options:
///   * `dns-sans`: an optional array of DNS Subject Alternative Names.
///   * `ip-sans`: an optional array of IP Address Subject Alternative Names.
///   * `is-ca`: whether this certificate should be marked as a Certificate Authority.
///   * `duration-days`: how many days from now this certificate should expire (defaults to 365).
///   * `subject`: the subject of this certificate.
///   * `common-name`: a shortcut for `subject = "CN = ..."` (defaults to the name of the secret).
///   * `ca`: the name of another existing `x509` certificate to sign this certificate. The other
///           certificate must be unexpired and marked with `is-ca = true`.
#[clap(verbatim_doc_comment)]
pub struct X509Opts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,

    #[serde(skip)]
    #[clap(
        short,
        long,
        help = "Output the certificate",
        long_help = "Output the certificate. Can be used with the other output options."
    )]
    certificate: bool,
    #[serde(skip)]
    #[clap(
        short,
        long,
        help = "Output the private key",
        long_help = "Output the private key. Can be used with the other output options."
    )]
    private_key: bool,
    #[serde(skip)]
    #[clap(
        short = 'P',
        long,
        help = "Output the public key",
        long_help = "Output the public key. Can be used with the other output options."
    )]
    public_key: bool,
}

impl WithCommonOpts for X509Opts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct X509Config {
    // Add DNS Subject Alternative Names to the certificate
    #[serde(default)]
    dns_sans: Vec<String>,
    // Add IP Subject Alternative Names to the certificate
    #[serde(default)]
    ip_sans: Vec<String>,
    // Mark the certificate as a certificate authority
    #[serde(default)]
    is_ca: bool,
    #[serde(
        default = "X509Config::default_duration_days",
        // Days from now to certificate expiration in days
    )]
    duration_days: u32,
    common_name: Option<String>,
    subject: Option<String>,

    ca: Option<String>,

    // Filled in internally so that generate_x509 can remain pure.
    #[serde(skip)]
    ca_contents: Option<String>,
}

impl X509Config {
    fn default_duration_days() -> u32 {
        365
    }
}

impl ConfigType<'_> for X509Config {
    fn should_cause_secret_regeneration(&self, secret: &Secret) -> AHResult<bool> {
        let serialized_self = serde_json::to_value(&self)?;

        if serialized_self != secret.config {
            return Ok(true);
        }

        let certificate = X509::from_pem(secret.value.as_ref())?;
        let now = Asn1Time::days_from_now(0)?;

        Ok(certificate.not_after() < &now)
    }
}

pub fn transform_x509(certificate_and_private_key: String, opts: &X509Opts) -> AHResult<String> {
    if !opts.certificate && !opts.private_key && !opts.public_key {
        return Ok(certificate_and_private_key);
    }

    let mut result = String::new();

    if opts.certificate {
        let certificate = X509::from_pem(certificate_and_private_key.as_ref())?;

        result += &String::from_utf8(certificate.to_pem()?)?;
    }

    if opts.private_key {
        let private_key = PKey::private_key_from_pem(certificate_and_private_key.as_ref())?;

        result += &String::from_utf8(private_key.private_key_to_pem_pkcs8()?)?;
    }

    if opts.public_key {
        let private_key = PKey::private_key_from_pem(certificate_and_private_key.as_ref())?;

        result += &String::from_utf8(private_key.public_key_to_pem()?)?;
    }

    Ok(result)
}

pub fn get_cert_name(x: &X509Opts, c: &X509Config) -> AHResult<openssl::x509::X509Name> {
    let mut cert_name_builder = X509NameBuilder::new()?;

    match &c.subject {
        Some(s) => {
            let dn = rfc2253::parse_distinguished_name_str(s)
                .map_err(|_| anyhow!("failed to parse subject"))?;

            for (name, value) in dn {
                cert_name_builder.append_entry_by_text(&name, &value)?;
            }
        }
        None => cert_name_builder.append_entry_by_text(
            "CN",
            c.common_name.as_ref().unwrap_or(&x.common_opts().name),
        )?,
    }

    Ok(cert_name_builder.build())
}

pub fn generate_x509(p: &X509Opts, c: &X509Config) -> AHResult<String> {
    let cert_name = get_cert_name(p, c)?;

    let rsa = Rsa::generate(4096)?;
    let pkey = PKey::from_rsa(rsa)?;
    let mut signing_key = pkey.clone();

    let now = Asn1Time::days_from_now(0)?;
    let expire = Asn1Time::days_from_now(c.duration_days)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.set_subject_name(&cert_name)?;
    cert_builder.set_not_before(&now)?;
    cert_builder.set_not_after(&expire)?;
    cert_builder.set_pubkey(&pkey)?;

    if let Some(ca_contents) = &c.ca_contents {
        let certificate = X509::from_pem(ca_contents.as_ref())?;
        let private_key = PKey::private_key_from_pem(ca_contents.as_ref())?;

        cert_builder.set_issuer_name(certificate.subject_name())?;
        signing_key = private_key.clone();
    } else {
        cert_builder.set_issuer_name(&cert_name)?;
    }

    if c.dns_sans.len() > 0 || c.ip_sans.len() > 0 {
        let ctx = cert_builder.x509v3_context(None, None);
        let mut san_builder = SubjectAlternativeName::new();

        for dns in &c.dns_sans {
            san_builder.dns(dns);
        }

        for ip in &c.ip_sans {
            san_builder.ip(ip);
        }

        let san_ext = san_builder.build(&ctx)?;
        cert_builder.append_extension(san_ext)?;
    }

    if c.is_ca {
        let mut basic_builder = BasicConstraints::new();

        basic_builder.critical();
        basic_builder.ca();

        cert_builder.append_extension(basic_builder.build()?)?;
    }

    cert_builder.sign(&signing_key, MessageDigest::sha256())?;

    Ok(String::from_utf8(cert_builder.build().to_pem()?)?
        + &String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?)
}

pub fn run_x509(store: &mut impl SecretStore, x: &X509Opts, c: &X509Config) -> AHResult<()> {
    let mut c = c.clone();

    if let Some(ca_name) = &c.ca {
        let (ca_contents, ca_config): (String, X509Config) =
            store.get_secret_with_config(SecretType::X509, &ca_name)?;

        if !ca_config.is_ca {
            bail!("attempt to use non-CA secret {} as CA", ca_name);
        }

        if ca_config.should_cause_secret_regeneration(&Secret {
            secret_type: SecretType::X509,
            value: ca_contents.clone(),
            config: serde_json::to_value(ca_config.clone())?,
        })? {
            bail!("CA secret {} cannot be used (expired?)", ca_name);
        }

        c.ca_contents = Some(ca_contents);
    }

    let mut value = store.get_or_generate(generate_x509, SecretType::X509, &x, &c)?;

    if x.common_opts().base64 {
        value = STANDARD.encode(value.chars().map(|c| c as u8).collect::<Vec<u8>>());
    }

    println!("{}", transform_x509(value, &x)?);

    Ok(())
}

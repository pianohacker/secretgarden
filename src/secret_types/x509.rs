use anyhow::Result as AHResult;
use clap::Clap;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509};
use serde::{Deserialize, Serialize};

use crate::types::{CommonOpts, WithCommonOpts};

#[derive(Clap, Serialize, Deserialize, PartialEq)]
pub struct X509Opts {
    #[clap(flatten)]
    #[serde(skip)]
    common: CommonOpts,
    #[clap(short, long, default_value = "32")]
    length: usize,
}

impl WithCommonOpts for X509Opts {
    fn common_opts(&self) -> &CommonOpts {
        &self.common
    }
}

pub fn generate_x509(p: &X509Opts) -> AHResult<String> {
    let mut cert_name_builder = X509NameBuilder::new()?;
    cert_name_builder.append_entry_by_text("CN", &p.common_opts().name)?;
    let cert_name = cert_name_builder.build();

    let rsa = Rsa::generate(4096)?;
    let pkey = PKey::from_rsa(rsa)?;

    let now = Asn1Time::days_from_now(0)?;
    let expire = Asn1Time::days_from_now(365)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.set_subject_name(&cert_name)?;
    cert_builder.set_issuer_name(&cert_name)?;
    cert_builder.set_not_before(&now)?;
    cert_builder.set_not_after(&expire)?;
    cert_builder.set_pubkey(&pkey)?;
    cert_builder.sign(&pkey, MessageDigest::sha256())?;

    Ok(String::from_utf8(cert_builder.build().to_pem()?)?
        + &String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?)
}

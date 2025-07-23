use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

use crate::error::PassError;

/// Configuration for package signing.
///
/// Contains WWDR (Apple Worldwide Developer Relations), Signer Certificate (Developer), Signer Certificate Key (Developer)
/// certificate for pass signing with private key
#[derive(Debug)]
pub struct SignConfig {
    pub sign_key: RsaPrivateKey,
    pub cert: Certificate,
    pub sign_cert: Certificate,
}

impl SignConfig {
    /// Create new config from buffers
    /// # Errors
    /// Returns `PassError` when the certs and keys cannot be loaded
    pub fn new(wwdr: &WWDR, sign_cert: &[u8], sign_key: &str) -> Result<SignConfig, PassError> {
        let cert = match wwdr {
            WWDR::G4 => Certificate::from_der(G4_CERT)?,
            WWDR::Custom(buf) => Certificate::from_pem(buf)?,
        };
        let sign_cert = Certificate::from_pem(sign_cert)?;
        let sign_key = RsaPrivateKey::from_pkcs8_pem(sign_key)?;

        Ok(SignConfig {
            sign_key,
            cert,
            sign_cert,
        })
    }
}

/// G4 certificate from <https://www.apple.com/certificateauthority/>
const G4_CERT: &[u8; 1113] = include_bytes!("AppleWWDRCAG4.cer");

/// Predefined certificate from Apple CA, or custom certificate
pub enum WWDR<'a> {
    G4,
    Custom(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use openssl::{
        error::ErrorStack,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::X509,
    };

    use super::*;

    /// Make x509 certificate and private key
    fn make_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(2048)?;
        let key_pair = PKey::from_rsa(rsa)?;

        let mut x509_name = openssl::x509::X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "RU")?;
        x509_name.append_entry_by_text("ST", "Primorskii krai")?;
        x509_name.append_entry_by_text("O", "Some organization")?;
        x509_name.append_entry_by_text("CN", "CERT TEST")?;
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = openssl::bn::BigNum::new()?;
            serial.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(&x509_name)?;
        cert_builder.set_pubkey(&key_pair)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(
            openssl::x509::extension::BasicConstraints::new()
                .critical()
                .ca()
                .build()?,
        )?;
        cert_builder.append_extension(
            openssl::x509::extension::KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;

        let subject_key_identifier = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        cert_builder.sign(&key_pair, openssl::hash::MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, key_pair))
    }

    #[test]
    fn create_config() {
        // Generate certificate
        let (sign_cert, sign_key) = make_cert().unwrap();

        let sign_cert = &sign_cert.to_pem().unwrap();
        let sign_key = &sign_key.private_key_to_pem_pkcs8().unwrap();
        let pem_str = std::str::from_utf8(sign_key).expect("PEM is not valid UTF-8");

        let _ = SignConfig::new(&WWDR::G4, sign_cert, pem_str).unwrap();
    }
}

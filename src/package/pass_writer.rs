use std::{
    io::{Seek, Write},
    time::SystemTime,
};

use cms::{
    attr::SigningTime,
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use rsa::{pkcs1v15::SigningKey, pkcs8::ObjectIdentifier};
use sha2::{Digest, Sha256};
use x509_cert::{
    attr::Attribute,
    der::{
        asn1::{SetOfVec, UtcTime},
        Any, Encode,
    },
    spki::AlgorithmIdentifier,
};
use zip::{write::SimpleFileOptions, ZipWriter};

use crate::{error::PassError, manifest::Manifest, sign::SignConfig};

/// Object Identifiers for pkpass payload
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_PKCS7_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Filenames for pkpass contents
const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "signature";

/// `PassWriter` is responsible for writing a pkpass file to a writer.
/// It handles writing files to the zip archive, manifest creation, and signing.
pub(super) struct PassWriter<W: Seek + Write> {
    zip_writer: Option<ZipWriter<W>>,
    manifest: Manifest,
    options: SimpleFileOptions,

    sign_config: Option<SignConfig>,
}

impl<W> PassWriter<W>
where
    W: Seek + Write,
{
    pub(super) fn new(writer: W, sign_config: Option<SignConfig>) -> Self {
        Self {
            manifest: Manifest::new(),
            zip_writer: Some(ZipWriter::new(writer)),
            options: SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
            sign_config,
        }
    }
    pub(super) fn write_file(&mut self, filename: &str, buf: &[u8]) -> Result<(), PassError> {
        let zip_writer = self.zip_writer.as_mut().ok_or(PassError::WriterClosed)?;
        zip_writer.start_file(filename, self.options)?;
        zip_writer.write_all(buf)?;
        self.manifest.add_item(filename, buf);
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), PassError> {
        let manifest_content = self.manifest.make_json()?;
        let manifest_data = manifest_content.as_bytes();
        self.write_file(MANIFEST_FILE, manifest_data)?;

        // If SignConfig is provided, create signature and write it to the ZIP file
        if let Some(sign_config) = &self.sign_config {
            let signature_data = sign(sign_config, manifest_data)?;
            self.write_file(SIGNATURE_FILE, &signature_data)?;
        }

        let zip_writer = self.zip_writer.take().ok_or(PassError::WriterClosed)?;
        zip_writer.finish()?;
        Ok(())
    }
}

/// Create a signature for the given manifest data using the provided `SignConfig`.
fn sign(sign_config: &SignConfig, manifest_data: &[u8]) -> Result<Vec<u8>, PassError> {
    let signing_key: SigningKey<Sha256> = SigningKey::new(sign_config.sign_key.clone());
    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: sign_config.sign_cert.clone().tbs_certificate.issuer,
        serial_number: sign_config.sign_cert.clone().tbs_certificate.serial_number,
    });
    let encapsulated_content_info = EncapsulatedContentInfo {
        econtent: None,
        econtent_type: OID_PKCS7_DATA,
    };

    let alg_id = AlgorithmIdentifier::<Any> {
        oid: OID_SHA256,
        parameters: Some(Any::null()),
    };

    let external_message_digest = Some(Sha256::digest(manifest_data));

    let mut signer_info_builder = SignerInfoBuilder::new(
        &signing_key,
        signer_id,
        alg_id.clone(),
        &encapsulated_content_info,
        external_message_digest.as_deref(),
    )?;
    signer_info_builder.add_signed_attribute(get_signing_time_attribute()?)?;

    // Build signed data and DER encode it
    SignedDataBuilder::new(&encapsulated_content_info)
        .add_certificate(CertificateChoices::Certificate(sign_config.cert.clone()))?
        .add_certificate(CertificateChoices::Certificate(
            sign_config.sign_cert.clone(),
        ))?
        .add_signer_info(signer_info_builder)?
        .add_digest_algorithm(alg_id)?
        .build()?
        .to_der()
        .map_err(PassError::ASN1)
}

fn get_signing_time_attribute() -> Result<Attribute, PassError> {
    let signing_time = SigningTime::UtcTime(UtcTime::from_system_time(SystemTime::now())?);
    let mut time_values: SetOfVec<Any> = SetOfVec::new();
    time_values.insert(Any::encode_from(&signing_time)?)?;
    Ok(Attribute {
        oid: OID_SIGNING_TIME,
        values: time_values,
    })
}

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

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_PKCS7_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "signature";

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
        if let Some(zip_writer) = self.zip_writer.as_mut() {
            zip_writer.start_file(filename, self.options)?;
            zip_writer.write_all(buf)?;
            self.manifest.add_item(filename, buf);
            Ok(())
        } else {
            Err(PassError::WriterClosed)
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), PassError> {
        let manifest_content = self.manifest.make_json()?;
        let manifest_bytes = manifest_content.as_bytes();
        self.write_file(MANIFEST_FILE, manifest_bytes)?;

        // If SignConfig is provided, make signature
        if let Some(sign_config) = &self.sign_config {
            let signature_data = create_signature(sign_config, manifest_bytes)?;
            self.write_file(SIGNATURE_FILE, &signature_data)?;
        }

        if let Some(zip_writer) = self.zip_writer.take() {
            zip_writer.finish()?;
            Ok(())
        } else {
            Err(PassError::WriterClosed)
        }
    }
}

fn create_signature(sign_config: &SignConfig, manifest_bytes: &[u8]) -> Result<Vec<u8>, PassError> {
    let signing_key: SigningKey<Sha256> = SigningKey::new(sign_config.sign_key.clone());
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: sign_config.sign_cert.clone().tbs_certificate.issuer,
        serial_number: sign_config.sign_cert.clone().tbs_certificate.serial_number,
    });
    let encapsulated_content_info = EncapsulatedContentInfo {
        econtent: None,
        econtent_type: OID_PKCS7_DATA,
    };
    let time = SigningTime::UtcTime(UtcTime::from_system_time(SystemTime::now())?);
    let mut time_values: SetOfVec<Any> = SetOfVec::new();
    time_values
        // .insert(Any::new(time.tag(), time.to_der().unwrap()).unwrap())
        .insert(Any::encode_from(&time)?)?;

    let alg_id = AlgorithmIdentifier::<Any> {
        oid: OID_SHA256,
        parameters: Some(Any::null()),
    };

    let external_message_digest = Some(Sha256::digest(manifest_bytes));

    let mut signer_info_builder = SignerInfoBuilder::new(
        &signing_key,
        sid,
        alg_id.clone(),
        &encapsulated_content_info,
        external_message_digest.as_deref(),
    )?;
    signer_info_builder.add_signed_attribute(Attribute {
        oid: OID_SIGNING_TIME,
        values: time_values,
    })?;

    // let time_attr = cms::builder::create_signing_time_attribute().unwrap();
    let content_info2 = SignedDataBuilder::new(&encapsulated_content_info)
        .add_certificate(CertificateChoices::Certificate(sign_config.cert.clone()))?
        .add_certificate(CertificateChoices::Certificate(
            sign_config.sign_cert.clone(),
        ))?
        .add_signer_info(signer_info_builder)?
        .add_digest_algorithm(alg_id)?
        .build()?;

    content_info2.to_der().map_err(PassError::ASN1)
}

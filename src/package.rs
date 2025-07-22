use std::{
    io::{Read, Seek, Write},
    str::FromStr,
    time::SystemTime,
};

use cms::{
    attr::SigningTime,
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{
        x509::{attr::Attribute, der::Any, spki::ObjectIdentifier},
        CertificateChoices, IssuerAndSerialNumber,
    },
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{
    der::{
        asn1::{SetOfVec, UtcTime},
        Encode,
    },
    spki::AlgorithmIdentifier,
};
use sha1::Digest;
use sha2::Sha256;

use crate::{error::PassError, pass::Pass};

use self::{manifest::Manifest, resource::Resource, sign::SignConfig};

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_PKCS7_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

pub mod manifest;
pub mod resource;
pub mod sign;

/// Pass Package, contains information about pass.json, images, manifest.json and signature.
#[derive(Debug)]
pub struct Package {
    /// Represents pass.json
    pub pass: Pass,

    /// Resources (image files)
    pub resources: Vec<Resource>,

    // Certificates for signing package
    pub sign_config: Option<SignConfig>,
}

impl Package {
    /// Create new package
    #[must_use]
    pub fn new(pass: Pass) -> Self {
        Self {
            pass,
            resources: vec![],
            sign_config: None,
        }
    }

    /// Read compressed package (.pkpass) from file.
    ///
    /// Use for creating .pkpass file from template.
    /// # Errors
    /// Returns an error if the pass cannot be read
    pub fn read<R: Read + Seek>(reader: R) -> Result<Self, PassError> {
        // Read .pkpass as zip
        let mut zip = zip::ZipArchive::new(reader).map_err(PassError::Compression)?;

        let mut pass: Option<Pass> = None;
        let mut resources = Vec::<Resource>::new();

        for i in 0..zip.len() {
            // Get file name
            let mut file = zip.by_index(i).map_err(PassError::Compression)?;
            let filename = file.name();
            // Read pass.json file
            if filename == "pass.json" {
                let mut buf = String::new();
                file.read_to_string(&mut buf).map_err(PassError::IO)?;
                pass = Some(Pass::from_json(&buf).map_err(PassError::Json)?);
                continue;
            }
            // Read resource files
            if let Ok(t) = resource::Type::from_str(filename) {
                let mut resource = Resource::new(t);
                std::io::copy(&mut file, &mut resource).map_err(PassError::IO)?;
                resources.push(resource);
            }
            // Skip unknown files
        }

        // Check is pass.json successfully read
        if let Some(pass) = pass {
            Ok(Self {
                pass,
                resources,
                sign_config: None,
            })
        } else {
            Err(PassError::MissingJson)
        }
    }

    /// Add certificates for signing package
    pub fn add_certificates(&mut self, config: SignConfig) {
        self.sign_config = Some(config);
    }

    /// Write compressed package.
    ///
    /// Use for creating .pkpass file
    /// # Errors
    /// Returns an error if writing fails
    pub fn write<W: Write + Seek>(&mut self, writer: W) -> Result<(), PassError> {
        let mut manifest = Manifest::new();

        let mut zip = zip::ZipWriter::new(writer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Adding pass.json to zip
        zip.start_file("pass.json", options)
            .map_err(PassError::Compression)?;
        let pass_json = self.pass.make_json().map_err(PassError::Json)?;

        zip.write_all(pass_json.as_bytes()).map_err(PassError::IO)?;
        manifest.add_item("pass.json", pass_json.as_bytes());

        // Adding each resource files to zip
        for resource in &self.resources {
            zip.start_file(resource.filename(), options)
                .map_err(PassError::Compression)?;
            zip.write_all(resource.as_bytes()).map_err(PassError::IO)?;
            manifest.add_item(resource.filename().as_str(), resource.as_bytes());
        }

        // Adding manifest.json to zip
        zip.start_file("manifest.json", options)
            .map_err(PassError::Compression)?;
        let manifest_json = manifest.make_json().map_err(PassError::Json)?;
        zip.write_all(manifest_json.as_bytes())
            .map_err(PassError::IO)?;
        manifest.add_item("manifest.json", manifest_json.as_bytes());

        // If SignConfig is provided, make signature
        if let Some(sign_config) = &self.sign_config {
            // let eci = EncapsulatedContentInfo {
            //     econtent: None,
            //     econtent_type: OID_PKCS7_DATA,
            // };
            let signing_key: SigningKey<Sha256> =
                rsa::pkcs1v15::SigningKey::new(sign_config.sign_key.clone());
            let ius = IssuerAndSerialNumber {
                issuer: sign_config.sign_cert.clone().tbs_certificate.issuer,
                serial_number: sign_config.sign_cert.clone().tbs_certificate.serial_number,
            };
            let sid = SignerIdentifier::IssuerAndSerialNumber(ius);
            // let digest_algorithm = Dig;
            let encapsulated_content_info = EncapsulatedContentInfo {
                econtent: None,
                econtent_type: OID_PKCS7_DATA,
            };
            let hash = Sha256::digest(manifest_json.as_bytes());
            let time = SigningTime::UtcTime(
                UtcTime::from_system_time(SystemTime::now()).map_err(PassError::ASN1)?,
            );

            let alg_id = AlgorithmIdentifier::<Any> {
                oid: OID_SHA256,
                parameters: Some(Any::null()),
            };

            let external_message_digest = Some(hash);
            let mut time_values: SetOfVec<Any> = SetOfVec::new();
            time_values
                // .insert(Any::new(time.tag(), time.to_der().unwrap()).unwrap())
                .insert(Any::encode_from(&time).map_err(PassError::ASN1)?)
                .map_err(PassError::ASN1)?;

            let mut signer_info_builder = SignerInfoBuilder::new(
                &signing_key,
                sid,
                alg_id.clone(),
                &encapsulated_content_info,
                external_message_digest.as_deref(),
            )
            .map_err(PassError::CmsBuilder)?;
            signer_info_builder
                .add_signed_attribute(Attribute {
                    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5"),
                    values: time_values,
                })
                .map_err(PassError::CmsBuilder)?;

            // let time_attr = cms::builder::create_signing_time_attribute().unwrap();
            let content_info2 = SignedDataBuilder::new(&encapsulated_content_info)
                .add_certificate(CertificateChoices::Certificate(sign_config.cert.clone()))
                .map_err(PassError::CmsBuilder)?
                .add_certificate(CertificateChoices::Certificate(
                    sign_config.sign_cert.clone(),
                ))
                .map_err(PassError::CmsBuilder)?
                .add_signer_info(signer_info_builder)
                .map_err(PassError::CmsBuilder)?
                .add_digest_algorithm(alg_id)
                .map_err(PassError::CmsBuilder)?
                .build()
                .map_err(PassError::CmsBuilder)?;

            let signature_data = content_info2.to_der().map_err(PassError::ASN1)?;
            // Adding signature to zip
            zip.start_file("signature", options)
                .map_err(PassError::Compression)?;
            zip.write_all(&signature_data).map_err(PassError::IO)?;
        }

        zip.finish().map_err(PassError::Compression)?;

        Ok(())
    }

    /// Adding image file to package.
    ///
    /// Reading file to internal buffer storage.
    /// # Errors
    /// Returns an error if the writing of the resource fails
    pub fn add_resource<R: Read>(
        &mut self,
        image_type: resource::Type,
        mut reader: R,
    ) -> Result<(), &'static str> {
        let mut resource = Resource::new(image_type);
        std::io::copy(&mut reader, &mut resource).map_err(|_| "Error while reading resource")?;
        self.resources.push(resource);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::pass::{PassBuilder, PassConfig};

    use super::*;

    #[test]
    fn make_package() {
        let pass = PassBuilder::new(PassConfig {
            organization_name: "Apple inc.".into(),
            description: "Example pass".into(),
            pass_type_identifier: "com.example.pass".into(),
            team_identifier: "AA00AA0A0A".into(),
            serial_number: "ABCDEFG1234567890".into(),
        })
        .logo_text("Test pass".into())
        .build();

        let _package = Package::new(pass);
    }

    #[test]
    fn write_package() {
        let pass = PassBuilder::new(PassConfig {
            organization_name: "Apple inc.".into(),
            description: "Example pass".into(),
            pass_type_identifier: "com.example.pass".into(),
            team_identifier: "AA00AA0A0A".into(),
            serial_number: "ABCDEFG1234567890".into(),
        })
        .logo_text("Test pass".into())
        .build();

        let expected_pass_json = pass.make_json().unwrap();

        let mut package = Package::new(pass);

        // Save package as .pkpass
        let mut buf = Vec::new();
        let writer = std::io::Cursor::new(&mut buf);
        package.write(writer).unwrap();

        // Read .pkpass as zip
        let reader = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipArchive::new(reader).unwrap();

        for i in 0..zip.len() {
            let file = zip.by_index(i).unwrap();
            println!("file[{}]: {}", i, file.name());
        }

        // Get pass.json and compare
        let mut packaged_pass_json = String::new();
        let _ = zip
            .by_name("pass.json")
            .unwrap()
            .read_to_string(&mut packaged_pass_json);

        assert_eq!(expected_pass_json, packaged_pass_json);
    }

    #[test]
    fn read_package() {
        let pass = PassBuilder::new(PassConfig {
            organization_name: "Apple inc.".into(),
            description: "Example pass".into(),
            pass_type_identifier: "com.example.pass".into(),
            team_identifier: "AA00AA0A0A".into(),
            serial_number: "ABCDEFG1234567890".into(),
        })
        .logo_text("Test pass".into())
        .build();
        let expected_json = pass.make_json().unwrap();

        // Create package with pass.json
        let mut package = Package::new(pass);

        // Add resources
        let data = [0u8; 2048];
        package
            .add_resource(resource::Type::Icon(resource::Version::Standard), &data[..])
            .unwrap();
        package
            .add_resource(resource::Type::Logo(resource::Version::Size3X), &data[..])
            .unwrap();

        // Save package as .pkpass
        let mut buf = Vec::new();
        let writer = std::io::Cursor::new(&mut buf);
        package.write(writer).unwrap();

        // Read .pkpass
        let reader = std::io::Cursor::new(&mut buf[..]);
        let package_read = Package::read(reader).unwrap();

        // Check pass.json
        let read_json = package_read.pass.make_json().unwrap();
        assert_eq!(expected_json, read_json);

        // Check assets
        println!("{:?}", package.resources);
        assert_eq!(2, package.resources.len());
        assert_eq!("icon.png", package.resources.first().unwrap().filename());
        assert_eq!("logo@3x.png", package.resources.get(1).unwrap().filename());
    }
}

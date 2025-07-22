use thiserror::Error;
use x509_cert::der;
use zip::result::ZipError;

#[derive(Error, Debug)]
pub enum PassError {
    #[error("missing pass.json in package file")]
    MissingJson,
    #[error("failed to compress package: {0}")]
    Compression(ZipError),
    #[error("I/O error: {0}")]
    IO(std::io::Error),
    #[error("Error during JSON conversion: {0}")]
    Json(serde_json::Error),
    #[error("Failed in DER coding stack: {0}")]
    ASN1(der::Error),
    #[error("CMS error: {0}")]
    CmsBuilder(cms::builder::Error),
}

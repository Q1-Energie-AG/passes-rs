use thiserror::Error;
use x509_cert::der;
use zip::result::ZipError;

#[derive(Error, Debug)]
pub enum PassError {
    #[error("missing pass.json in package file")]
    MissingJson,
    #[error("pass writer already closed")]
    WriterClosed,
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

impl From<ZipError> for PassError {
    fn from(err: ZipError) -> Self {
        PassError::Compression(err)
    }
}

impl From<std::io::Error> for PassError {
    fn from(err: std::io::Error) -> Self {
        PassError::IO(err)
    }
}

impl From<serde_json::Error> for PassError {
    fn from(err: serde_json::Error) -> Self {
        PassError::Json(err)
    }
}

impl From<der::Error> for PassError {
    fn from(err: der::Error) -> Self {
        PassError::ASN1(err)
    }
}

impl From<cms::builder::Error> for PassError {
    fn from(err: cms::builder::Error) -> Self {
        PassError::CmsBuilder(err)
    }
}

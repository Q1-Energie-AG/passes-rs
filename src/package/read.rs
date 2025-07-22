use std::{
    io::{Read, Seek},
    str::FromStr,
};

use zip::ZipArchive;

use crate::{
    error::PassError,
    resource::{self, Resource},
    Package, Pass,
};

impl Package {
    /// Read compressed package (.pkpass) from file.
    ///
    /// Use for creating .pkpass file from template.
    /// # Errors
    /// Returns an error if the pass cannot be read
    pub fn read<R: Read + Seek>(reader: R) -> Result<Self, PassError> {
        // Read .pkpass as zip
        let mut zip = ZipArchive::new(reader)?;

        let mut pass: Option<Pass> = None;
        let mut resources = Vec::<Resource>::new();

        for i in 0..zip.len() {
            // Get file name
            let mut file = zip.by_index(i)?;
            let filename = file.name();
            // Read pass.json file
            if filename == "pass.json" {
                let mut buf = String::new();
                file.read_to_string(&mut buf)?;
                pass = Some(Pass::from_json(&buf)?);
                continue;
            }
            // Read resource files
            if let Ok(t) = resource::Type::from_str(filename) {
                let mut resource = Resource::new(t);
                std::io::copy(&mut file, &mut resource)?;
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
}

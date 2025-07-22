use std::io::{Seek, Write};

use crate::{error::PassError, pass_writer::PassWriter, Package};

const PASS_FILE: &str = "pass.json";

impl Package {
    /// Write compressed package.
    ///
    /// Use for creating .pkpass file
    /// # Errors
    /// Returns an error if writing fails
    pub fn write<W: Write + Seek>(&mut self, writer: W) -> Result<(), PassError> {
        let mut pass_writer = PassWriter::new(writer, self.sign_config.take());

        // Adding pass.json to zip
        let pass_json = self.pass.to_json()?;
        pass_writer.write_file(PASS_FILE, pass_json.as_bytes())?;
        // Adding each resource files to zip
        for resource in &self.resources {
            pass_writer.write_file(&resource.filename(), resource.as_bytes())?;
        }

        pass_writer.finish()?;
        Ok(())
    }
}

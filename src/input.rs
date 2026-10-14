use std::fs;
use std::io::{Cursor, Read};

use zip::ZipArchive;

pub(crate) fn read_file_spec(spec: &str) -> Result<Vec<u8>, String> {
    let Some((archive, entry)) = spec.split_once('!') else {
        return fs::read(spec).map_err(|error| format!("{spec}: {error}"));
    };

    if entry.is_empty() || entry.contains('!') {
        return Err("invalid ZIP entry".to_owned());
    }

    let bytes = fs::read(archive).map_err(|error| format!("{archive}: {error}"))?;
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("invalid ZIP {archive}: {error}"))?;
    let mut file = zip
        .by_name(entry)
        .map_err(|error| format!("{archive}!{entry}: {error}"))?;
    let mut output = Vec::new();

    file.read_to_end(&mut output)
        .map_err(|error| format!("{archive}!{entry}: {error}"))?;

    Ok(output)
}

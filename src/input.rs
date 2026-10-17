use std::fs;
use std::io::Read;
use std::path::PathBuf;

use crc32fast::hash;
use zip::ZipArchive;

pub(crate) struct FileSpec {
    source: Source,
    size: u64,
    crc32: u32,
}

enum Source {
    Direct(Vec<u8>),
    Archive(PathBuf, String),
}

impl FileSpec {
    pub(crate) fn open(spec: &str) -> Result<Self, String> {
        let Some((archive, entry)) = spec.split_once('!') else {
            let bytes = fs::read(spec).map_err(|error| format!("{spec}: {error}"))?;

            return Ok(Self {
                size: bytes.len() as u64,
                crc32: hash(&bytes),
                source: Source::Direct(bytes),
            });
        };

        if entry.is_empty() || entry.contains('!') {
            return Err("invalid ZIP entry".to_owned());
        }

        let (size, crc32) = {
            let file = fs::File::open(archive).map_err(|error| format!("{archive}: {error}"))?;
            let mut zip =
                ZipArchive::new(file).map_err(|error| format!("invalid ZIP {archive}: {error}"))?;
            let file = zip
                .by_name(entry)
                .map_err(|error| format!("{archive}!{entry}: {error}"))?;

            (file.size(), file.crc32())
        };

        Ok(Self {
            source: Source::Archive(PathBuf::from(archive), entry.to_owned()),
            size,
            crc32,
        })
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn crc32(&self) -> u32 {
        self.crc32
    }

    pub(crate) fn into_bytes(self, spec: &str) -> Result<Vec<u8>, String> {
        let (archive, entry) = match self.source {
            Source::Direct(bytes) => return Ok(bytes),
            Source::Archive(archive, entry) => (archive, entry),
        };

        let file = fs::File::open(&archive).map_err(|error| format!("{spec}: {error}"))?;
        let mut zip =
            ZipArchive::new(file).map_err(|error| format!("invalid ZIP {spec}: {error}"))?;
        let mut file = zip
            .by_name(&entry)
            .map_err(|error| format!("{spec}: {error}"))?;
        let capacity = usize::try_from(self.size)
            .map_err(|_| format!("{spec}: ZIP entry is too large for this platform"))?;
        let mut output = Vec::with_capacity(capacity);

        file.read_to_end(&mut output)
            .map_err(|error| format!("{spec}: {error}"))?;

        Ok(output)
    }
}

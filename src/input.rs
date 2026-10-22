use std::borrow::Cow;
use std::fs::{self, File};
use std::path::Path;

use crate::zip::Zip;

pub(crate) struct FileSpec {
    source: Source,
    size: u64,
    crc32: u32,
}

enum Source {
    Direct(Vec<u8>),
    Archive(Zip<'static, File>, String),
}

impl FileSpec {
    pub(crate) fn open(spec: &str) -> Result<Self, String> {
        let Some((archive, entry)) = spec.split_once('!') else {
            let bytes = fs::read(spec).map_err(|error| format!("{spec}: {error}"))?;

            return Ok(Self {
                size: bytes.len() as u64,
                crc32: crc32fast::hash(&bytes),
                source: Source::Direct(bytes),
            });
        };

        if entry.is_empty() || entry.contains('!') {
            return Err("invalid ZIP entry".to_owned());
        }

        let mut zip = Zip::open(Path::new(archive))?;
        let (size, crc32) = zip.metadata(entry)?;

        Ok(Self {
            source: Source::Archive(zip, entry.to_owned()),
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
        let (mut zip, entry) = match self.source {
            Source::Direct(bytes) => return Ok(bytes),
            Source::Archive(archive, entry) => (archive, entry),
        };

        zip.read_entry(&entry)
            .map(Cow::into_owned)
            .map_err(|error| format!("{spec}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::FileSpec;

    #[test]
    fn reads_real_mapping_entries_and_metadata() {
        for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            let id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("apkq-entry-{id}.zip"));
            let mut writer = ZipWriter::new(fs::File::create(&path).unwrap());
            let bytes = b"com.example.Foo -> a:\n";
            writer
                .start_file(
                    "maps/release.txt",
                    SimpleFileOptions::default().compression_method(compression),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
            writer.finish().unwrap();
            let spec = format!("{}!maps/release.txt", path.display());
            let source = FileSpec::open(&spec).unwrap();
            assert_eq!(source.size(), bytes.len() as u64);
            assert_eq!(source.crc32(), crc32fast::hash(bytes));
            assert_eq!(source.into_bytes(&spec).unwrap(), bytes);
            assert!(FileSpec::open(&format!("{}!absent.txt", path.display())).is_err());
            assert!(FileSpec::open(&format!("{}!inner.zip!mapping.txt", path.display())).is_err());
            fs::remove_file(path).unwrap();
        }
    }
}

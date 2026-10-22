use std::borrow::Cow;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use ::zip::{CompressionMethod, ZipArchive};

pub(crate) struct Zip<'a, R> {
    archive: ZipArchive<R>,
    bytes: Option<&'a [u8]>,
    label: String,
}

impl Zip<'static, File> {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let label = path.display().to_string();
        let file = File::open(path).map_err(|error| format!("{label}: {error}"))?;
        let archive = ZipArchive::new(file)
            .map_err(|error| format!("invalid ZIP archive {label}: {error}"))?;

        Ok(Self {
            archive,
            bytes: None,
            label,
        })
    }
}

impl<'a> Zip<'a, Cursor<&'a [u8]>> {
    pub(crate) fn from_bytes(bytes: &'a [u8], label: &str) -> Result<Self, String> {
        let label = if label.is_empty() { "input" } else { label };
        let archive = ZipArchive::new(Cursor::new(bytes))
            .map_err(|error| format!("invalid ZIP archive {label}: {error}"))?;

        Ok(Self {
            archive,
            bytes: Some(bytes),
            label: label.to_owned(),
        })
    }
}

impl<'a, R: Read + Seek> Zip<'a, R> {
    pub(crate) fn names(&self) -> Result<Vec<String>, String> {
        self.archive
            .file_names()
            .map(|name| {
                name.map(Cow::into_owned)
                    .map_err(|error| format!("{}: {error}", self.label))
            })
            .collect()
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.archive.index_for_name(name).is_some()
    }

    pub(crate) fn metadata(&mut self, name: &str) -> Result<(u64, u32), String> {
        let entry = self
            .archive
            .by_name(name)
            .map_err(|error| format!("{}!{name}: {error}", self.label))?;

        Ok((entry.size(), entry.crc32()))
    }

    pub(crate) fn read_entry(&mut self, name: &str) -> Result<Cow<'a, [u8]>, String> {
        let mut entry = self
            .archive
            .by_name(name)
            .map_err(|error| format!("{}!{name}: {error}", self.label))?;
        let size = entry.size();

        if let Some(archive_bytes) = self.bytes
            && entry.compression() == CompressionMethod::Stored
            && !entry.encrypted()
            && entry.compressed_size() == size
        {
            let start = entry.data_start().ok_or("missing ZIP entry data offset")?;
            let start = usize::try_from(start).map_err(|_| "ZIP entry offset is too large")?;
            let length = usize::try_from(size).map_err(|_| "ZIP entry size is too large")?;
            let end = start
                .checked_add(length)
                .ok_or("ZIP entry range overflow")?;
            let bytes = archive_bytes
                .get(start..end)
                .ok_or("ZIP entry extends beyond archive")?;

            if crc32fast::hash(bytes) != entry.crc32() {
                return Err(format!(
                    "ZIP entry {name} in {} has an invalid CRC",
                    self.label
                ));
            }

            Ok(Cow::Borrowed(bytes))
        } else {
            let mut bytes = Vec::new();

            entry
                .read_to_end(&mut bytes)
                .map_err(|error| format!("{}!{name}: {error}", self.label))?;

            Ok(Cow::Owned(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Zip;
    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, ZipArchive, ZipWriter};
    use std::borrow::Cow;
    use std::io::{Cursor, Write};

    #[test]
    fn borrows_stored_entries_and_owns_deflated_entries() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, method) in [
            ("classes.dex", CompressionMethod::Stored),
            ("classes2.dex", CompressionMethod::Deflated),
        ] {
            writer
                .start_file(
                    name,
                    SimpleFileOptions::default().compression_method(method),
                )
                .unwrap();
            writer.write_all(b"dex\nexample").unwrap();
        }

        let bytes = writer.finish().unwrap().into_inner();
        let mut archive = Zip::from_bytes(&bytes, "APK").unwrap();

        for (name, borrowed) in [("classes.dex", true), ("classes2.dex", false)] {
            let data = archive.read_entry(name).unwrap();
            assert_eq!(data.as_ref(), b"dex\nexample");
            assert_eq!(matches!(data, Cow::Borrowed(_)), borrowed);
        }

        let stored = archive.read_entry("classes.dex").unwrap();
        let deflated = archive.read_entry("classes2.dex").unwrap();
        assert_eq!(stored.as_ref(), deflated.as_ref());
        assert!(matches!(stored, Cow::Borrowed(_)));
        assert!(archive.contains("classes.dex"));
        assert!(!archive.contains("missing"));
        assert!(archive.read_entry("missing").is_err());

        let mut corrupted = bytes.clone();
        let start = {
            let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
            archive.by_index(0).unwrap().data_start().unwrap() as usize
        };

        corrupted[start] ^= 1;

        let mut archive = Zip::from_bytes(&corrupted, "APK").unwrap();
        assert!(archive.read_entry("classes.dex").is_err());
    }
}

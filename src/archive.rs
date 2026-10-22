use std::borrow::Cow;
use std::fs;
use std::path::Path;

use crate::zip::Zip;

#[derive(Debug)]
pub struct ApkArchive {
    pub(crate) bytes: Vec<u8>,
    pub(crate) label: String,
    pub(crate) nested: Vec<ApkArchive>,
}

impl ApkArchive {
    pub fn open(apk: &Path) -> Result<Self, String> {
        if !apk.is_file() {
            return Err(format!("input is not a file: {}", apk.display()));
        }

        let bytes = fs::read(apk).map_err(|error| format!("{}: {error}", apk.display()))?;

        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        Self::from_bytes_at(bytes, "")
    }

    fn from_bytes_at(bytes: Vec<u8>, label: &str) -> Result<Self, String> {
        let mut archive = Zip::from_bytes(&bytes, label)?;
        let mut nested = Vec::new();

        for name in archive.names()? {
            if Self::is_nested_archive(&name) {
                let nested_bytes = archive.read_entry(&name)?.into_owned();
                let nested_label = Self::join_label(label, &name);
                let prepared = Self::from_bytes_at(nested_bytes, &nested_label)?;

                nested.push(prepared);
            }
        }

        Ok(ApkArchive {
            bytes,
            label: label.to_owned(),
            nested,
        })
    }

    fn is_nested_archive(entry: &str) -> bool {
        entry.ends_with(".apk")
    }

    pub(crate) fn join_label(parent: &str, entry: &str) -> String {
        if parent.is_empty() {
            entry.to_owned()
        } else {
            format!("{parent}!{entry}")
        }
    }

    pub(crate) fn is_classes_dex(entry: &str) -> bool {
        let name = entry.rsplit('/').next().unwrap_or(entry);
        name == "classes.dex"
            || name
                .strip_prefix("classes")
                .and_then(|name| name.strip_suffix(".dex"))
                .is_some_and(|number| {
                    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                })
    }

    pub(crate) fn visit_dex<'a>(
        &'a self,
        selected: Option<&str>,
        visitor: &mut impl FnMut(&str, Cow<'a, [u8]>) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut archive = Zip::from_bytes(&self.bytes, &self.label)?;

        for name in archive.names()? {
            let location = Self::join_label(&self.label, &name);

            if Self::is_classes_dex(&name) && selected.is_none_or(|selected| selected == location) {
                let bytes = archive.read_entry(&name)?;

                visitor(&location, bytes)?;
            }
        }

        for nested in &self.nested {
            nested.visit_dex(selected, visitor)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ApkArchive;
    use ::zip::ZipWriter;
    use ::zip::write::SimpleFileOptions;
    use std::io::{Cursor, Write};

    #[test]
    fn follows_apks_beyond_three_nested_levels() {
        let mut bytes = ZipWriter::new(Cursor::new(Vec::new()))
            .finish()
            .unwrap()
            .into_inner();

        for _ in 0..4 {
            let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
            writer
                .start_file("inner.apk", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&bytes).unwrap();
            bytes = writer.finish().unwrap().into_inner();
        }

        let mut archive = ApkArchive::from_bytes(bytes).unwrap();
        for _ in 0..4 {
            assert_eq!(archive.nested.len(), 1);
            archive = archive.nested.pop().unwrap();
        }
        assert!(archive.nested.is_empty());
    }

    #[test]
    fn recognizes_dex_names() {
        assert!(ApkArchive::is_classes_dex("classes.dex"));
        assert!(ApkArchive::is_classes_dex("nested/classes12.dex"));
        assert!(!ApkArchive::is_classes_dex("other.dex"));
    }
}

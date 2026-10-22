use std::borrow::Cow;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use zip::{CompressionMethod, ZipArchive};

mod code;
mod decompile;
mod disassemble;
mod filter;
mod format;
pub mod mapping;
mod opcode;
mod parse;

use crate::java::{JavaField, JavaMethod, JavaType};
pub use decompile::{DecompiledClass, decompile_apk};
pub use disassemble::{
    DisassembledClass, DisassembledInstruction, DisassembledMethod, disassemble_apk,
};
use mapping::Mapping;

#[derive(Debug)]
pub struct PreparedArchive {
    pub(crate) bytes: Vec<u8>,
    pub(crate) label: String,
    pub(crate) nested: Vec<PreparedArchive>,
}

#[derive(Debug)]
pub struct DexIndex {
    pub classes: Vec<ClassLocation>,
    pub locations: Vec<MethodLocation>,
    pub fields: Vec<FieldLocation>,
}

pub struct ReferenceFilter<'a> {
    pub strings: &'a [String],
    pub calls: &'a [JavaMethod],
    pub types: &'a [JavaType],
    pub fields: &'a [JavaField],
    pub mapping: Option<&'a Mapping>,
}

#[derive(Debug)]
pub struct MethodLocation {
    pub dex: String,
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub source_file: Option<String>,
}

#[derive(Debug)]
pub struct ClassLocation {
    pub dex: String,
    pub class: String,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
}

#[derive(Debug)]
pub struct FieldLocation {
    pub dex: String,
    pub class: String,
    pub field: String,
    pub descriptor: String,
    pub source_file: Option<String>,
}

pub fn method_matches(
    query: &JavaMethod,
    class: &str,
    name: &str,
    descriptor: &str,
    mapping: Option<&Mapping>,
) -> bool {
    query.matches(class, name, descriptor)
        || mapping.is_some_and(|mapping| {
            mapping.original_class(class).is_some_and(|original| {
                mapping
                    .methods(class, name, descriptor)
                    .any(|alias| query.matches(original, alias.name, alias.descriptor))
            })
        })
}

pub fn index_apk(apk: &Path, filter: Option<&ReferenceFilter<'_>>) -> Result<DexIndex, String> {
    let prepared = prepare_apk(apk)?;
    index_prepared(&prepared, filter)
}

pub fn prepare_apk(apk: &Path) -> Result<PreparedArchive, String> {
    if !apk.is_file() {
        return Err(format!("input is not a file: {}", apk.display()));
    }

    let bytes = fs::read(apk).map_err(|error| format!("{}: {error}", apk.display()))?;

    prepare_archive(bytes)
}

pub fn prepare_archive(bytes: Vec<u8>) -> Result<PreparedArchive, String> {
    prepare_archive_at(bytes, "")
}

pub fn index_prepared(
    prepared: &PreparedArchive,
    filter: Option<&ReferenceFilter<'_>>,
) -> Result<DexIndex, String> {
    let mut index = DexIndex {
        classes: Vec::new(),
        locations: Vec::new(),
        fields: Vec::new(),
    };

    index_archive(prepared, filter, &mut index)?;

    Ok(index)
}

fn prepare_archive_at(bytes: Vec<u8>, label: &str) -> Result<PreparedArchive, String> {
    let mut archive = open_archive(&bytes, label)?;
    let mut nested = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("invalid ZIP entry in {label}: {error}"))?;
        let name = entry
            .name()
            .map_err(|error| format!("invalid ZIP entry name in {label}: {error}"))?
            .into_owned();

        if is_nested_archive(&name) {
            let nested_bytes = read_entry(&mut entry, &name, label)?;
            let nested_label = join_label(label, &name);
            let prepared = prepare_archive_at(nested_bytes, &nested_label)?;
            nested.push(prepared);
        }
    }

    Ok(PreparedArchive {
        bytes,
        label: label.to_owned(),
        nested,
    })
}

fn is_classes_dex(entry: &str) -> bool {
    let name = entry.rsplit('/').next().unwrap_or(entry);
    name == "classes.dex"
        || name
            .strip_prefix("classes")
            .and_then(|name| name.strip_suffix(".dex"))
            .is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn is_nested_archive(entry: &str) -> bool {
    entry.ends_with(".apk")
}

fn index_archive(
    prepared: &PreparedArchive,
    filter: Option<&ReferenceFilter<'_>>,
    index: &mut DexIndex,
) -> Result<(), String> {
    let mut archive = open_archive(&prepared.bytes, &prepared.label)?;

    for entry_index in 0..archive.len() {
        let mut entry = archive
            .by_index(entry_index)
            .map_err(|error| format!("invalid ZIP entry in {}: {error}", prepared.label))?;
        let name = entry
            .name()
            .map_err(|error| format!("invalid ZIP entry name in {}: {error}", prepared.label))?
            .into_owned();

        if is_classes_dex(&name) {
            let bytes = read_dex_entry(&prepared.bytes, &mut entry, &name, &prepared.label)?;
            parse::parse_dex(bytes, &join_label(&prepared.label, &name), filter, index)?;
        }
    }

    for nested in &prepared.nested {
        index_archive(nested, filter, index)?;
    }

    Ok(())
}

fn open_archive<'a>(bytes: &'a [u8], label: &str) -> Result<ZipArchive<Cursor<&'a [u8]>>, String> {
    ZipArchive::new(Cursor::new(bytes)).map_err(|error| {
        let label = if label.is_empty() { "input" } else { label };
        format!("invalid ZIP archive {label}: {error}")
    })
}

fn read_entry(reader: &mut impl Read, name: &str, archive: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {name} from {archive}: {error}"))?;

    Ok(bytes)
}

fn read_dex_entry<'a>(
    archive_bytes: &'a [u8],
    entry: &mut zip::read::ZipFile<'_, Cursor<&'a [u8]>>,
    name: &str,
    archive: &str,
) -> Result<Cow<'a, [u8]>, String> {
    let size = entry.size();

    if entry.compression() == CompressionMethod::Stored
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
            return Err(format!("ZIP entry {name} in {archive} has an invalid CRC"));
        }

        Ok(Cow::Borrowed(bytes))
    } else {
        read_entry(entry, name, archive).map(Cow::Owned)
    }
}

fn join_label(parent: &str, entry: &str) -> String {
    if parent.is_empty() {
        entry.to_owned()
    } else {
        format!("{parent}!{entry}")
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    use super::{
        code::CodeItem, code::CodeReferences, filter::ResolvedFilter, is_classes_dex,
        prepare_archive, read_dex_entry,
    };

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

        let mut archive = prepare_archive(bytes).unwrap();
        for _ in 0..4 {
            assert_eq!(archive.nested.len(), 1);
            archive = archive.nested.pop().unwrap();
        }
        assert!(archive.nested.is_empty());
    }

    #[test]
    fn borrows_stored_dex_and_owns_deflated_dex() {
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
        let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();

        for (index, borrowed) in [(0, true), (1, false)] {
            let mut entry = archive.by_index(index).unwrap();
            let data = read_dex_entry(&bytes, &mut entry, "classes.dex", "APK").unwrap();
            assert_eq!(data.as_ref(), b"dex\nexample");
            assert_eq!(matches!(data, Cow::Borrowed(_)), borrowed);
        }

        let mut corrupted = bytes.clone();
        let start = {
            let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
            archive.by_index(0).unwrap().data_start().unwrap() as usize
        };

        corrupted[start] ^= 1;

        let mut archive = ZipArchive::new(Cursor::new(corrupted.as_slice())).unwrap();
        let mut entry = archive.by_index(0).unwrap();
        assert!(read_dex_entry(&corrupted, &mut entry, "classes.dex", "APK").is_err());
    }

    #[test]
    fn recognizes_dex_names() {
        assert!(is_classes_dex("classes.dex"));
        assert!(is_classes_dex("nested/classes12.dex"));
        assert!(!is_classes_dex("other.dex"));
    }

    #[test]
    fn reads_invoke_targets_without_call_site_details() {
        let instructions: [u16; 13] = [0x006e, 7, 0, 0x0074, 7, 0, 0x00fa, 8, 0, 0, 0x00fc, 9, 0];
        let mut data = vec![0; 16];

        data[12..16].copy_from_slice(&(instructions.len() as u32).to_le_bytes());

        for instruction in instructions {
            data.extend_from_slice(&instruction.to_le_bytes());
        }

        assert_eq!(
            CodeItem::parse(&data, 0)
                .unwrap()
                .references()
                .unwrap()
                .methods,
            [(7, 0), (7, 3), (8, 6)]
        );
    }

    #[test]
    fn reads_type_field_and_string_references() {
        let instructions: [u16; 8] = [0x001c, 1, 0x0052, 2, 0x0062, 3, 0x001a, 4];
        let mut data = vec![0; 16];

        data[12..16].copy_from_slice(&(instructions.len() as u32).to_le_bytes());

        for instruction in instructions {
            data.extend_from_slice(&instruction.to_le_bytes());
        }

        let references = CodeItem::parse(&data, 0).unwrap().references().unwrap();
        assert_eq!(references.types, [(1, 0)]);
        assert_eq!(references.fields, [(2, 2), (3, 4)]);
        assert_eq!(references.static_fields, [(3, 4)]);
        assert_eq!(references.strings, [(4, 6)]);
    }

    #[test]
    fn combines_reference_filters_within_one_method() {
        let filter = ResolvedFilter {
            strings: vec![vec![false, true]],
            static_fields: vec![vec![false, false]],
            calls: vec![vec![true]],
            types: vec![vec![false, true]],
            fields: vec![vec![true]],
            string_count: 2,
            type_count: 2,
            field_count: 1,
            method_count: 1,
        };
        let mut refs = CodeReferences {
            strings: vec![(1, 0)],
            methods: vec![(0, 2)],
            types: vec![(1, 4)],
            fields: vec![(0, 6)],
            ..CodeReferences::default()
        };

        assert!(filter.matches(&refs));
        refs.methods.clear();
        assert!(!filter.matches(&refs));
        refs.methods.push((1, 2));
        assert!(filter.validate(&refs).is_err());
    }
}

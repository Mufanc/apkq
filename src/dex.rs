use std::path::Path;

use crate::archive::ApkArchive;

mod code;
mod decompile;
mod disassemble;
mod filter;
mod format;
pub mod mapping;
mod opcode;
mod parse;
pub mod query;

use crate::java::{JavaField, JavaMethod, JavaType};
pub use decompile::DecompiledClass;
pub use disassemble::{
    DisassembleTarget, DisassembledInstruction, DisassembledMethod, Disassembly, DisassemblyFormat,
};
use mapping::Mapping;

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

impl DexIndex {
    pub fn from_apk(apk: &Path, filter: Option<&ReferenceFilter<'_>>) -> Result<DexIndex, String> {
        let prepared = ApkArchive::open(apk)?;
        Self::from_archive(&prepared, filter, None)
    }

    pub fn from_archive(
        prepared: &ApkArchive,
        filter: Option<&ReferenceFilter<'_>>,
        selected: Option<&str>,
    ) -> Result<DexIndex, String> {
        let mut index = DexIndex {
            classes: Vec::new(),
            locations: Vec::new(),
            fields: Vec::new(),
        };

        prepared.visit_dex(selected, &mut |label, bytes| {
            parse::parse_dex(bytes, label, filter, &mut index)
        })?;

        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::{code::CodeItem, code::CodeReferences, filter::ResolvedFilter};

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

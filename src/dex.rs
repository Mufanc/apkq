use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use blake3::Hasher;
use zip::ZipArchive;

const MAX_ARCHIVE_DEPTH: usize = 3;
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub struct PreparedArchive {
    bytes: Vec<u8>,
    fingerprint: [u8; 32],
    label: String,
    nested: Vec<PreparedArchive>,
}

impl PreparedArchive {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

#[derive(Debug)]
pub struct DexIndex {
    pub classes: Vec<ClassLocation>,
    pub locations: Vec<MethodLocation>,
    pub fields: Vec<FieldLocation>,
    pub strings: Vec<IndexedString>,
    pub stats: DexStats,
}

#[derive(Debug)]
pub struct IndexedString {
    pub value: String,
    pub sites: Vec<StringSite>,
}

#[derive(Clone, Debug)]
pub struct StringSite {
    pub location_id: usize,
    pub pc: u32,
    pub kind: ReferenceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceKind {
    ConstString,
    StaticValue,
}

#[derive(Clone, Copy)]
pub struct StringSiteRef {
    pub location_id: usize,
    pub pc: u32,
    pub kind: ReferenceKind,
}

pub struct MethodLocationRef<'a> {
    pub dex: &'a str,
    pub class: &'a str,
    pub method: &'a str,
    pub descriptor: &'a str,
    pub source_file: Option<&'a str>,
}

pub struct ClassLocationRef<'a> {
    pub dex: &'a str,
    pub class: &'a str,
    pub source_file: Option<&'a str>,
}

pub struct FieldLocationRef<'a> {
    pub dex: &'a str,
    pub class: &'a str,
    pub field: &'a str,
    pub descriptor: &'a str,
    pub source_file: Option<&'a str>,
}

pub trait DexSource {
    fn stats(&self) -> DexStats;
    fn string_count(&self) -> usize;
    fn string_value(&self, index: usize) -> Result<&str, String>;
    fn string_site_count(&self, index: usize) -> Result<usize, String>;
    fn visit_string_sites(
        &self,
        index: usize,
        visit: &mut dyn FnMut(StringSiteRef),
    ) -> Result<(), String>;
    fn location(&self, index: usize) -> Result<MethodLocationRef<'_>, String>;
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

#[derive(Clone, Copy, Default, Debug)]
pub struct DexStats {
    pub archives: usize,
    pub dex_files: usize,
    pub strings: usize,
    pub methods_with_code: usize,
    pub referenced_strings: usize,
    pub const_string_references: usize,
    pub static_value_fields: usize,
    pub static_value_references: usize,
}

impl DexSource for DexIndex {
    fn stats(&self) -> DexStats {
        self.stats
    }

    fn string_count(&self) -> usize {
        self.strings.len()
    }

    fn string_value(&self, index: usize) -> Result<&str, String> {
        self.strings
            .get(index)
            .map(|string| string.value.as_str())
            .ok_or_else(|| format!("DEX string index out of bounds: {index}"))
    }

    fn string_site_count(&self, index: usize) -> Result<usize, String> {
        self.strings
            .get(index)
            .map(|string| string.sites.len())
            .ok_or_else(|| format!("DEX string index out of bounds: {index}"))
    }

    fn visit_string_sites(
        &self,
        index: usize,
        visit: &mut dyn FnMut(StringSiteRef),
    ) -> Result<(), String> {
        let string = self
            .strings
            .get(index)
            .ok_or_else(|| format!("DEX string index out of bounds: {index}"))?;
        for site in &string.sites {
            visit(StringSiteRef {
                location_id: site.location_id,
                pc: site.pc,
                kind: site.kind,
            });
        }
        Ok(())
    }

    fn location(&self, index: usize) -> Result<MethodLocationRef<'_>, String> {
        let location = self
            .locations
            .get(index)
            .ok_or_else(|| format!("DEX location index out of bounds: {index}"))?;
        Ok(MethodLocationRef {
            dex: &location.dex,
            class: &location.class,
            method: &location.method,
            descriptor: &location.descriptor,
            source_file: location.source_file.as_deref(),
        })
    }
}

pub fn index_apk(apk: &Path) -> Result<DexIndex, String> {
    let prepared = prepare_apk(apk)?;
    index_prepared(&prepared)
}

pub fn prepare_apk(apk: &Path) -> Result<PreparedArchive, String> {
    if !apk.is_file() {
        return Err(format!("APK does not exist: {}", apk.display()));
    }
    let bytes = fs::read(apk).map_err(|error| format!("{}: {error}", apk.display()))?;
    prepare_archive(bytes)
}

pub fn prepare_archive(bytes: Vec<u8>) -> Result<PreparedArchive, String> {
    prepare_archive_at(bytes, "", 0)
}

pub fn index_prepared(prepared: &PreparedArchive) -> Result<DexIndex, String> {
    let mut index = DexIndex {
        classes: Vec::new(),
        locations: Vec::new(),
        fields: Vec::new(),
        strings: Vec::new(),
        stats: DexStats::default(),
    };
    index_archive(prepared, &mut index)?;
    Ok(index)
}

fn prepare_archive_at(
    bytes: Vec<u8>,
    label: &str,
    depth: usize,
) -> Result<PreparedArchive, String> {
    let mut archive = open_archive(&bytes, label)?;
    let mut parts = Vec::new();
    let mut nested = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("invalid ZIP entry in {label}: {error}"))?;
        let name = entry.name().to_owned();
        if is_classes_dex(&name) {
            parts.push((name, 0u8, entry.crc32(), entry.size(), None));
        } else if depth < MAX_ARCHIVE_DEPTH && is_nested_archive(&name) {
            let entry_size = entry.size();
            let nested_bytes = read_entry(&mut entry, &name, entry_size, label)?;
            let nested_label = join_label(label, &name);
            let prepared = prepare_archive_at(nested_bytes, &nested_label, depth + 1)?;
            parts.push((name, 1u8, 0, 0, Some(prepared.fingerprint)));
            nested.push(prepared);
        }
    }

    parts.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Hasher::new();
    hasher.update(b"dexq-dex-tree-v1\0");
    for (name, kind, crc32, size, nested_fingerprint) in parts {
        hasher.update(&[kind]);
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&crc32.to_le_bytes());
        hasher.update(&size.to_le_bytes());
        if let Some(fingerprint) = nested_fingerprint {
            hasher.update(&fingerprint);
        }
    }
    Ok(PreparedArchive {
        bytes,
        fingerprint: *hasher.finalize().as_bytes(),
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

fn index_archive(prepared: &PreparedArchive, index: &mut DexIndex) -> Result<(), String> {
    index.stats.archives += 1;
    let mut archive = open_archive(&prepared.bytes, &prepared.label)?;
    for entry_index in 0..archive.len() {
        let mut entry = archive
            .by_index(entry_index)
            .map_err(|error| format!("invalid ZIP entry in {}: {error}", prepared.label))?;
        if is_classes_dex(entry.name()) {
            let name = entry.name().to_owned();
            let size = entry.size();
            let bytes = read_entry(&mut entry, &name, size, &prepared.label)?;
            parse_dex(&bytes, &join_label(&prepared.label, &name), index)?;
        }
    }
    for nested in &prepared.nested {
        index_archive(nested, index)?;
    }
    Ok(())
}

fn open_archive<'a>(bytes: &'a [u8], label: &str) -> Result<ZipArchive<Cursor<&'a [u8]>>, String> {
    ZipArchive::new(Cursor::new(bytes)).map_err(|error| {
        let label = if label.is_empty() { "APK" } else { label };
        format!("invalid ZIP archive {label}: {error}")
    })
}

fn read_entry(
    reader: &mut impl Read,
    name: &str,
    size: u64,
    archive: &str,
) -> Result<Vec<u8>, String> {
    if size > MAX_ENTRY_BYTES {
        return Err(format!(
            "ZIP entry {name} in {archive} is too large: {size} bytes"
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {name} from {archive}: {error}"))?;
    Ok(bytes)
}

fn join_label(parent: &str, entry: &str) -> String {
    if parent.is_empty() {
        entry.to_owned()
    } else {
        format!("{parent}!{entry}")
    }
}

fn parse_dex(data: &[u8], label: &str, index: &mut DexIndex) -> Result<(), String> {
    if data.len() < 0x70 || &data[..4] != b"dex\n" {
        return Err(format!("unsupported or truncated DEX: {label}"));
    }

    let string_ids_size = u32_at(data, 0x38)? as usize;
    let string_ids_off = u32_at(data, 0x3c)? as usize;
    let type_ids_size = u32_at(data, 0x40)? as usize;
    let type_ids_off = u32_at(data, 0x44)? as usize;
    let proto_ids_size = u32_at(data, 0x48)? as usize;
    let proto_ids_off = u32_at(data, 0x4c)? as usize;
    let field_ids_size = u32_at(data, 0x50)? as usize;
    let field_ids_off = u32_at(data, 0x54)? as usize;
    let method_ids_size = u32_at(data, 0x58)? as usize;
    let method_ids_off = u32_at(data, 0x5c)? as usize;
    let class_defs_size = u32_at(data, 0x60)? as usize;
    let class_defs_off = u32_at(data, 0x64)? as usize;

    check_table(data, string_ids_off, string_ids_size, 4)?;
    check_table(data, type_ids_off, type_ids_size, 4)?;
    check_table(data, proto_ids_off, proto_ids_size, 12)?;
    check_table(data, field_ids_off, field_ids_size, 8)?;
    check_table(data, method_ids_off, method_ids_size, 8)?;
    check_table(data, class_defs_off, class_defs_size, 32)?;

    let strings = (0..string_ids_size)
        .map(|index| {
            let offset = u32_at(data, string_ids_off + index * 4)? as usize;
            read_mutf8(data, offset)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let types = (0..type_ids_size)
        .map(|index| u32_at(data, type_ids_off + index * 4).map(|value| value as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let protos = (0..proto_ids_size)
        .map(|index| parse_proto(data, proto_ids_off + index * 12, &types, &strings))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = (0..field_ids_size)
        .map(|index| {
            let offset = field_ids_off + index * 8;
            let class_idx = u16_at(data, offset)? as usize;
            let type_idx = u16_at(data, offset + 2)? as usize;
            let name_idx = u32_at(data, offset + 4)? as usize;
            Ok(FieldId {
                class: string_for_type(&types, &strings, class_idx)?.to_owned(),
                name: strings
                    .get(name_idx)
                    .ok_or_else(|| format!("bad field name index in {label}"))?
                    .to_owned(),
                descriptor: string_for_type(&types, &strings, type_idx)?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let methods = (0..method_ids_size)
        .map(|index| {
            let offset = method_ids_off + index * 8;
            let class_idx = u16_at(data, offset)? as usize;
            let proto_idx = u16_at(data, offset + 2)? as usize;
            let name_idx = u32_at(data, offset + 4)? as usize;
            Ok(MethodId {
                class: string_for_type(&types, &strings, class_idx)?.to_owned(),
                name: strings
                    .get(name_idx)
                    .ok_or_else(|| format!("bad method name index in {label}"))?
                    .to_owned(),
                descriptor: protos
                    .get(proto_idx)
                    .ok_or_else(|| format!("bad proto index in {label}"))?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut static_strings_by_field = vec![None; field_ids_size];
    for class_index in 0..class_defs_size {
        let offset = class_defs_off + class_index * 32;
        let class_data_off = u32_at(data, offset + 24)? as usize;
        let static_values_off = u32_at(data, offset + 28)? as usize;
        if class_data_off != 0 && static_values_off != 0 {
            let static_fields = read_static_fields(data, class_data_off)?;
            index.stats.static_value_fields += read_static_string_values(
                data,
                static_values_off,
                &static_fields,
                &mut static_strings_by_field,
            )?;
        }
    }

    let mut sites_by_string = vec![Vec::new(); strings.len()];
    for class_index in 0..class_defs_size {
        let offset = class_defs_off + class_index * 32;
        let class_idx = u32_at(data, offset)? as usize;
        let source_idx = u32_at(data, offset + 16)?;
        let class_data_off = u32_at(data, offset + 24)? as usize;
        let class = string_for_type(&types, &strings, class_idx)?.to_owned();
        let source_file = (source_idx != u32::MAX)
            .then(|| strings.get(source_idx as usize).cloned())
            .flatten();
        index.classes.push(ClassLocation {
            dex: label.to_owned(),
            class: class.clone(),
            source_file: source_file.clone(),
        });
        if class_data_off == 0 {
            continue;
        }
        parse_class_data(
            data,
            class_data_off,
            label,
            &class,
            source_file.as_deref(),
            &fields,
            &methods,
            &static_strings_by_field,
            &mut sites_by_string,
            index,
        )?;
    }

    index.stats.dex_files += 1;
    index.stats.strings += strings.len();
    for (value, sites) in strings.into_iter().zip(sites_by_string) {
        if !sites.is_empty() {
            index.stats.referenced_strings += 1;
            index.strings.push(IndexedString { value, sites });
        }
    }
    Ok(())
}

struct MethodId {
    class: String,
    name: String,
    descriptor: String,
}

struct FieldId {
    class: String,
    name: String,
    descriptor: String,
}

#[allow(clippy::too_many_arguments)]
fn parse_class_data(
    data: &[u8],
    offset: usize,
    label: &str,
    class: &str,
    source_file: Option<&str>,
    fields: &[FieldId],
    methods: &[MethodId],
    static_strings_by_field: &[Option<usize>],
    sites_by_string: &mut [Vec<StringSite>],
    index: &mut DexIndex,
) -> Result<(), String> {
    let mut cursor = offset;
    let static_fields = read_uleb128(data, &mut cursor)?;
    let instance_fields = read_uleb128(data, &mut cursor)?;
    let direct_methods = read_uleb128(data, &mut cursor)?;
    let virtual_methods = read_uleb128(data, &mut cursor)?;

    for field_count in [static_fields, instance_fields] {
        let mut field_idx = 0usize;
        for _ in 0..field_count {
            field_idx = field_idx
                .checked_add(read_uleb128(data, &mut cursor)? as usize)
                .ok_or("field index overflow")?;
            read_uleb128(data, &mut cursor)?;
            let field = fields
                .get(field_idx)
                .ok_or_else(|| format!("bad encoded field index in {label}"))?;
            index.fields.push(FieldLocation {
                dex: label.to_owned(),
                class: if field.class == class {
                    class.to_owned()
                } else {
                    field.class.clone()
                },
                field: field.name.clone(),
                descriptor: field.descriptor.clone(),
                source_file: source_file.map(str::to_owned),
            });
        }
    }
    for method_count in [direct_methods, virtual_methods] {
        let mut method_idx = 0usize;
        for _ in 0..method_count {
            method_idx = method_idx
                .checked_add(read_uleb128(data, &mut cursor)? as usize)
                .ok_or("method index overflow")?;
            read_uleb128(data, &mut cursor)?;
            let code_off = read_uleb128(data, &mut cursor)? as usize;
            let method = methods
                .get(method_idx)
                .ok_or_else(|| format!("bad encoded method index in {label}"))?;
            let location_id = index.locations.len();
            index.locations.push(MethodLocation {
                dex: label.to_owned(),
                class: if method.class == class {
                    class.to_owned()
                } else {
                    method.class.clone()
                },
                method: method.name.clone(),
                descriptor: method.descriptor.clone(),
                source_file: source_file.map(str::to_owned),
            });
            if code_off == 0 {
                continue;
            }
            index.stats.methods_with_code += 1;
            let references = parse_code_item(data, code_off)?;
            let static_references = references
                .static_fields
                .iter()
                .filter_map(|&(field_idx, pc)| {
                    static_strings_by_field
                        .get(field_idx)
                        .copied()
                        .flatten()
                        .map(|string_idx| (string_idx, pc))
                })
                .collect::<Vec<_>>();
            for (string_idx, pc) in references.strings {
                let sites = sites_by_string
                    .get_mut(string_idx)
                    .ok_or_else(|| format!("bad const-string index in {label}"))?;
                sites.push(StringSite {
                    location_id,
                    pc,
                    kind: ReferenceKind::ConstString,
                });
                index.stats.const_string_references += 1;
            }
            for (string_idx, pc) in static_references {
                let sites = sites_by_string
                    .get_mut(string_idx)
                    .ok_or_else(|| format!("bad static string index in {label}"))?;
                sites.push(StringSite {
                    location_id,
                    pc,
                    kind: ReferenceKind::StaticValue,
                });
                index.stats.static_value_references += 1;
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct CodeReferences {
    strings: Vec<(usize, u32)>,
    static_fields: Vec<(usize, u32)>,
}

fn parse_code_item(data: &[u8], offset: usize) -> Result<CodeReferences, String> {
    let insns_size = u32_at(data, offset + 12)? as usize;
    let insns_off = offset + 16;
    check_table(data, insns_off, insns_size, 2)?;
    let mut references = CodeReferences::default();
    let mut pc = 0usize;

    while pc < insns_size {
        let instruction = u16_at(data, insns_off + pc * 2)?;
        let opcode = instruction as u8;
        if opcode == 0x1a {
            references
                .strings
                .push((u16_at(data, insns_off + (pc + 1) * 2)? as usize, pc as u32));
        } else if opcode == 0x1b {
            let low = u16_at(data, insns_off + (pc + 1) * 2)? as u32;
            let high = u16_at(data, insns_off + (pc + 2) * 2)? as u32;
            references
                .strings
                .push((((high << 16) | low) as usize, pc as u32));
        } else if opcode == 0x62 {
            references
                .static_fields
                .push((u16_at(data, insns_off + (pc + 1) * 2)? as usize, pc as u32));
        }
        let width = instruction_width(data, insns_off, pc, insns_size)?;
        pc = pc.checked_add(width).ok_or("instruction offset overflow")?;
    }
    Ok(references)
}

fn read_static_fields(data: &[u8], offset: usize) -> Result<Vec<usize>, String> {
    let mut cursor = offset;
    let static_fields = read_uleb128(data, &mut cursor)? as usize;
    read_uleb128(data, &mut cursor)?;
    read_uleb128(data, &mut cursor)?;
    read_uleb128(data, &mut cursor)?;
    let mut field_idx = 0usize;
    let mut fields = Vec::with_capacity(static_fields);
    for _ in 0..static_fields {
        field_idx = field_idx
            .checked_add(read_uleb128(data, &mut cursor)? as usize)
            .ok_or("field index overflow")?;
        read_uleb128(data, &mut cursor)?;
        fields.push(field_idx);
    }
    Ok(fields)
}

fn read_static_string_values(
    data: &[u8],
    offset: usize,
    static_fields: &[usize],
    strings_by_field: &mut [Option<usize>],
) -> Result<usize, String> {
    let mut cursor = offset;
    let value_count = read_uleb128(data, &mut cursor)? as usize;
    if value_count > static_fields.len() {
        return Err("static_values has more values than static fields".to_owned());
    }
    let mut found = 0;
    for &field_idx in static_fields.iter().take(value_count) {
        if let Some(string_idx) = read_encoded_value(data, &mut cursor)? {
            let value = strings_by_field
                .get_mut(field_idx)
                .ok_or("static field index is out of bounds")?;
            *value = Some(string_idx);
            found += 1;
        }
    }
    Ok(found)
}

fn read_encoded_value(data: &[u8], cursor: &mut usize) -> Result<Option<usize>, String> {
    let header = *data.get(*cursor).ok_or("truncated encoded_value")?;
    *cursor += 1;
    let value_type = header & 0x1f;
    let byte_count = (header >> 5) as usize + 1;
    match value_type {
        0x17 => Ok(Some(
            read_little_endian_value(data, cursor, byte_count)? as usize
        )),
        0x1c => {
            let size = read_uleb128(data, cursor)?;
            for _ in 0..size {
                read_encoded_value(data, cursor)?;
            }
            Ok(None)
        }
        0x1d => {
            read_uleb128(data, cursor)?;
            let size = read_uleb128(data, cursor)?;
            for _ in 0..size {
                read_uleb128(data, cursor)?;
                read_encoded_value(data, cursor)?;
            }
            Ok(None)
        }
        0x1e | 0x1f => Ok(None),
        0x00..=0x06 | 0x10 | 0x11 | 0x15 | 0x16 | 0x18 | 0x19 | 0x1a | 0x1b => {
            read_little_endian_value(data, cursor, byte_count)?;
            Ok(None)
        }
        _ => Err(format!("unknown encoded_value type 0x{value_type:02x}")),
    }
}

fn read_little_endian_value(
    data: &[u8],
    cursor: &mut usize,
    byte_count: usize,
) -> Result<u64, String> {
    if byte_count > 8 {
        return Err("encoded_value is too wide".to_owned());
    }
    let bytes = data
        .get(*cursor..*cursor + byte_count)
        .ok_or("truncated encoded_value payload")?;
    *cursor += byte_count;
    Ok(bytes.iter().enumerate().fold(0u64, |value, (shift, byte)| {
        value | (*byte as u64) << (shift * 8)
    }))
}

fn instruction_width(
    data: &[u8],
    insns_off: usize,
    pc: usize,
    insns_size: usize,
) -> Result<usize, String> {
    let instruction = u16_at(data, insns_off + pc * 2)?;
    let opcode = instruction as u8;
    let width = if opcode == 0 {
        match instruction >> 8 {
            0 => 1,
            1 => 4 + u16_at(data, insns_off + (pc + 1) * 2)? as usize * 2,
            2 => 2 + u16_at(data, insns_off + (pc + 1) * 2)? as usize * 4,
            3 => {
                let element_width = u16_at(data, insns_off + (pc + 1) * 2)? as usize;
                let low = u16_at(data, insns_off + (pc + 2) * 2)? as u32;
                let high = u16_at(data, insns_off + (pc + 3) * 2)? as u32;
                4 + (element_width * ((high << 16) | low) as usize).div_ceil(2)
            }
            ident => return Err(format!("unknown DEX payload 0x{ident:02x}")),
        }
    } else {
        match opcode {
            0x01
            | 0x04
            | 0x07
            | 0x0a..=0x12
            | 0x1d
            | 0x1e
            | 0x21
            | 0x27
            | 0x28
            | 0x7b..=0x8f
            | 0xb0..=0xcf => 1,
            0x02
            | 0x05
            | 0x08
            | 0x13
            | 0x15
            | 0x16
            | 0x19
            | 0x1a
            | 0x1c
            | 0x1f
            | 0x20
            | 0x22
            | 0x23
            | 0x29
            | 0x2d..=0x3d
            | 0x44..=0x6d
            | 0x90..=0xaf
            | 0xd0..=0xe2
            | 0xfe
            | 0xff => 2,
            0x03
            | 0x06
            | 0x09
            | 0x14
            | 0x17
            | 0x1b
            | 0x24..=0x26
            | 0x2a..=0x2c
            | 0x6e..=0x72
            | 0x74..=0x78
            | 0xfc
            | 0xfd => 3,
            0x18 => 5,
            0xfa | 0xfb => 4,
            _ => return Err(format!("unknown DEX opcode 0x{opcode:02x}")),
        }
    };
    if pc + width > insns_size {
        return Err("DEX instruction extends beyond code_item".to_owned());
    }
    Ok(width)
}

fn parse_proto(
    data: &[u8],
    offset: usize,
    types: &[usize],
    strings: &[String],
) -> Result<String, String> {
    let return_type = u32_at(data, offset + 4)? as usize;
    let parameters_off = u32_at(data, offset + 8)? as usize;
    let mut descriptor = "(".to_owned();
    if parameters_off != 0 {
        let size = u32_at(data, parameters_off)? as usize;
        check_table(data, parameters_off + 4, size, 2)?;
        for index in 0..size {
            let type_idx = u16_at(data, parameters_off + 4 + index * 2)? as usize;
            descriptor.push_str(string_for_type(types, strings, type_idx)?);
        }
    }
    descriptor.push(')');
    descriptor.push_str(string_for_type(types, strings, return_type)?);
    Ok(descriptor)
}

fn string_for_type<'a>(
    types: &[usize],
    strings: &'a [String],
    type_idx: usize,
) -> Result<&'a str, String> {
    let string_idx = *types
        .get(type_idx)
        .ok_or_else(|| format!("bad type index {type_idx}"))?;
    strings
        .get(string_idx)
        .map(String::as_str)
        .ok_or_else(|| format!("bad descriptor string index {string_idx}"))
}

fn read_mutf8(data: &[u8], offset: usize) -> Result<String, String> {
    let mut cursor = offset;
    read_uleb128(data, &mut cursor)?;
    let mut utf16 = Vec::new();
    loop {
        let first = *data.get(cursor).ok_or("unterminated MUTF-8 string")?;
        cursor += 1;
        if first == 0 {
            break;
        }
        let code = if first & 0x80 == 0 {
            first as u16
        } else if first & 0xe0 == 0xc0 {
            let second = *data.get(cursor).ok_or("truncated MUTF-8 sequence")?;
            cursor += 1;
            (((first & 0x1f) as u16) << 6) | (second & 0x3f) as u16
        } else if first & 0xf0 == 0xe0 {
            let second = *data.get(cursor).ok_or("truncated MUTF-8 sequence")?;
            let third = *data.get(cursor + 1).ok_or("truncated MUTF-8 sequence")?;
            cursor += 2;
            (((first & 0x0f) as u16) << 12)
                | (((second & 0x3f) as u16) << 6)
                | (third & 0x3f) as u16
        } else {
            return Err("invalid MUTF-8 lead byte".to_owned());
        };
        utf16.push(code);
    }
    Ok(String::from_utf16_lossy(&utf16))
}

fn read_uleb128(data: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *data.get(*cursor).ok_or("truncated ULEB128")?;
        *cursor += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("ULEB128 is too large".to_owned())
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or("read beyond DEX boundary")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or("read beyond DEX boundary")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn check_table(data: &[u8], offset: usize, count: usize, width: usize) -> Result<(), String> {
    let length = count.checked_mul(width).ok_or("DEX table size overflow")?;
    data.get(
        offset
            ..offset
                .checked_add(length)
                .ok_or("DEX table offset overflow")?,
    )
    .ok_or("DEX table extends beyond file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::{is_classes_dex, prepare_archive, read_mutf8, read_static_string_values};

    #[test]
    fn recognizes_dex_names_and_mutf8() {
        assert!(is_classes_dex("classes.dex"));
        assert!(is_classes_dex("nested/classes12.dex"));
        assert!(!is_classes_dex("other.dex"));
        assert_eq!(
            read_mutf8(&[3, b'a', 0xc0, 0x80, b'b', 0], 0).unwrap(),
            "a\0b"
        );
    }

    #[test]
    fn maps_static_value_strings_to_fields() {
        let data = [3, 0x04, 7, 0x17, 2, 0x1e];
        let mut strings_by_field = vec![None; 10];
        assert_eq!(
            read_static_string_values(&data, 0, &[5, 7, 9], &mut strings_by_field).unwrap(),
            1
        );
        assert_eq!(strings_by_field[7], Some(2));
    }

    #[test]
    fn fingerprint_ignores_resources_in_nested_apks() {
        let nested_a = test_archive(&[
            ("classes.dex", b"same dex"),
            ("res/raw/value", b"resource a"),
        ]);
        let nested_b = test_archive(&[
            ("classes.dex", b"same dex"),
            ("res/raw/value", b"resource b changed"),
        ]);
        let outer_a = test_archive(&[
            ("classes.dex", b"outer dex"),
            ("assets/inner.apk", &nested_a),
        ]);
        let outer_b = test_archive(&[
            ("classes.dex", b"outer dex"),
            ("assets/inner.apk", &nested_b),
        ]);

        assert_eq!(
            prepare_archive(outer_a).unwrap().fingerprint(),
            prepare_archive(outer_b).unwrap().fingerprint()
        );
    }

    fn test_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for &(name, bytes) in entries {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
}

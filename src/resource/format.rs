use std::fmt::Write;

pub(super) use crate::binary::ByteView;
use crate::binary::Cursor;

const CHUNK_HEADER_SIZE: usize = 8;
const STRING_POOL_HEADER_SIZE: usize = 28;
const PACKAGE_HEADER_SIZE: usize = 284;
const TYPE_HEADER_SIZE: usize = 24;
const ENTRY_HEADER_SIZE: usize = 8;
const COMPLEX_ENTRY_HEADER_SIZE: usize = 16;
const MAP_ENTRY_SIZE: usize = 12;
const NO_ENTRY: u32 = u32::MAX;
const UTF8_FLAG: u32 = 0x100;
#[derive(Clone, Copy, Eq, PartialEq)]
enum ArscChunkKind {
    StringPool,
    Table,
    Package,
    Type,
    Other(u16),
}

impl From<u16> for ArscChunkKind {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => Self::StringPool,
            0x0002 => Self::Table,
            0x0200 => Self::Package,
            0x0201 => Self::Type,
            value => Self::Other(value),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum XmlChunkKind {
    StringPool,
    Xml,
    StartElement,
    EndElement,
    Other(u16),
}

impl From<u16> for XmlChunkKind {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => Self::StringPool,
            0x0003 => Self::Xml,
            0x0102 => Self::StartElement,
            0x0103 => Self::EndElement,
            value => Self::Other(value),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Chunk {
    pub(super) start: usize,
    pub(super) header_size: usize,
    pub(super) end: usize,
    raw_type: u16,
}

impl Chunk {
    pub(super) fn parse(bytes: &[u8], start: usize, limit: usize) -> Result<Self, String> {
        let view = ByteView::bounded(bytes, limit.min(bytes.len()));
        let raw_type = view.u16(start)?;
        let header_size = view.u16(start + 2)? as usize;
        let size = view.u32(start + 4)? as usize;
        let end = start
            .checked_add(size)
            .ok_or("resource chunk size overflow")?;

        if header_size < CHUNK_HEADER_SIZE || size < header_size || end > limit || end > bytes.len()
        {
            return Err("invalid resource chunk bounds".to_owned());
        }

        Ok(Self {
            start,
            header_size,
            end,
            raw_type,
        })
    }

    pub(super) fn body(self) -> usize {
        self.start + self.header_size
    }

    pub(super) fn view<'a>(self, bytes: &'a [u8]) -> ByteView<'a> {
        ByteView::bounded(bytes, self.end)
    }

    fn arsc_kind(self) -> ArscChunkKind {
        self.raw_type.into()
    }

    pub(super) fn xml_kind(self) -> XmlChunkKind {
        self.raw_type.into()
    }
}

pub(super) struct Resource {
    pub(super) id: u32,
    pub(super) package: String,
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) config: String,
    pub(super) value: String,
    pub(super) path: Option<String>,
    pub(super) references: Vec<(String, u32)>,
}

pub(super) struct StringPool {
    values: Vec<String>,
}

impl StringPool {
    fn read_utf8_length(cursor: &mut Cursor<'_>) -> Result<usize, String> {
        let first = cursor.read_u8()?;

        if first & 0x80 == 0 {
            return Ok(first as usize);
        }

        Ok((((first & 0x7f) as usize) << 8) | cursor.read_u8()? as usize)
    }

    fn read_utf16_length(cursor: &mut Cursor<'_>) -> Result<usize, String> {
        let first = cursor.read_u16()?;

        if first & 0x8000 == 0 {
            return Ok(first as usize);
        }

        Ok((((first & 0x7fff) as usize) << 16) | cursor.read_u16()? as usize)
    }

    pub(super) fn parse(bytes: &[u8], pool: Chunk) -> Result<Self, String> {
        if pool.header_size < STRING_POOL_HEADER_SIZE {
            return Err("invalid resource string pool".to_owned());
        }

        let view = pool.view(bytes);
        let count = view.u32(pool.start + 8)? as usize;
        let style_count = view.u32(pool.start + 12)? as usize;
        let flags = view.u32(pool.start + 16)?;
        let data_start = view.u32(pool.start + 20)? as usize;
        let offsets_start = pool.body();
        let offset_bytes = count
            .checked_add(style_count)
            .and_then(|count| count.checked_mul(4))
            .ok_or("resource string pool size overflow")?;
        view.slice(offsets_start, offset_bytes)?;
        let mut values = Vec::with_capacity(count);

        for index in 0..count {
            let offset = view.u32(offsets_start + index * 4)? as usize;
            let start = pool
                .start
                .checked_add(data_start)
                .and_then(|start| start.checked_add(offset))
                .ok_or("resource string offset overflow")?;
            let mut cursor = Cursor::from_view(view, start)?;

            if flags & UTF8_FLAG != 0 {
                Self::read_utf8_length(&mut cursor)?;
                let len = Self::read_utf8_length(&mut cursor)?;
                let value = std::str::from_utf8(cursor.read_bytes(len)?)
                    .map_err(|error| format!("invalid resource UTF-8: {error}"))?
                    .to_owned();

                if cursor.read_u8()? != 0 {
                    return Err("resource UTF-8 string lacks terminator".to_owned());
                }

                values.push(value);
            } else {
                let len = Self::read_utf16_length(&mut cursor)?;
                let raw = cursor.read_bytes(
                    len.checked_mul(2)
                        .ok_or("resource UTF-16 length overflow")?,
                )?;
                let units = raw
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>();

                if cursor.read_u16()? != 0 {
                    return Err("resource UTF-16 string lacks terminator".to_owned());
                }

                values.push(
                    String::from_utf16(&units)
                        .map_err(|error| format!("invalid resource UTF-16: {error}"))?,
                );
            }
        }

        Ok(Self { values })
    }

    pub(super) fn into_values(self) -> Vec<String> {
        self.values
    }
}

fn strings(bytes: &[u8], pool: Chunk) -> Result<Vec<String>, String> {
    if pool.arsc_kind() != ArscChunkKind::StringPool {
        return Err("invalid resource table string pool".to_owned());
    }

    StringPool::parse(bytes, pool).map(StringPool::into_values)
}

fn pool_at(bytes: &[u8], package: Chunk, relative: usize) -> Result<Vec<String>, String> {
    let start = package
        .start
        .checked_add(relative)
        .ok_or("resource package offset overflow")?;

    strings(bytes, Chunk::parse(bytes, start, package.end)?)
}

fn name_at(pool: &[String], index: usize) -> Result<&str, String> {
    pool.get(index)
        .map(String::as_str)
        .ok_or("resource string index is out of bounds".to_owned())
}

fn package_name(bytes: &[u8], package: Chunk) -> Result<String, String> {
    let raw = ByteView::bounded(bytes, package.body()).slice(package.start + 12, 256)?;
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();

    String::from_utf16(&units).map_err(|error| format!("invalid resource package name: {error}"))
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ValueKind {
    Null,
    Reference,
    Attribute,
    String,
    DynamicReference,
    DynamicAttribute,
    Integer,
    Boolean,
    Other(u8),
}

impl From<u8> for ValueKind {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Null,
            0x01 => Self::Reference,
            0x02 => Self::Attribute,
            0x03 => Self::String,
            0x07 => Self::DynamicReference,
            0x08 => Self::DynamicAttribute,
            0x10 => Self::Integer,
            0x12 => Self::Boolean,
            value => Self::Other(value),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct TypedValue {
    pub(super) kind: ValueKind,
    pub(super) data: u32,
}

impl TypedValue {
    pub(super) fn parse(view: ByteView<'_>, offset: usize) -> Result<Self, String> {
        let size = view.u16(offset)? as usize;

        if size < 8 {
            return Err("invalid resource value size".to_owned());
        }

        view.slice(offset, size)?;

        Ok(Self {
            kind: ValueKind::from(view.u8(offset + 3)?),
            data: view.u32(offset + 4)?,
        })
    }

    fn display(self, pool: &[String]) -> Result<(String, Option<u32>), String> {
        match self.kind {
            ValueKind::String => Ok((name_at(pool, self.data as usize)?.to_owned(), None)),
            ValueKind::Reference | ValueKind::DynamicReference => {
                Ok((format!("@0x{:08x}", self.data), Some(self.data)))
            }
            ValueKind::Attribute | ValueKind::DynamicAttribute => {
                Ok((format!("?0x{:08x}", self.data), Some(self.data)))
            }
            ValueKind::Integer => Ok(((self.data as i32).to_string(), None)),
            ValueKind::Boolean => Ok(((self.data != 0).to_string(), None)),
            ValueKind::Null => Ok((String::new(), None)),
            ValueKind::Other(_) => Ok((format!("0x{:08x}", self.data), None)),
        }
    }
}

struct Configuration<'a> {
    bytes: &'a [u8],
}

impl<'a> Configuration<'a> {
    fn parse(bytes: &'a [u8], ty: Chunk) -> Result<Self, String> {
        let offset = ty.start + 20;
        let view = ByteView::bounded(bytes, ty.body());
        let size = view.u32(offset)? as usize;

        if size < 4 {
            return Err("invalid resource configuration".to_owned());
        }

        Ok(Self {
            bytes: view.slice(offset, size)?,
        })
    }

    fn label(&self) -> String {
        let raw = self.bytes;

        if raw[4..].iter().all(|byte| *byte == 0) {
            return "default".to_owned();
        }

        let mut result = String::new();

        if raw.len() >= 12 && raw[8] != 0 && raw[9] != 0 {
            if raw[8].is_ascii_alphabetic() && raw[9].is_ascii_alphabetic() {
                result.push(raw[8] as char);
                result.push(raw[9] as char);
            }

            if raw[10].is_ascii_alphabetic() && raw[11].is_ascii_alphabetic() {
                result.push_str("-r");
                result.push(raw[10] as char);
                result.push(raw[11] as char);
            }
        }

        if raw.len() >= 28 {
            let density = u16::from_le_bytes([raw[14], raw[15]]);
            if density != 0 {
                let _ = write!(result, "-{}dpi", density);
            }
            let sdk = u16::from_le_bytes([raw[24], raw[25]]);
            if sdk != 0 {
                let _ = write!(result, "-v{sdk}");
            }
        }

        if result.is_empty() {
            result.push_str("other");
        }

        // Keep qualifiers we do not decode distinct in the output.
        result.push(':');

        for byte in &raw[4..] {
            let _ = write!(result, "{byte:02x}");
        }

        result
    }
}

#[derive(Clone, Copy)]
struct TypeFlags(u8);

impl TypeFlags {
    const SPARSE: u8 = 0x01;
    const OFFSET16: u8 = 0x02;

    fn sparse(self) -> bool {
        self.0 & Self::SPARSE != 0
    }

    fn offset16(self) -> bool {
        !self.sparse() && self.0 & Self::OFFSET16 != 0
    }
}

struct TypeChunk {
    chunk: Chunk,
    id: u32,
    flags: TypeFlags,
    count: usize,
    entries: usize,
}

impl TypeChunk {
    fn parse(bytes: &[u8], chunk: Chunk) -> Result<Self, String> {
        if chunk.header_size < TYPE_HEADER_SIZE {
            return Err("invalid resource type header".to_owned());
        }

        let view = chunk.view(bytes);
        let id = view.u8(chunk.start + 8)? as u32;

        if id == 0 {
            return Err("resource type ID is zero".to_owned());
        }

        let flags = TypeFlags(view.u8(chunk.start + 9)?);
        let count = view.u32(chunk.start + 12)? as usize;
        let entries = chunk
            .start
            .checked_add(view.u32(chunk.start + 16)? as usize)
            .ok_or("resource entry offset overflow")?;

        if entries > chunk.end {
            return Err("resource entry data exceeds chunk".to_owned());
        }

        let width = if flags.offset16() { 2 } else { 4 };

        view.slice(
            chunk.body(),
            count
                .checked_mul(width)
                .ok_or("resource entry count overflow")?,
        )?;

        Ok(Self {
            chunk,
            id,
            flags,
            count,
            entries,
        })
    }

    fn entry_offset(&self, bytes: &[u8], index: usize) -> Result<Option<(u32, usize)>, String> {
        let view = self.chunk.view(bytes);
        let offsets = self.chunk.body();

        let (id, relative) = if self.flags.sparse() {
            (
                view.u16(offsets + index * 4)? as u32,
                view.u16(offsets + index * 4 + 2)? as u32 * 4,
            )
        } else if self.flags.offset16() {
            let relative = view.u16(offsets + index * 2)?;
            if relative == u16::MAX {
                return Ok(None);
            }
            (index as u32, relative as u32 * 4)
        } else {
            let relative = view.u32(offsets + index * 4)?;
            if relative == NO_ENTRY {
                return Ok(None);
            }
            (index as u32, relative)
        };

        let offset = self
            .entries
            .checked_add(relative as usize)
            .ok_or("resource entry offset overflow")?;

        Ok(Some((id, offset)))
    }
}

struct Entry {
    size: usize,
    key_index: usize,
    complex_count: Option<usize>,
}

#[derive(Clone, Copy)]
struct EntryFlags(u16);

impl EntryFlags {
    const COMPLEX: u16 = 0x01;

    fn complex(self) -> bool {
        self.0 & Self::COMPLEX != 0
    }
}

impl Entry {
    fn parse(view: ByteView<'_>, offset: usize) -> Result<Self, String> {
        let size = view.u16(offset)? as usize;

        if size < ENTRY_HEADER_SIZE {
            return Err("invalid resource entry size".to_owned());
        }

        view.slice(offset, size)?;

        let complex = EntryFlags(view.u16(offset + 2)?).complex();

        if complex && size < COMPLEX_ENTRY_HEADER_SIZE {
            return Err("invalid complex resource entry".to_owned());
        }

        Ok(Self {
            size,
            key_index: view.u32(offset + 4)? as usize,
            complex_count: complex
                .then(|| view.u32(offset + 12).map(|value| value as usize))
                .transpose()?,
        })
    }
}

struct Package<'a> {
    id: u32,
    type_offset: u32,
    name: String,
    type_names: Vec<String>,
    key_names: Vec<String>,
    values: &'a [String],
}

fn parse_type(
    bytes: &[u8],
    ty: Chunk,
    package: &Package<'_>,
    output: &mut Vec<Resource>,
) -> Result<(), String> {
    let ty = TypeChunk::parse(bytes, ty)?;
    let view = ty.chunk.view(bytes);
    let config = Configuration::parse(bytes, ty.chunk)?.label();
    let kind = name_at(&package.type_names, ty.id as usize - 1)?.to_owned();

    for index in 0..ty.count {
        let Some((entry_id, offset)) = ty.entry_offset(bytes, index)? else {
            continue;
        };
        let entry = Entry::parse(view, offset)?;
        let name = name_at(&package.key_names, entry.key_index)?.to_owned();
        let id_type = ty
            .id
            .checked_add(package.type_offset)
            .ok_or("resource type ID overflow")?;

        if package.id > 255 || id_type > 255 || entry_id > 65535 {
            return Err("resource ID component is out of range".to_owned());
        }

        let id = (package.id << 24) | (id_type << 16) | entry_id;
        let mut references = Vec::new();
        let value = if let Some(count) = entry.complex_count {
            let mut values_out = Vec::new();
            let maps = offset + entry.size;
            view.slice(
                maps,
                count
                    .checked_mul(MAP_ENTRY_SIZE)
                    .ok_or("resource map count overflow")?,
            )?;
            for item in 0..count {
                let item_offset = maps + item * MAP_ENTRY_SIZE;
                let key = view.u32(item_offset)?;
                let (text, reference) =
                    TypedValue::parse(view, item_offset + 4)?.display(package.values)?;
                if let Some(reference) = reference {
                    references.push((format!("map:0x{key:08x}"), reference));
                }
                if !text.is_empty() {
                    values_out.push(text);
                }
            }
            values_out.join(" | ")
        } else {
            let (text, reference) =
                TypedValue::parse(view, offset + entry.size)?.display(package.values)?;
            if let Some(reference) = reference {
                references.push(("value".to_owned(), reference));
            }
            text
        };

        let path = value.starts_with("res/").then(|| value.clone());

        output.push(Resource {
            id,
            package: package.name.clone(),
            kind: kind.clone(),
            name,
            config: config.clone(),
            value,
            path,
            references,
        });
    }

    Ok(())
}

fn parse_package(
    bytes: &[u8],
    package: Chunk,
    values: &[String],
    output: &mut Vec<Resource>,
) -> Result<(), String> {
    if package.header_size < PACKAGE_HEADER_SIZE {
        return Err("invalid resource package header".to_owned());
    }

    let view = package.view(bytes);
    let parsed = Package {
        id: view.u32(package.start + 8)?,
        name: package_name(bytes, package)?,
        type_names: pool_at(bytes, package, view.u32(package.start + 268)? as usize)?,
        key_names: pool_at(bytes, package, view.u32(package.start + 276)? as usize)?,
        type_offset: if package.header_size >= 288 {
            view.u32(package.start + 284)?
        } else {
            0
        },
        values,
    };
    let mut cursor = package.body();

    while cursor < package.end {
        let child = Chunk::parse(bytes, cursor, package.end)?;
        if child.arsc_kind() == ArscChunkKind::Type {
            parse_type(bytes, child, &parsed, output)?;
        }
        cursor = child.end;
    }

    Ok(())
}

pub(super) fn parse(bytes: &[u8]) -> Result<Vec<Resource>, String> {
    let table = Chunk::parse(bytes, 0, bytes.len())?;

    if table.arsc_kind() != ArscChunkKind::Table || table.header_size < 12 {
        return Err("not an Android resource table".to_owned());
    }

    let mut cursor = table.body();
    let pool = Chunk::parse(bytes, cursor, table.end)?;
    let values = strings(bytes, pool)?;

    cursor = pool.end;

    let mut output = Vec::new();

    while cursor < table.end {
        let child = Chunk::parse(bytes, cursor, table.end)?;
        if child.arsc_kind() == ArscChunkKind::Package {
            parse_package(bytes, child, &values, &mut output)?;
        }
        cursor = child.end;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{Chunk, strings};

    #[test]
    fn decodes_android_utf8_string_pool() {
        let mut bytes = vec![1, 0, 28, 0, 39, 0, 0, 0];
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0x100u32.to_le_bytes());
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[2, 2, b'o', b'k', 0, 0, 0]);
        let pool = Chunk::parse(&bytes, 0, bytes.len()).unwrap();
        assert_eq!(strings(&bytes, pool).unwrap(), ["ok"]);
    }
}

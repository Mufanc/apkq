use std::borrow::Cow;

use crate::binary::{ByteView, Cursor};

const HEADER_SIZE: usize = 0x70;
const HEADER_FIELDS_OFFSET: usize = 0x20;
const LINK_AND_MAP_FIELDS_SIZE: usize = 12;
const ENDIAN_TAG: u32 = 0x1234_5678;
const NO_INDEX: u32 = u32::MAX;

const STRING_ID_WIDTH: usize = 4;
const TYPE_ID_WIDTH: usize = 4;
const PROTO_ID_WIDTH: usize = 12;
const FIELD_ID_WIDTH: usize = 8;
const METHOD_ID_WIDTH: usize = 8;
const CLASS_DEF_WIDTH: usize = 32;

const VALUE_STRING: u8 = 0x17;
const VALUE_ARRAY: u8 = 0x1c;
const VALUE_ANNOTATION: u8 = 0x1d;
const VALUE_NULL: u8 = 0x1e;
const VALUE_BOOLEAN: u8 = 0x1f;

#[derive(Clone, Copy)]
struct Section {
    count: usize,
    offset: usize,
}

#[derive(Clone, Copy)]
struct Header {
    strings: Section,
    types: Section,
    prototypes: Section,
    fields: Section,
    methods: Section,
    classes: Section,
}

pub(super) struct Dex<'a> {
    bytes: Cow<'a, [u8]>,
    header: Header,
}

impl<'a> Dex<'a> {
    pub(super) fn parse(bytes: Cow<'a, [u8]>) -> Result<Self, String> {
        let header = Header::parse(&bytes)?;
        Ok(Self { bytes, header })
    }

    pub(super) fn into_bytes(self) -> Cow<'a, [u8]> {
        self.bytes
    }

    fn view(&self) -> DexView<'_> {
        DexView { bytes: &self.bytes }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn strings(&self) -> StringTable<'_> {
        StringTable::new(self.view(), self.header.strings)
    }

    pub(super) fn types(&self) -> TypeTable<'_> {
        TypeTable::new(self.view(), self.header.types)
    }

    pub(super) fn prototypes(&self) -> ProtoTable<'_> {
        ProtoTable::new(self.view(), self.header.prototypes)
    }

    pub(super) fn fields(&self) -> FieldTable<'_> {
        FieldTable::new(self.view(), self.header.fields)
    }

    pub(super) fn methods(&self) -> MethodTable<'_> {
        MethodTable::new(self.view(), self.header.methods)
    }

    pub(super) fn classes(&self) -> ClassTable<'_> {
        ClassTable::new(self.view(), self.header.classes)
    }
}

impl Header {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let view = ByteView::new(bytes);
        let magic = view.slice(0, 8)?;

        if &magic[..4] != b"dex\n" || !magic[4..7].iter().all(u8::is_ascii_digit) || magic[7] != 0 {
            return Err("unsupported DEX magic".to_owned());
        }

        let mut fields = Cursor::new(bytes, HEADER_FIELDS_OFFSET)?;

        if fields.read_u32()? as usize != bytes.len() {
            return Err("DEX file_size does not match the input".to_owned());
        }

        if fields.read_u32()? as usize != HEADER_SIZE {
            return Err("unsupported DEX header size".to_owned());
        }

        if fields.read_u32()? != ENDIAN_TAG {
            return Err("unsupported DEX byte order".to_owned());
        }

        fields.skip(LINK_AND_MAP_FIELDS_SIZE)?;

        let strings = view.section(&mut fields, STRING_ID_WIDTH)?;
        let types = view.section(&mut fields, TYPE_ID_WIDTH)?;
        let prototypes = view.section(&mut fields, PROTO_ID_WIDTH)?;
        let table_fields = view.section(&mut fields, FIELD_ID_WIDTH)?;
        let methods = view.section(&mut fields, METHOD_ID_WIDTH)?;
        let classes = view.section(&mut fields, CLASS_DEF_WIDTH)?;

        Ok(Self {
            strings,
            types,
            prototypes,
            fields: table_fields,
            methods,
            classes,
        })
    }
}

#[derive(Clone, Copy)]
struct DexView<'a> {
    bytes: &'a [u8],
}

impl<'a> DexView<'a> {
    fn bytes(self) -> ByteView<'a> {
        ByteView::new(self.bytes)
    }
}
impl ByteView<'_> {
    fn section(self, cursor: &mut Cursor<'_>, width: usize) -> Result<Section, String> {
        let section = Section {
            count: cursor.read_u32()? as usize,
            offset: cursor.read_u32()? as usize,
        };

        self.table(section, width)?;

        Ok(section)
    }

    fn table(self, section: Section, width: usize) -> Result<(), String> {
        let length = section
            .count
            .checked_mul(width)
            .ok_or("DEX table size overflow")?;

        self.slice(section.offset, length)?;

        Ok(())
    }
}

macro_rules! table {
    ($name:ident, $item:ident, $width:expr) => {
        pub(super) struct $name<'a> {
            dex: DexView<'a>,
            section: Section,
        }

        impl<'a> $name<'a> {
            fn new(dex: DexView<'a>, section: Section) -> Self {
                Self { dex, section }
            }

            pub(super) fn len(&self) -> usize {
                self.section.count
            }

            pub(super) fn get(&self, index: usize) -> Result<$item<'a>, String> {
                if index >= self.section.count {
                    return Err(format!("DEX table index {index} is out of bounds"));
                }

                let offset = self
                    .section
                    .offset
                    .checked_add(
                        index
                            .checked_mul($width)
                            .ok_or("DEX table index overflow")?,
                    )
                    .ok_or("DEX table offset overflow")?;

                $item::read(self.dex, offset)
            }
        }
    };
}

table!(StringTable, StringId, STRING_ID_WIDTH);
table!(TypeTable, TypeId, TYPE_ID_WIDTH);
table!(ProtoTable, ProtoId, PROTO_ID_WIDTH);
table!(FieldTable, FieldId, FIELD_ID_WIDTH);
table!(MethodTable, MethodId, METHOD_ID_WIDTH);
table!(ClassTable, ClassDef, CLASS_DEF_WIDTH);

pub(super) struct StringId<'a> {
    dex: DexView<'a>,
    data_offset: usize,
}

impl<'a> StringId<'a> {
    fn read(dex: DexView<'a>, offset: usize) -> Result<Self, String> {
        let mut cursor = Cursor::new(dex.bytes, offset)?;
        Ok(Self {
            dex,
            data_offset: cursor.read_u32()? as usize,
        })
    }

    pub(super) fn value(&self) -> Result<Cow<'a, str>, String> {
        let mut cursor = Cursor::new(self.dex.bytes, self.data_offset)?;
        let utf16_size = cursor.read_uleb128()? as usize;
        let start = cursor.offset();
        let end = self.dex.bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .and_then(|length| start.checked_add(length))
            .ok_or("unterminated MUTF-8 string")?;
        let encoded = &self.dex.bytes[start..end];

        if !encoded.iter().any(|byte| *byte >= 0xf0)
            && let Ok(value) = std::str::from_utf8(encoded)
            && value.encode_utf16().count() == utf16_size
        {
            return Ok(Cow::Borrowed(value));
        }

        decode_mutf8(encoded, utf16_size).map(Cow::Owned)
    }
}

pub(super) struct TypeId<'a> {
    _dex: DexView<'a>,
    descriptor_index: usize,
}

impl<'a> TypeId<'a> {
    fn read(dex: DexView<'a>, offset: usize) -> Result<Self, String> {
        let mut cursor = Cursor::new(dex.bytes, offset)?;
        Ok(Self {
            _dex: dex,
            descriptor_index: cursor.read_u32()? as usize,
        })
    }

    pub(super) fn descriptor_index(&self) -> usize {
        self.descriptor_index
    }
}

pub(super) struct ProtoId<'a> {
    dex: DexView<'a>,
    return_type_index: usize,
    parameters_offset: usize,
}

impl<'a> ProtoId<'a> {
    fn read(dex: DexView<'a>, offset: usize) -> Result<Self, String> {
        let mut cursor = Cursor::new(dex.bytes, offset)?;
        cursor.read_u32()?;
        Ok(Self {
            dex,
            return_type_index: cursor.read_u32()? as usize,
            parameters_offset: cursor.read_u32()? as usize,
        })
    }

    pub(super) fn return_type_index(&self) -> usize {
        self.return_type_index
    }

    pub(super) fn parameters(&self) -> Result<Option<TypeList<'a>>, String> {
        TypeList::parse(self.dex, self.parameters_offset)
    }
}

pub(super) struct FieldId<'a> {
    _dex: DexView<'a>,
    class_index: usize,
    type_index: usize,
    name_index: usize,
}

impl<'a> FieldId<'a> {
    fn read(dex: DexView<'a>, offset: usize) -> Result<Self, String> {
        let mut cursor = Cursor::new(dex.bytes, offset)?;
        Ok(Self {
            _dex: dex,
            class_index: cursor.read_u16()? as usize,
            type_index: cursor.read_u16()? as usize,
            name_index: cursor.read_u32()? as usize,
        })
    }

    pub(super) fn class_index(&self) -> usize {
        self.class_index
    }

    pub(super) fn type_index(&self) -> usize {
        self.type_index
    }

    pub(super) fn name_index(&self) -> usize {
        self.name_index
    }
}

pub(super) struct MethodId<'a> {
    _dex: DexView<'a>,
    class_index: usize,
    prototype_index: usize,
    name_index: usize,
}

impl<'a> MethodId<'a> {
    fn read(dex: DexView<'a>, offset: usize) -> Result<Self, String> {
        let mut cursor = Cursor::new(dex.bytes, offset)?;
        Ok(Self {
            _dex: dex,
            class_index: cursor.read_u16()? as usize,
            prototype_index: cursor.read_u16()? as usize,
            name_index: cursor.read_u32()? as usize,
        })
    }

    pub(super) fn class_index(&self) -> usize {
        self.class_index
    }

    pub(super) fn prototype_index(&self) -> usize {
        self.prototype_index
    }

    pub(super) fn name_index(&self) -> usize {
        self.name_index
    }
}

pub(super) struct ClassDef<'a> {
    dex: DexView<'a>,
    class_index: usize,
    superclass_index: Option<usize>,
    interfaces_offset: usize,
    source_index: Option<usize>,
    class_data_offset: usize,
    static_values_offset: usize,
}

impl<'a> ClassDef<'a> {
    fn read(dex: DexView<'a>, offset: usize) -> Result<Self, String> {
        let mut cursor = Cursor::new(dex.bytes, offset)?;
        let class_index = cursor.read_u32()? as usize;

        cursor.read_u32()?;

        let superclass_index = cursor.read_u32()?;
        let interfaces_offset = cursor.read_u32()? as usize;
        let source_index = cursor.read_u32()?;

        cursor.read_u32()?;

        let class_data_offset = cursor.read_u32()? as usize;
        let static_values_offset = cursor.read_u32()? as usize;

        Ok(Self {
            dex,
            class_index,
            superclass_index: (superclass_index != NO_INDEX).then_some(superclass_index as usize),
            interfaces_offset,
            source_index: (source_index != NO_INDEX).then_some(source_index as usize),
            class_data_offset,
            static_values_offset,
        })
    }

    pub(super) fn class_index(&self) -> usize {
        self.class_index
    }

    pub(super) fn superclass_index(&self) -> Option<usize> {
        self.superclass_index
    }

    pub(super) fn interfaces(&self) -> Result<Option<TypeList<'a>>, String> {
        TypeList::parse(self.dex, self.interfaces_offset)
    }

    pub(super) fn source_index(&self) -> Option<usize> {
        self.source_index
    }

    pub(super) fn data(&self) -> Result<Option<ClassData<'a>>, String> {
        ClassData::parse(self.dex, self.class_data_offset)
    }

    pub(super) fn static_values(&self) -> Result<Option<EncodedArray<'a>>, String> {
        EncodedArray::parse(self.dex.bytes, self.static_values_offset)
    }
}

pub(super) struct TypeList<'a> {
    dex: DexView<'a>,
    count: usize,
    offset: usize,
}

impl<'a> TypeList<'a> {
    fn parse(dex: DexView<'a>, offset: usize) -> Result<Option<Self>, String> {
        if offset == 0 {
            return Ok(None);
        }

        let mut cursor = Cursor::new(dex.bytes, offset)?;
        let count = cursor.read_u32()? as usize;
        let items_offset = cursor.offset();

        dex.bytes().table(
            Section {
                count,
                offset: items_offset,
            },
            2,
        )?;

        Ok(Some(Self {
            dex,
            count,
            offset: items_offset,
        }))
    }

    pub(super) fn len(&self) -> usize {
        self.count
    }

    pub(super) fn type_index(&self, index: usize) -> Result<usize, String> {
        if index >= self.count {
            return Err(format!("type list index {index} is out of bounds"));
        }

        Ok(self.dex.bytes().u16(self.offset + index * 2)? as usize)
    }
}

pub(super) struct ClassData<'a> {
    cursor: Cursor<'a>,
    field_counts: [usize; 2],
    method_counts: [usize; 2],
    field_group: usize,
    fields_read: usize,
    field_index: usize,
    method_group: usize,
    methods_read: usize,
    method_index: usize,
}

impl<'a> ClassData<'a> {
    fn parse(bytes: DexView<'a>, offset: usize) -> Result<Option<Self>, String> {
        if offset == 0 {
            return Ok(None);
        }

        let mut cursor = Cursor::new(bytes.bytes, offset)?;
        let field_counts = [
            cursor.read_uleb128()? as usize,
            cursor.read_uleb128()? as usize,
        ];

        let method_counts = [
            cursor.read_uleb128()? as usize,
            cursor.read_uleb128()? as usize,
        ];

        Ok(Some(Self {
            cursor,
            field_counts,
            method_counts,
            field_group: 0,
            fields_read: 0,
            field_index: 0,
            method_group: 0,
            methods_read: 0,
            method_index: 0,
        }))
    }

    pub(super) fn next_field(&mut self) -> Result<Option<EncodedField>, String> {
        while self.field_group < self.field_counts.len()
            && self.fields_read == self.field_counts[self.field_group]
        {
            self.field_group += 1;
            self.fields_read = 0;
            self.field_index = 0;
        }

        if self.field_group == self.field_counts.len() {
            return Ok(None);
        }

        self.field_index = self
            .field_index
            .checked_add(self.cursor.read_uleb128()? as usize)
            .ok_or("field index overflow")?;
        self.cursor.read_uleb128()?;
        self.fields_read += 1;

        Ok(Some(EncodedField {
            index: self.field_index,
            is_static: self.field_group == 0,
        }))
    }

    pub(super) fn next_method(&mut self) -> Result<Option<EncodedMethod>, String> {
        while self.next_field()?.is_some() {}

        while self.method_group < self.method_counts.len()
            && self.methods_read == self.method_counts[self.method_group]
        {
            self.method_group += 1;
            self.methods_read = 0;
            self.method_index = 0;
        }

        if self.method_group == self.method_counts.len() {
            return Ok(None);
        }

        self.method_index = self
            .method_index
            .checked_add(self.cursor.read_uleb128()? as usize)
            .ok_or("method index overflow")?;
        self.cursor.read_uleb128()?;

        let code_offset = self.cursor.read_uleb128()? as usize;

        self.methods_read += 1;

        Ok(Some(EncodedMethod {
            index: self.method_index,
            code_offset,
        }))
    }
}

pub(super) struct EncodedField {
    index: usize,
    is_static: bool,
}

impl EncodedField {
    pub(super) fn index(&self) -> usize {
        self.index
    }

    pub(super) fn is_static(&self) -> bool {
        self.is_static
    }
}

pub(super) struct EncodedMethod {
    index: usize,
    code_offset: usize,
}

impl EncodedMethod {
    pub(super) fn index(&self) -> usize {
        self.index
    }

    pub(super) fn code_offset(&self) -> Option<usize> {
        (self.code_offset != 0).then_some(self.code_offset)
    }
}

pub(super) struct EncodedArray<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}

impl<'a> EncodedArray<'a> {
    fn parse(bytes: &'a [u8], offset: usize) -> Result<Option<Self>, String> {
        if offset == 0 {
            return Ok(None);
        }

        let mut cursor = Cursor::new(bytes, offset)?;
        let remaining = cursor.read_uleb128()? as usize;

        Ok(Some(Self { cursor, remaining }))
    }

    pub(super) fn len(&self) -> usize {
        self.remaining
    }

    pub(super) fn next(&mut self) -> Result<Option<EncodedValue>, String> {
        if self.remaining == 0 {
            return Ok(None);
        }

        self.remaining -= 1;

        read_encoded_value(&mut self.cursor).map(Some)
    }
}

pub(super) enum EncodedValue {
    String(usize),
    Other,
}

trait DexCursor {
    fn read_uleb128(&mut self) -> Result<u32, String>;
    fn read_little_endian(&mut self, byte_count: usize) -> Result<u64, String>;
}

impl DexCursor for Cursor<'_> {
    fn read_uleb128(&mut self) -> Result<u32, String> {
        let mut value = 0u32;

        for shift in (0..35).step_by(7) {
            let byte = self.read_u8()?;
            value |= ((byte & 0x7f) as u32) << shift;

            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }

        Err("ULEB128 is too large".to_owned())
    }

    fn read_little_endian(&mut self, byte_count: usize) -> Result<u64, String> {
        if byte_count > 8 {
            return Err("encoded_value is too wide".to_owned());
        }

        let bytes = self.read_bytes(byte_count)?;

        Ok(bytes.iter().enumerate().fold(0, |value, (shift, byte)| {
            value | (*byte as u64) << (shift * 8)
        }))
    }
}

fn read_encoded_value(cursor: &mut Cursor<'_>) -> Result<EncodedValue, String> {
    let header = cursor.read_u8()?;
    let value_type = header & 0x1f;
    let byte_count = (header >> 5) as usize + 1;

    match value_type {
        VALUE_STRING => Ok(EncodedValue::String(
            cursor.read_little_endian(byte_count)? as usize
        )),
        VALUE_ARRAY => {
            let count = cursor.read_uleb128()?;

            for _ in 0..count {
                read_encoded_value(cursor)?;
            }

            Ok(EncodedValue::Other)
        }
        VALUE_ANNOTATION => {
            cursor.read_uleb128()?;

            let count = cursor.read_uleb128()?;

            for _ in 0..count {
                cursor.read_uleb128()?;
                read_encoded_value(cursor)?;
            }

            Ok(EncodedValue::Other)
        }
        VALUE_NULL | VALUE_BOOLEAN => Ok(EncodedValue::Other),
        0x00..=0x06 | 0x10 | 0x11 | 0x15 | 0x16 | 0x18..=0x1b => {
            cursor.read_little_endian(byte_count)?;
            Ok(EncodedValue::Other)
        }
        _ => Err(format!("unknown encoded_value type 0x{value_type:02x}")),
    }
}

fn decode_mutf8(encoded: &[u8], utf16_size: usize) -> Result<String, String> {
    let mut utf16 = Vec::with_capacity(utf16_size);
    let mut cursor = 0;

    while cursor < encoded.len() {
        let first = encoded[cursor];
        cursor += 1;

        let code = if first & 0x80 == 0 {
            first as u16
        } else if first & 0xe0 == 0xc0 {
            let second = *encoded.get(cursor).ok_or("truncated MUTF-8 sequence")?;

            if second & 0xc0 != 0x80 {
                return Err("invalid MUTF-8 continuation byte".to_owned());
            }

            cursor += 1;

            (((first & 0x1f) as u16) << 6) | (second & 0x3f) as u16
        } else if first & 0xf0 == 0xe0 {
            let second = *encoded.get(cursor).ok_or("truncated MUTF-8 sequence")?;
            let third = *encoded.get(cursor + 1).ok_or("truncated MUTF-8 sequence")?;

            if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                return Err("invalid MUTF-8 continuation byte".to_owned());
            }

            cursor += 2;

            (((first & 0x0f) as u16) << 12)
                | (((second & 0x3f) as u16) << 6)
                | (third & 0x3f) as u16
        } else {
            return Err("invalid MUTF-8 lead byte".to_owned());
        };

        utf16.push(code);
    }

    if utf16.len() != utf16_size {
        return Err("MUTF-8 UTF-16 size mismatch".to_owned());
    }

    Ok(String::from_utf16_lossy(&utf16))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{DexView, EncodedArray, EncodedValue, StringId};

    #[test]
    fn borrows_utf8_and_owns_modified_utf8() {
        let plain = [3, b'a', b'b', b'c', 0];
        let value = StringId {
            dex: DexView { bytes: &plain },
            data_offset: 0,
        }
        .value()
        .unwrap();
        assert!(matches!(value, Cow::Borrowed("abc")));

        let modified = [3, b'a', 0xc0, 0x80, b'b', 0];
        let value = StringId {
            dex: DexView { bytes: &modified },
            data_offset: 0,
        }
        .value()
        .unwrap();
        assert!(matches!(value, Cow::Owned(ref value) if value == "a\0b"));
    }

    #[test]
    fn reads_encoded_array_values() {
        let bytes = [0, 3, 0x04, 7, 0x17, 2, 0x1e];
        let mut values = EncodedArray::parse(&bytes, 1).unwrap().unwrap();
        assert!(matches!(values.next().unwrap(), Some(EncodedValue::Other)));
        assert!(matches!(
            values.next().unwrap(),
            Some(EncodedValue::String(2))
        ));
        assert!(matches!(values.next().unwrap(), Some(EncodedValue::Other)));
        assert!(values.next().unwrap().is_none());
    }
}

use std::collections::HashSet;

use super::format::{ByteView, Chunk, StringPool, TypedValue, ValueKind, XmlChunkKind};

const XML_NODE_HEADER_SIZE: usize = 16;
const XML_START_ELEMENT_SIZE: usize = 36;
const XML_ATTRIBUTE_SIZE: usize = 20;
const NO_INDEX: u32 = u32::MAX;
const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

pub(super) struct Hit {
    pub(super) attribute: String,
    pub(super) view_id: Option<u32>,
}

fn text(pool: &[String], index: u32) -> Result<&str, String> {
    pool.get(index as usize)
        .map(String::as_str)
        .ok_or("binary XML string index is out of bounds".to_owned())
}

struct XmlAttribute {
    namespace_index: Option<u32>,
    name_index: u32,
    value: TypedValue,
}

impl XmlAttribute {
    fn parse(view: ByteView<'_>, offset: usize) -> Result<Self, String> {
        let namespace = view.u32(offset)?;

        Ok(Self {
            namespace_index: (namespace != NO_INDEX).then_some(namespace),
            name_index: view.u32(offset + 4)?,
            value: TypedValue::parse(view, offset + 12)?,
        })
    }
}

struct XmlStartElement {
    attributes: Vec<XmlAttribute>,
}

impl XmlStartElement {
    fn parse(bytes: &[u8], chunk: Chunk) -> Result<Self, String> {
        if chunk.header_size < XML_NODE_HEADER_SIZE
            || chunk.start + XML_START_ELEMENT_SIZE > chunk.end
        {
            return Err("invalid binary XML start element".to_owned());
        }

        let view = chunk.view(bytes);
        let attribute_start = view.u16(chunk.start + 24)? as usize;
        let attribute_size = view.u16(chunk.start + 26)? as usize;
        let count = view.u16(chunk.start + 28)? as usize;

        if attribute_size < XML_ATTRIBUTE_SIZE {
            return Err("invalid binary XML attribute size".to_owned());
        }

        let start = chunk
            .start
            .checked_add(XML_NODE_HEADER_SIZE)
            .and_then(|offset| offset.checked_add(attribute_start))
            .ok_or("binary XML attribute offset overflow")?;
        let length = count
            .checked_mul(attribute_size)
            .ok_or("binary XML attribute count overflow")?;

        if start < chunk.start + XML_START_ELEMENT_SIZE {
            return Err("binary XML attributes overlap element header".to_owned());
        }

        view.slice(start, length)?;

        let attributes = (0..count)
            .map(|index| XmlAttribute::parse(view, start + index * attribute_size))
            .collect::<Result<_, _>>()?;

        Ok(Self { attributes })
    }
}

pub(super) fn references(bytes: &[u8], targets: &HashSet<u32>) -> Result<Vec<Hit>, String> {
    let xml = Chunk::parse(bytes, 0, bytes.len())?;

    if xml.xml_kind() != XmlChunkKind::Xml {
        return Err("not Android binary XML".to_owned());
    }

    let mut pool = Vec::new();
    let mut depth = 0usize;
    let mut hits = Vec::new();
    let mut cursor = xml.body();

    while cursor < xml.end {
        let item = Chunk::parse(bytes, cursor, xml.end)?;
        match item.xml_kind() {
            XmlChunkKind::StringPool => pool = StringPool::parse(bytes, item)?.into_values(),
            XmlChunkKind::StartElement => {
                let element = XmlStartElement::parse(bytes, item)?;
                depth += 1;

                let mut view_id = None;
                let mut matched = Vec::new();

                for attribute in element.attributes {
                    let attr_name = text(&pool, attribute.name_index)?;
                    let uri = attribute
                        .namespace_index
                        .map(|index| text(&pool, index))
                        .transpose()?
                        .unwrap_or("");

                    if !matches!(
                        attribute.value.kind,
                        ValueKind::Reference | ValueKind::DynamicReference
                    ) {
                        continue;
                    }

                    if attr_name == "id" && uri == ANDROID_NAMESPACE {
                        view_id = Some(attribute.value.data);
                    }

                    if targets.contains(&attribute.value.data) {
                        let attribute = if uri == ANDROID_NAMESPACE {
                            format!("android:{attr_name}")
                        } else if uri.is_empty() {
                            attr_name.to_owned()
                        } else {
                            format!("{uri}:{attr_name}")
                        };
                        matched.push(attribute);
                    }
                }

                for attribute in matched {
                    hits.push(Hit { attribute, view_id });
                }
            }
            XmlChunkKind::EndElement if depth == 0 => {
                return Err("binary XML has unmatched end element".to_owned());
            }
            XmlChunkKind::EndElement => depth -= 1,
            _ => {}
        }
        cursor = item.end;
    }
    
    if depth != 0 {
        return Err("binary XML has unclosed elements".to_owned());
    }

    Ok(hits)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::references;

    #[test]
    fn locates_view_id_in_compiled_xml() {
        let names = [
            "TextView",
            "http://schemas.android.com/apk/res/android",
            "id",
        ];
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for name in names {
            offsets.extend_from_slice(&(data.len() as u32).to_le_bytes());
            data.push(name.len() as u8);
            data.push(name.len() as u8);
            data.extend_from_slice(name.as_bytes());
            data.push(0);
        }
        let pool_size = (28 + offsets.len() + data.len()) as u32;
        let mut pool = vec![1, 0, 28, 0];
        pool.extend_from_slice(&pool_size.to_le_bytes());
        pool.extend_from_slice(&3u32.to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes());
        pool.extend_from_slice(&0x100u32.to_le_bytes());
        pool.extend_from_slice(&40u32.to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes());
        pool.extend_from_slice(&offsets);
        pool.extend_from_slice(&data);

        let mut start = vec![2, 1, 16, 0, 56, 0, 0, 0];
        start.extend_from_slice(&7u32.to_le_bytes());
        start.extend_from_slice(&u32::MAX.to_le_bytes());
        start.extend_from_slice(&u32::MAX.to_le_bytes());
        start.extend_from_slice(&0u32.to_le_bytes());
        start.extend_from_slice(&20u16.to_le_bytes());
        start.extend_from_slice(&20u16.to_le_bytes());
        start.extend_from_slice(&1u16.to_le_bytes());
        start.extend_from_slice(&[0; 6]);
        start.extend_from_slice(&1u32.to_le_bytes());
        start.extend_from_slice(&2u32.to_le_bytes());
        start.extend_from_slice(&u32::MAX.to_le_bytes());
        start.extend_from_slice(&[8, 0, 0, 1]);
        start.extend_from_slice(&0x7f010001u32.to_le_bytes());

        let mut end = vec![3, 1, 16, 0, 24, 0, 0, 0];
        end.extend_from_slice(&7u32.to_le_bytes());
        end.extend_from_slice(&u32::MAX.to_le_bytes());
        end.extend_from_slice(&u32::MAX.to_le_bytes());
        end.extend_from_slice(&0u32.to_le_bytes());
        let mut xml = vec![3, 0, 8, 0];
        xml.extend_from_slice(
            &(8 + pool.len() as u32 + start.len() as u32 + end.len() as u32).to_le_bytes(),
        );
        xml.extend_from_slice(&pool);
        xml.extend_from_slice(&start);
        xml.extend_from_slice(&end);

        let hits = references(&xml, &HashSet::from([0x7f010001])).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].attribute, "android:id");
        assert_eq!(hits[0].view_id, Some(0x7f010001));
    }
}

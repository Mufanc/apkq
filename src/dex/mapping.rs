use std::collections::HashMap;
use std::slice::Iter;

use rkyv::rancor::Error;
use rkyv::{Archive, Serialize};

use crate::java::JavaType;
use crate::mapping_cache::{self, Cache};

#[derive(Debug)]
pub struct Mapping {
    data: Cache<MappingData>,
}

#[derive(Archive, Debug, Serialize)]
struct MappingData {
    classes: HashMap<String, ClassMapping>,
}

#[derive(Archive, Debug, Serialize)]
struct ClassMapping {
    original: String,
    methods: HashMap<String, Vec<StoredMemberMapping>>,
    fields: HashMap<String, Vec<StoredMemberMapping>>,
}

#[derive(Archive, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct StoredMemberMapping {
    name: String,
    descriptor: String,
}

pub struct MemberMapping<'a> {
    pub name: &'a str,
    pub descriptor: &'a str,
}

pub struct MemberMappings<'a>(MemberMappingIter<'a>);

enum MemberMappingIter<'a> {
    Parsed(Iter<'a, StoredMemberMapping>),
    Archived(Iter<'a, ArchivedStoredMemberMapping>),
    Empty,
}

impl<'a> Iterator for MemberMappings<'a> {
    type Item = MemberMapping<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            MemberMappingIter::Parsed(items) => items.next().map(|item| MemberMapping {
                name: &item.name,
                descriptor: &item.descriptor,
            }),
            MemberMappingIter::Archived(items) => items.next().map(|item| MemberMapping {
                name: item.name.as_str(),
                descriptor: item.descriptor.as_str(),
            }),
            MemberMappingIter::Empty => None,
        }
    }
}

impl Mapping {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut names = HashMap::new();

        for line in text.lines() {
            if let Some((original, obfuscated)) = parse_class_line(line) {
                names.insert(original.to_owned(), obfuscated.to_owned());
            }
        }

        if names.is_empty() {
            return Err("mapping contains no class mappings".to_owned());
        }

        let mut classes = HashMap::new();
        let mut current_class = None;

        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((original, obfuscated)) = parse_class_line(line) {
                let descriptor = type_descriptor(obfuscated, None)?;

                classes.insert(
                    descriptor.clone(),
                    ClassMapping {
                        original: type_descriptor(original, None)?,
                        methods: HashMap::new(),
                        fields: HashMap::new(),
                    },
                );
                current_class = Some(descriptor);

                continue;
            }

            if !line.starts_with(char::is_whitespace) {
                return Err(format!("invalid class mapping at line {}", line_number + 1));
            }

            let class = current_class.as_ref().ok_or_else(|| {
                format!("member before class mapping at line {}", line_number + 1)
            })?;

            let class = classes
                .get_mut(class)
                .expect("current mapping class was just inserted");

            parse_member(trimmed, &names, class)
                .map_err(|error| format!("{error} at line {}", line_number + 1))?;
        }

        for class in classes.values_mut() {
            for members in class.methods.values_mut().chain(class.fields.values_mut()) {
                members.sort();
                members.dedup();
            }
        }

        Ok(Self {
            data: Cache::Parsed(MappingData { classes }),
        })
    }

    pub fn original_class(&self, descriptor: &str) -> Option<&str> {
        match &self.data {
            Cache::Parsed(mapping) => mapping
                .classes
                .get(descriptor)
                .map(|class| class.original.as_str()),
            Cache::Archived(bytes) => archived(bytes.as_ref())
                .classes
                .get(descriptor)
                .map(|class| class.original.as_str()),
        }
    }

    pub fn obfuscated_classes(&self, original: &str) -> Vec<&str> {
        match &self.data {
            Cache::Parsed(mapping) => mapping
                .classes
                .iter()
                .filter_map(|(descriptor, class)| {
                    (class.original == original).then_some(descriptor.as_str())
                })
                .collect(),
            Cache::Archived(bytes) => archived(bytes.as_ref())
                .classes
                .iter()
                .filter_map(|(descriptor, class)| {
                    (class.original.as_str() == original).then_some(descriptor.as_str())
                })
                .collect(),
        }
    }

    pub fn methods<'a>(&'a self, class: &str, name: &str, descriptor: &str) -> MemberMappings<'a> {
        self.members(class, &member_key(name, descriptor), false)
    }

    pub fn fields<'a>(&'a self, class: &str, name: &str, descriptor: &str) -> MemberMappings<'a> {
        self.members(class, &member_key(name, descriptor), true)
    }

    fn members<'a>(&'a self, class: &str, key: &str, fields: bool) -> MemberMappings<'a> {
        match &self.data {
            Cache::Parsed(mapping) => mapping
                .classes
                .get(class)
                .and_then(|class| {
                    if fields {
                        class.fields.get(key)
                    } else {
                        class.methods.get(key)
                    }
                })
                .map(|items| MemberMappings(MemberMappingIter::Parsed(items.iter())))
                .unwrap_or(MemberMappings(MemberMappingIter::Empty)),
            Cache::Archived(bytes) => archived(bytes.as_ref())
                .classes
                .get(class)
                .and_then(|class| {
                    if fields {
                        class.fields.get(key)
                    } else {
                        class.methods.get(key)
                    }
                })
                .map(|items| MemberMappings(MemberMappingIter::Archived(items.iter())))
                .unwrap_or(MemberMappings(MemberMappingIter::Empty)),
        }
    }
}

pub fn load(spec: &str) -> Result<Mapping, String> {
    let data = mapping_cache::load(
        "dex",
        spec,
        |bytes| {
            let text = std::str::from_utf8(bytes)
                .map_err(|error| format!("mapping is not valid UTF-8: {error}"))?;

            Mapping::parse(text).map(|mapping| match mapping.data {
                Cache::Parsed(data) => data,
                Cache::Archived(_) => unreachable!(),
            })
        },
        |bytes| rkyv::access::<ArchivedMappingData, Error>(bytes).is_ok(),
    )?;

    Ok(Mapping { data })
}

#[allow(unsafe_code)]
fn archived(bytes: &[u8]) -> &ArchivedMappingData {
    // SAFETY: ArchivedBytes is constructed only after validation and remains immutable.
    unsafe { rkyv::access_unchecked(bytes) }
}

fn parse_class_line(line: &str) -> Option<(&str, &str)> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }

    let (original, obfuscated) = line.split_once(" -> ")?;

    Some((original.trim(), obfuscated.trim().strip_suffix(':')?))
}

fn parse_member(
    line: &str,
    names: &HashMap<String, String>,
    class: &mut ClassMapping,
) -> Result<(), String> {
    let (original, obfuscated) = line
        .split_once(" -> ")
        .ok_or_else(|| "invalid member mapping".to_owned())?;
    let original = strip_line_prefix(original);

    if let Some(open) = original.find('(') {
        let close = original[open + 1..]
            .find(')')
            .map(|index| open + 1 + index)
            .ok_or_else(|| "invalid method mapping".to_owned())?;
        let (return_type, name) = original[..open]
            .trim()
            .rsplit_once(' ')
            .ok_or_else(|| "invalid method mapping".to_owned())?;
        let parameters = &original[open + 1..close];
        let original_descriptor = method_descriptor(return_type, parameters, None)?;
        let obfuscated_descriptor = method_descriptor(return_type, parameters, Some(names))?;

        class
            .methods
            .entry(member_key(obfuscated.trim(), &obfuscated_descriptor))
            .or_default()
            .push(StoredMemberMapping {
                name: name.to_owned(),
                descriptor: original_descriptor,
            });
    } else {
        let (field_type, name) = original
            .trim()
            .rsplit_once(' ')
            .ok_or_else(|| "invalid field mapping".to_owned())?;
        let original_descriptor = type_descriptor(field_type, None)?;
        let obfuscated_descriptor = type_descriptor(field_type, Some(names))?;

        class
            .fields
            .entry(member_key(obfuscated.trim(), &obfuscated_descriptor))
            .or_default()
            .push(StoredMemberMapping {
                name: name.to_owned(),
                descriptor: original_descriptor,
            });
    }

    Ok(())
}

fn strip_line_prefix(value: &str) -> &str {
    let Some((start, rest)) = value.split_once(':') else {
        return value;
    };

    let Some((end, signature)) = rest.split_once(':') else {
        return value;
    };

    if start.chars().all(|character| character.is_ascii_digit())
        && end.chars().all(|character| character.is_ascii_digit())
    {
        signature
    } else {
        value
    }
}

fn method_descriptor(
    return_type: &str,
    parameters: &str,
    names: Option<&HashMap<String, String>>,
) -> Result<String, String> {
    let mut descriptor = String::from("(");

    if !parameters.trim().is_empty() {
        for parameter in parameters.split(',') {
            descriptor.push_str(&type_descriptor(parameter, names)?);
        }
    }

    descriptor.push(')');
    descriptor.push_str(&type_descriptor(return_type, names)?);

    Ok(descriptor)
}

fn type_descriptor(
    type_name: &str,
    names: Option<&HashMap<String, String>>,
) -> Result<String, String> {
    let ty: JavaType = type_name.trim().parse()?;
    let ty = match names {
        Some(names) => ty.map_class(names)?,
        None => ty,
    };

    Ok(ty.descriptor().to_owned())
}

fn member_key(name: &str, descriptor: &str) -> String {
    format!("{name}\0{descriptor}")
}

#[cfg(test)]
mod tests {

    use super::Mapping;

    const SAMPLE: &str = "\
# compiler: R8
com.example.Outer$Inner -> a.b:
    int count -> c
    1:2:java.lang.String load(com.example.Model,int[]):10:11 -> a
com.example.Model -> c.d:
    1:1:void <init>() -> <init>
";

    #[test]
    fn parses_classes_fields_methods_and_line_ranges() {
        let mapping = Mapping::parse(SAMPLE).unwrap();
        assert_eq!(
            mapping.original_class("La/b;"),
            Some("Lcom/example/Outer$Inner;")
        );
        assert_eq!(
            mapping.obfuscated_classes("Lcom/example/Outer$Inner;"),
            ["La/b;"]
        );
        assert_eq!(
            mapping.fields("La/b;", "c", "I").next().unwrap().name,
            "count"
        );
        let method = mapping
            .methods("La/b;", "a", "(Lc/d;[I)Ljava/lang/String;")
            .next()
            .unwrap();
        assert_eq!(method.name, "load");
        assert_eq!(
            method.descriptor,
            "(Lcom/example/Model;[I)Ljava/lang/String;"
        );
    }
}

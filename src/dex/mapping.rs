use std::collections::HashMap;
#[cfg(test)]
use std::io::{Cursor, Read};

use crate::input;
#[cfg(test)]
use zip::ZipArchive;

#[derive(Debug)]
pub struct Mapping {
    classes: HashMap<String, ClassMapping>,
}

#[derive(Debug)]
struct ClassMapping {
    original: String,
    methods: HashMap<String, Vec<MemberMapping>>,
    fields: HashMap<String, Vec<MemberMapping>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemberMapping {
    pub name: String,
    pub descriptor: String,
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

        Ok(Self { classes })
    }

    pub fn original_class(&self, descriptor: &str) -> Option<&str> {
        self.classes
            .get(descriptor)
            .map(|class| class.original.as_str())
    }

    pub fn methods(&self, class: &str, name: &str, descriptor: &str) -> &[MemberMapping] {
        self.classes
            .get(class)
            .and_then(|class| class.methods.get(&member_key(name, descriptor)))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn fields(&self, class: &str, name: &str, descriptor: &str) -> &[MemberMapping] {
        self.classes
            .get(class)
            .and_then(|class| class.fields.get(&member_key(name, descriptor)))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

pub fn load(spec: &str) -> Result<Mapping, String> {
    let bytes = input::read_file_spec(spec)?;

    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("mapping is not valid UTF-8: {error}"))?;

    Mapping::parse(text)
}

#[cfg(test)]
fn read_zip_entry(bytes: &[u8], archive: &str, entry: &str) -> Result<Vec<u8>, String> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("invalid mapping ZIP {archive}: {error}"))?;
    let mut file = zip
        .by_name(entry)
        .map_err(|error| format!("{archive}!{entry}: {error}"))?;

    let mut output = Vec::new();

    file.read_to_end(&mut output)
        .map_err(|error| format!("{archive}!{entry}: {error}"))?;

    if output.starts_with(b"PK\x03\x04")
        || output.starts_with(b"PK\x05\x06")
        || output.starts_with(b"PK\x07\x08")
    {
        return Err("nested mapping archives are not supported".to_owned());
    }

    Ok(output)
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
            .push(MemberMapping {
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
            .push(MemberMapping {
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
    let mut type_name = type_name.trim();
    let mut dimensions = 0;

    while let Some(element) = type_name.strip_suffix("[]") {
        type_name = element;
        dimensions += 1;
    }

    let base = match type_name {
        "void" => "V".to_owned(),
        "boolean" => "Z".to_owned(),
        "byte" => "B".to_owned(),
        "char" => "C".to_owned(),
        "short" => "S".to_owned(),
        "int" => "I".to_owned(),
        "long" => "J".to_owned(),
        "float" => "F".to_owned(),
        "double" => "D".to_owned(),
        "" => return Err("empty type in mapping".to_owned()),
        class => {
            let class = names
                .and_then(|names| names.get(class))
                .map(String::as_str)
                .unwrap_or(class);
            format!("L{};", class.replace('.', "/"))
        }
    };

    Ok(format!("{}{}", "[".repeat(dimensions), base))
}

fn member_key(name: &str, descriptor: &str) -> String {
    format!("{name}\0{descriptor}")
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::{Mapping, read_zip_entry};

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
        assert_eq!(mapping.fields("La/b;", "c", "I")[0].name, "count");
        let method = &mapping.methods("La/b;", "a", "(Lc/d;[I)Ljava/lang/String;")[0];
        assert_eq!(method.name, "load");
        assert_eq!(
            method.descriptor,
            "(Lcom/example/Model;[I)Ljava/lang/String;"
        );
    }

    #[test]
    fn reads_an_explicit_zip_entry() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("maps/release.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(SAMPLE.as_bytes()).unwrap();
        writer
            .start_file("maps/nested.zip", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"PK\x03\x04").unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let mapping = read_zip_entry(&bytes, "bundle.zip", "maps/release.txt").unwrap();
        assert_eq!(mapping, SAMPLE.as_bytes());
        assert_eq!(
            read_zip_entry(&bytes, "bundle.zip", "maps/nested.zip").unwrap_err(),
            "nested mapping archives are not supported"
        );
    }
}

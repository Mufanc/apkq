use crate::input;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Mapping {
    entries: HashMap<(String, String, String), String>,
}

impl Mapping {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = HashMap::new();

        for (index, line) in text.lines().enumerate() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (original, obfuscated) = line
                .split_once(" -> ")
                .ok_or_else(|| format!("invalid resource mapping at line {}", index + 1))?;
            let (original_package, original_kind, original_name) = parse_name(original)?;
            let (package, kind, name) = parse_name(obfuscated)?;

            if original_package != package || original_kind != kind {
                return Err(format!(
                    "resource package or type changes at line {}",
                    index + 1
                ));
            }

            entries.insert(
                (package.to_owned(), kind.to_owned(), name.to_owned()),
                original_name.to_owned(),
            );
        }

        if entries.is_empty() {
            return Err("mapping contains no resource mappings".to_owned());
        }

        Ok(Self { entries })
    }

    pub fn original(&self, package: &str, kind: &str, name: &str) -> Option<&str> {
        self.entries
            .get(&(package.to_owned(), kind.to_owned(), name.to_owned()))
            .map(String::as_str)
    }
}

pub fn load(spec: &str) -> Result<Mapping, String> {
    let bytes = input::read_file_spec(spec)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("resource mapping is not valid UTF-8: {error}"))?;

    Mapping::parse(text)
}

fn parse_name(value: &str) -> Result<(&str, &str, &str), String> {
    let (package, resource) = value
        .trim()
        .split_once(".R.")
        .ok_or("invalid resource mapping name")?;
    let (kind, name) = resource
        .split_once('.')
        .ok_or("invalid resource mapping name")?;

    if package.is_empty() || kind.is_empty() || name.is_empty() {
        return Err("invalid resource mapping name".to_owned());
    }

    Ok((package, kind, name))
}

#[cfg(test)]
mod tests {
    use super::Mapping;

    #[test]
    fn parses_andresguard_mapping() {
        let mapping =
            Mapping::parse("com.example.R.layout.activity_login -> com.example.R.layout.a\n")
                .unwrap();

        assert_eq!(
            mapping.original("com.example", "layout", "a"),
            Some("activity_login")
        );
    }
}

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::Path;

use regex::Regex;
use zip::ZipArchive;

use crate::dex::{self, PreparedArchive};

mod format;
pub mod mapping;
mod xml;

pub struct Query<'a> {
    pub mapping: Option<&'a mapping::Mapping>,
    pub kind: Option<&'a str>,
    pub name: Option<&'a str>,
    pub name_contains: Option<&'a str>,
    pub id: Option<u32>,
    pub value: Option<&'a str>,
    pub value_regex: Option<&'a Regex>,
    pub uses_resource: Option<&'a str>,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub struct Location {
    pub archive: String,
    pub id: u32,
    pub kind: String,
    pub name: String,
    pub config: String,
    pub value: String,
    pub path: Option<String>,
    pub usage: Option<String>,
}

pub fn parse_id(text: &str) -> Result<u32, String> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid resource ID: {text}"))
    } else {
        text.parse()
            .map_err(|_| format!("invalid resource ID: {text}"))
    }
}

fn target_ids(
    resources: &[format::Resource],
    target: &str,
    mapping: Option<&mapping::Mapping>,
) -> Result<HashSet<u32>, String> {
    if target.starts_with("0x")
        || target.starts_with("0X")
        || target.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(HashSet::from([parse_id(target)?]));
    }
    let (owner, rest) = match target.split_once(':') {
        Some((owner, rest)) if !owner.is_empty() => (Some(owner), rest),
        Some(_) => return Err("resource package cannot be empty".to_owned()),
        None => (None, target),
    };
    let (kind, name) = rest
        .split_once('/')
        .ok_or("resource reference must be an ID or [package:]type/name")?;
    if kind.is_empty() || name.is_empty() || name.contains('/') {
        return Err("resource reference must be an ID or [package:]type/name".to_owned());
    }
    Ok(resources
        .iter()
        .filter(|resource| {
            resource.kind == kind
                && (resource.name == name
                    || mapping.and_then(|mapping| {
                        mapping.original(&resource.package, &resource.kind, &resource.name)
                    }) == Some(name))
                && owner.is_none_or(|owner| resource.package == owner)
        })
        .map(|resource| resource.id)
        .collect())
}

pub fn validate_reference(value: &str) -> Result<String, String> {
    target_ids(&[], value, None)?;
    Ok(value.to_owned())
}

pub fn index_apk(apk: &Path, query: &Query<'_>) -> Result<Vec<Location>, String> {
    let prepared = dex::prepare_apk(apk)?;
    let mut output = Vec::new();
    index_archive(&prepared, query, &mut output)?;
    Ok(output)
}

fn index_archive(
    prepared: &PreparedArchive,
    query: &Query<'_>,
    output: &mut Vec<Location>,
) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(prepared.bytes.as_slice()))
        .map_err(|error| format!("{}: {error}", prepared.label))?;
    let mut bytes = Vec::new();

    match archive.by_name("resources.arsc") {
        Ok(mut entry) => entry
            .read_to_end(&mut bytes)
            .map_err(|error| format!("{}!resources.arsc: {error}", prepared.label))?,
        Err(zip::result::ZipError::FileNotFound) => 0,
        Err(error) => return Err(format!("{}!resources.arsc: {error}", prepared.label)),
    };

    if !bytes.is_empty() {
        let resources = format::parse(&bytes)
            .map_err(|error| format!("{}!resources.arsc: {error}", prepared.label))?;
        let targets = query
            .uses_resource
            .map(|value| target_ids(&resources, value, query.mapping))
            .transpose()?;
        let names = resources
            .iter()
            .map(|resource| {
                (
                    resource.id,
                    format!("{}:{}/{}", resource.package, resource.kind, resource.name),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut xml_cache = HashMap::<String, Vec<xml::Hit>>::new();

        for resource in &resources {
            let original = query.mapping.and_then(|mapping| {
                mapping.original(&resource.package, &resource.kind, &resource.name)
            });

            if query.kind.is_some_and(|value| resource.kind != value)
                || query
                    .name
                    .is_some_and(|value| resource.name != value && original != Some(value))
                || query.name_contains.is_some_and(|value| {
                    !resource.name.contains(value)
                        && !original.is_some_and(|name| name.contains(value))
                })
                || query.id.is_some_and(|value| resource.id != value)
                || query
                    .value
                    .is_some_and(|value| !resource.value.contains(value))
                || query
                    .value_regex
                    .is_some_and(|regex| !regex.is_match(&resource.value))
            {
                continue;
            }

            let location = |usage: Option<String>| Location {
                archive: prepared.label.clone(),
                id: resource.id,
                kind: resource.kind.clone(),
                name: resource.name.clone(),
                config: resource.config.clone(),
                value: resource.value.clone(),
                path: resource.path.clone(),
                usage,
            };

            if let Some(targets) = &targets {
                if targets.is_empty() {
                    continue;
                }

                for (attribute, reference) in &resource.references {
                    if targets.contains(reference) {
                        output.push(location(Some(attribute.clone())));
                    }
                }

                if let Some(path) = resource.path.as_ref().filter(|path| path.ends_with(".xml")) {
                    if !xml_cache.contains_key(path) {
                        let mut xml_bytes = Vec::new();
                        archive
                            .by_name(path)
                            .map_err(|error| format!("{}!{path}: {error}", prepared.label))?
                            .read_to_end(&mut xml_bytes)
                            .map_err(|error| format!("{}!{path}: {error}", prepared.label))?;
                        let hits = xml::references(&xml_bytes, targets)
                            .map_err(|error| format!("{}!{path}: {error}", prepared.label))?;
                        xml_cache.insert(path.clone(), hits);
                    }

                    for hit in &xml_cache[path] {
                        let view_id = hit.view_id.map(|id| {
                            names
                                .get(&id)
                                .cloned()
                                .unwrap_or_else(|| format!("0x{id:08x}"))
                        });
                        let usage = view_id
                            .map(|view_id| format!("{view_id}@{}", hit.attribute))
                            .unwrap_or_else(|| hit.attribute.clone());
                        output.push(location(Some(usage)));
                    }
                }
            } else {
                output.push(location(None));
            }
        }
    }
    for nested in &prepared.nested {
        index_archive(nested, query, output)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{format::Resource, parse_id, target_ids};

    #[test]
    fn resource_targets_are_scoped_and_ids_are_numeric() {
        let resources = vec![Resource {
            id: 0x7f010001,
            package: "app".into(),
            kind: "string".into(),
            name: "login_failed".into(),
            config: "default".into(),
            value: "failed".into(),
            path: None,
            references: vec![],
        }];
        assert_eq!(parse_id("0x7f010001").unwrap(), 0x7f010001);
        assert_eq!(
            target_ids(&resources, "string/login_failed", None)
                .unwrap()
                .len(),
            1
        );
        assert!(
            target_ids(&resources, "other:string/login_failed", None)
                .unwrap()
                .is_empty()
        );
        assert_eq!(target_ids(&resources, "0x7f010001", None).unwrap().len(), 1);
    }
}

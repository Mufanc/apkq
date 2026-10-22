use super::format::Dex;
use crate::archive::ApkArchive;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};

use regex::Regex;

use super::mapping::Mapping;
use super::parse;
use super::{DexIndex, FieldLocation, MethodLocation};
use crate::java::{JavaClass, JavaField, JavaMethod};

pub enum Query<'a> {
    Classes {
        name: Option<&'a JavaClass>,
        name_regex: Option<&'a Regex>,
        inherits: Option<&'a JavaClass>,
    },
    Fields {
        class: Option<&'a JavaClass>,
        name: Option<&'a str>,
        name_regex: Option<&'a Regex>,
    },
    Methods {
        class: Option<&'a JavaClass>,
        name: Option<&'a str>,
        name_regex: Option<&'a Regex>,
        has_field: Option<&'a str>,
    },
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub struct Symbol {
    pub dex: String,
    pub kind: char,
    pub symbol: String,
    pub original: Option<String>,
    pub source: Option<String>,
}

impl Query<'_> {
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

    pub fn select(
        &self,
        index: &DexIndex,
        mapping: Option<&Mapping>,
        selected_dex: Option<&str>,
    ) -> Result<Vec<Symbol>, String> {
        let mut output = Vec::new();

        match self {
            Query::Classes {
                name,
                name_regex,
                inherits,
                ..
            } => {
                let descendants = inherits
                    .as_ref()
                    .map(|parent| Self::inheritors(index, parent, mapping));

                for class in &index.classes {
                    if !Self::class_filters_match(&class.class, *name, *name_regex, mapping)?
                        || descendants
                            .as_ref()
                            .is_some_and(|descendants| !descendants.contains(class.class.as_str()))
                    {
                        continue;
                    }

                    output.push(Symbol {
                        dex: class.dex.clone(),
                        kind: 'C',
                        symbol: JavaClass::from_descriptor(&class.class)?.to_string(),
                        original: mapping
                            .as_ref()
                            .and_then(|mapping| mapping.original_class(&class.class))
                            .map(JavaClass::from_descriptor)
                            .transpose()?
                            .map(|class| class.to_string()),
                        source: class.source_file.clone(),
                    });
                }
            }
            Query::Fields {
                class,
                name,
                name_regex,
                ..
            } => {
                for field in &index.fields {
                    if class
                        .as_ref()
                        .is_some_and(|class| !Self::class_matches(&field.class, class, mapping))
                        || name
                            .as_deref()
                            .is_some_and(|name| !Self::field_name_matches(field, name, mapping))
                        || name_regex.as_ref().is_some_and(|regex| {
                            !Self::field_name_regex_matches(field, regex, mapping)
                        })
                    {
                        continue;
                    }

                    let symbol =
                        JavaField::from_parts(&field.class, &field.field, &field.descriptor)?
                            .to_string();
                    let originals = mapping
                        .as_ref()
                        .map(|mapping| {
                            mapping
                                .fields(&field.class, &field.field, &field.descriptor)
                                .filter_map(|alias| {
                                    mapping.original_class(&field.class).map(|owner| {
                                        JavaField::from_parts(owner, alias.name, alias.descriptor)
                                            .map(|field| field.to_string())
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()?
                        .unwrap_or_default();

                    Self::push_aliases(
                        &mut output,
                        &field.dex,
                        'F',
                        symbol,
                        originals,
                        field.source_file.as_deref(),
                    );
                }
            }
            Query::Methods {
                class,
                name,
                name_regex,
                has_field,
                ..
            } => {
                let field_classes = has_field.as_deref().map(|name| {
                    index
                        .fields
                        .iter()
                        .filter(|field| Self::field_name_matches(field, name, mapping))
                        .map(|field| field.class.as_str())
                        .collect::<HashSet<_>>()
                });

                for method in &index.locations {
                    if class
                        .as_ref()
                        .is_some_and(|class| !Self::class_matches(&method.class, class, mapping))
                        || name
                            .as_deref()
                            .is_some_and(|name| !Self::method_name_matches(method, name, mapping))
                        || name_regex.as_ref().is_some_and(|regex| {
                            !Self::method_name_regex_matches(method, regex, mapping)
                        })
                        || field_classes
                            .as_ref()
                            .is_some_and(|classes| !classes.contains(method.class.as_str()))
                    {
                        continue;
                    }

                    let symbol =
                        JavaMethod::from_parts(&method.class, &method.method, &method.descriptor)?
                            .to_string();
                    let originals = mapping
                        .as_ref()
                        .map(|mapping| {
                            mapping
                                .methods(&method.class, &method.method, &method.descriptor)
                                .filter_map(|alias| {
                                    mapping.original_class(&method.class).map(|owner| {
                                        JavaMethod::from_parts(owner, alias.name, alias.descriptor)
                                            .map(|method| method.to_string())
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()?
                        .unwrap_or_default();

                    Self::push_aliases(
                        &mut output,
                        &method.dex,
                        'M',
                        symbol,
                        originals,
                        method.source_file.as_deref(),
                    );
                }
            }
        }

        output.retain(|symbol| selected_dex.is_none_or(|selected| symbol.dex == selected));
        output.sort();
        output.dedup();

        Ok(output)
    }

    fn class_matches(descriptor: &str, query: &JavaClass, mapping: Option<&Mapping>) -> bool {
        descriptor == query.descriptor()
            || mapping
                .and_then(|mapping| mapping.original_class(descriptor))
                .is_some_and(|name| name == query.descriptor())
    }

    fn class_filters_match(
        descriptor: &str,
        name: Option<&JavaClass>,
        name_regex: Option<&Regex>,
        mapping: Option<&Mapping>,
    ) -> Result<bool, String> {
        let original = mapping.and_then(|mapping| mapping.original_class(descriptor));
        let names = [Some(descriptor), original];

        if !name.is_none_or(|query| {
            names
                .iter()
                .flatten()
                .any(|name| *name == query.descriptor())
        }) {
            return Ok(false);
        }

        let Some(regex) = name_regex else {
            return Ok(true);
        };

        for descriptor in names.iter().flatten() {
            if regex.is_match(JavaClass::from_descriptor(descriptor)?.name()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn method_name_matches(
        method: &MethodLocation,
        query: &str,
        mapping: Option<&Mapping>,
    ) -> bool {
        method.method == query
            || mapping.is_some_and(|mapping| {
                mapping
                    .methods(&method.class, &method.method, &method.descriptor)
                    .any(|alias| alias.name == query)
            })
    }

    fn method_name_regex_matches(
        method: &MethodLocation,
        regex: &Regex,
        mapping: Option<&Mapping>,
    ) -> bool {
        regex.is_match(&method.method)
            || mapping.is_some_and(|mapping| {
                mapping
                    .methods(&method.class, &method.method, &method.descriptor)
                    .any(|alias| regex.is_match(alias.name))
            })
    }

    fn field_name_matches(field: &FieldLocation, query: &str, mapping: Option<&Mapping>) -> bool {
        field.field == query
            || mapping.is_some_and(|mapping| {
                mapping
                    .fields(&field.class, &field.field, &field.descriptor)
                    .any(|alias| alias.name == query)
            })
    }

    fn field_name_regex_matches(
        field: &FieldLocation,
        regex: &Regex,
        mapping: Option<&Mapping>,
    ) -> bool {
        regex.is_match(&field.field)
            || mapping.is_some_and(|mapping| {
                mapping
                    .fields(&field.class, &field.field, &field.descriptor)
                    .any(|alias| regex.is_match(alias.name))
            })
    }

    fn inheritors<'a>(
        index: &'a DexIndex,
        query: &JavaClass,
        mapping: Option<&Mapping>,
    ) -> HashSet<&'a str> {
        let mut children = HashMap::<&str, Vec<&str>>::new();

        for class in &index.classes {
            if let Some(parent) = class.superclass.as_deref() {
                children.entry(parent).or_default().push(&class.class);
            }

            for parent in &class.interfaces {
                children.entry(parent).or_default().push(&class.class);
            }
        }

        let mut pending = children
            .keys()
            .filter(|name| Self::class_matches(name, query, mapping))
            .copied()
            .collect::<VecDeque<_>>();
        let mut matches = HashSet::new();

        while let Some(parent) = pending.pop_front() {
            for &child in children.get(parent).into_iter().flatten() {
                if matches.insert(child) {
                    pending.push_back(child);
                }
            }
        }

        matches
    }

    fn push_aliases(
        output: &mut Vec<Symbol>,
        dex: &str,
        kind: char,
        symbol: String,
        originals: Vec<String>,
        source: Option<&str>,
    ) {
        if originals.is_empty() {
            output.push(Symbol {
                dex: dex.to_owned(),
                kind,
                symbol,
                original: None,
                source: source.map(str::to_owned),
            });
        } else {
            for original in originals {
                output.push(Symbol {
                    dex: dex.to_owned(),
                    kind,
                    symbol: symbol.clone(),
                    original: Some(original),
                    source: source.map(str::to_owned),
                });
            }
        }
    }
}

pub(super) struct LocatedTarget<'a> {
    pub dex: String,
    pub class: String,
    pub method: Option<(String, String)>,
    pub bytes: Cow<'a, [u8]>,
}

impl<'a> LocatedTarget<'a> {
    pub(super) fn from_class(
        prepared: &'a ApkArchive,
        query: &JavaClass,
        selected: Option<&str>,
        mapping: Option<&Mapping>,
    ) -> Result<Self, String> {
        let mut descriptors = vec![query.descriptor()];

        if let Some(mapping) = mapping {
            descriptors.extend(mapping.obfuscated_classes(query.descriptor()));
        }

        descriptors.sort_unstable();
        descriptors.dedup();

        let mut matches = Vec::new();
        let mut target_bytes = None;

        prepared.visit_dex(selected, &mut |label, bytes| {
            let dex = Dex::parse(bytes)?;

            let found = Self::find_classes(&dex, &descriptors)?;

            for descriptor in &found {
                matches.push((label.to_owned(), descriptor.clone()));
            }

            if !found.is_empty() && target_bytes.is_none() {
                target_bytes = Some(dex.into_bytes());
            }

            Ok(())
        })?;

        match matches.len() {
            0 => Err(format!("class {query} was not found")),
            1 => {
                let (dex, class) = matches.remove(0);
                Ok(LocatedTarget {
                    dex,
                    class,
                    method: None,
                    bytes: target_bytes.ok_or("selected DEX disappeared")?,
                })
            }
            _ => Err(format!(
                "class {query} is ambiguous:\n{}\nselect one with --dex",
                matches
                    .iter()
                    .map(|(label, _)| format!("  {label}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
        }
    }

    fn find_classes(dex: &Dex<'_>, descriptors: &[&str]) -> Result<Vec<String>, String> {
        let strings = dex.strings();
        let types = dex.types();
        let classes = dex.classes();
        let mut matches = Vec::new();

        for index in 0..classes.len() {
            let class = classes.get(index)?;
            let ty = types.get(class.class_index())?;
            let descriptor = strings.get(ty.descriptor_index())?.value()?;

            if descriptors.contains(&descriptor.as_ref())
                && !matches.iter().any(|item| item == &descriptor)
            {
                matches.push(descriptor.into_owned());
            }
        }

        Ok(matches)
    }

    pub(super) fn from_method(
        prepared: &'a ApkArchive,
        query: &JavaMethod,
        selected: Option<&str>,
        mapping: Option<&Mapping>,
    ) -> Result<Self, String> {
        let mut descriptors = vec![query.class().descriptor()];

        if let Some(mapping) = mapping {
            descriptors.extend(mapping.obfuscated_classes(query.class().descriptor()));
        }

        let mut matches = Vec::new();
        let mut target_bytes = None;

        prepared.visit_dex(selected, &mut |label, bytes| {
            let dex = Dex::parse(bytes)?;

            if Self::find_classes(&dex, &descriptors)?.is_empty() {
                return Ok(());
            }

            let mut index = DexIndex {
                classes: Vec::new(),
                locations: Vec::new(),
                fields: Vec::new(),
            };

            parse::parse_dex(Cow::Borrowed(dex.bytes()), label, None, &mut index)?;

            let found = index
                .locations
                .into_iter()
                .filter(|method| {
                    Query::method_matches(
                        query,
                        &method.class,
                        &method.method,
                        &method.descriptor,
                        mapping,
                    )
                })
                .collect::<Vec<_>>();

            if !found.is_empty() && target_bytes.is_none() {
                target_bytes = Some(dex.into_bytes());
            }

            matches.extend(found);

            Ok(())
        })?;

        match matches.len() {
            0 => Err(format!("method {query} was not found")),
            1 => {
                let method = matches.remove(0);
                Ok(LocatedTarget {
                    dex: method.dex,
                    class: method.class,
                    method: Some((method.method, method.descriptor)),
                    bytes: target_bytes.ok_or("selected DEX disappeared")?,
                })
            }
            _ => {
                let candidates = matches
                    .iter()
                    .map(|method| {
                        JavaMethod::from_parts(&method.class, &method.method, &method.descriptor)
                            .map(|symbol| format!("  {}  {symbol}", method.dex))
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join("\n");

                Err(format!(
                    "method {query} is ambiguous:\n{candidates}\nuse a full signature or select one with --dex"
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::{ClassLocation, FieldLocation, MethodLocation};

    #[test]
    fn dex_selection_preserves_cross_dex_inheritance() {
        let class = |dex: &str, name: &str, parent: &str| ClassLocation {
            dex: dex.to_owned(),
            class: name.to_owned(),
            superclass: Some(parent.to_owned()),
            interfaces: Vec::new(),
            source_file: None,
        };
        let index = DexIndex {
            classes: vec![
                class("classes.dex", "LIntermediate;", "LBase;"),
                class("classes2.dex", "LChild;", "LIntermediate;"),
            ],
            fields: Vec::new(),
            locations: Vec::new(),
        };
        let base: JavaClass = "Base".parse().unwrap();
        let query = Query::Classes {
            name: None,
            name_regex: None,
            inherits: Some(&base),
        };
        let rows = query.select(&index, None, Some("classes2.dex")).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].symbol, "Child");
    }

    #[test]
    fn matches_class_regex_against_java_names() {
        let package = Regex::new(r"^com\.example\.").unwrap();
        let simple_name = Regex::new(r"MainActivity$").unwrap();

        assert!(
            Query::class_filters_match("Lcom/example/MainActivity;", None, Some(&package), None)
                .unwrap()
        );
        assert!(
            Query::class_filters_match(
                "Lcom/example/MainActivity;",
                None,
                Some(&simple_name),
                None
            )
            .unwrap()
        );
    }

    #[test]
    fn matches_member_regex_against_original_names() {
        let mapping = Mapping::parse(
            "com.example.Type -> a.b:\n    int originalField -> c\n    void originalMethod() -> d\n",
        )
        .unwrap();
        let field = FieldLocation {
            dex: String::new(),
            class: "La/b;".to_owned(),
            field: "c".to_owned(),
            descriptor: "I".to_owned(),
            source_file: None,
        };
        let method = MethodLocation {
            dex: String::new(),
            class: "La/b;".to_owned(),
            method: "d".to_owned(),
            descriptor: "()V".to_owned(),
            source_file: None,
        };

        assert!(Query::field_name_regex_matches(
            &field,
            &Regex::new("^originalField$").unwrap(),
            Some(&mapping)
        ));
        assert!(Query::method_name_regex_matches(
            &method,
            &Regex::new("^originalMethod$").unwrap(),
            Some(&mapping)
        ));
        assert!(Query::method_matches(
            &"com.example.Type#originalMethod():void".parse().unwrap(),
            &method.class,
            &method.method,
            &method.descriptor,
            Some(&mapping)
        ));
        assert!(Query::method_matches(
            &"a.b#d():void".parse().unwrap(),
            &method.class,
            &method.method,
            &method.descriptor,
            Some(&mapping)
        ));
    }
}

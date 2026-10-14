#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use apkq::dex::mapping::{self, Mapping};
use apkq::dex::{self, DexIndex, ReferenceFilter};
use apkq::java::{JavaClass, JavaField, JavaMethod, JavaType};
use apkq::resource::{self, Query};
use clap::{Parser, Subcommand};
use regex::Regex;

mod output;

use output::{Row, print_output, print_resources, push_aliases};

#[derive(Parser)]
#[command(
    name = "apkq",
    about = "Query Android APKs directly",
    after_help = r#"Examples:
  apkq app.apk c --name com.example.MainActivity
  apkq app.apk f --class com.example.Config --name apiKey
  apkq app.apk m --uses-string token
  apkq app.apk r --type string --value 'Login failed'
  apkq app.apk r --type layout --uses-resource string/login_failed
  apkq app.apk --mapping 'mapping.zip!path/to/mapping.txt' --json m --name originalMethod

Input: an APK; embedded APKs are searched recursively.
Output: TSV by default; --json and --aligned are available. Timing and count go to stderr. Code rows contain DEX, TYPE (C/F/M), SYMBOL, optional ORIGINAL, and SOURCE. Resource rows contain nested ARCHIVE, ID, TYPE, NAME, CONFIG, VALUE, PATH, and USAGE.
Mapping: --mapping accepts a file or 'archive.zip!entry'. Code queries use R8/ProGuard mappings; resource queries use AndResGuard mappings.
Search covers DEX definitions and references, compiled resource values, and XML attributes.
Run 'apkq <apk> <command> --help' for query syntax."#
)]
struct Cli {
    /// APK file to search
    input: PathBuf,
    /// Mapping file, or ZIP entry as archive.zip!path/to/mapping.txt
    #[arg(long, global = true, value_name = "FILE[!ENTRY]")]
    mapping: Option<String>,
    /// Emit a JSON array instead of TSV
    #[arg(long, global = true)]
    json: bool,
    /// Align text columns instead of TSV
    #[arg(long, global = true, conflicts_with = "json")]
    aligned: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find Android resources and references in compiled XML
    #[command(
        visible_alias = "r",
        after_help = r#"Resources are read from resources.arsc in each APK, including embedded APKs. IDs are scoped to their containing APK.
--type limits returned resource types, for example string, id, or layout. --name is exact; --name-contains and --value are case-sensitive substrings. --value-regex uses Rust regex syntax. Filters are ANDed.
--uses-resource finds resources that directly reference an ID in their table value or compiled XML attributes. Give a numeric ID (0x7f...), type/name, or package:type/name. USAGE identifies the table value or XML view ID and attribute.

Examples:
  apkq app.apk r --type string --value 'Login failed'
  apkq app.apk r --type string --value-regex 'login|sign.?in'
  apkq app.apk r --type id --name-contains button
  apkq app.apk r --type layout --name activity_login
  apkq app.apk r --id 0x7f0a0012
  apkq app.apk r --type layout --uses-resource string/login_failed
  apkq app.apk --json r --type layout --uses-resource 0x7f0a0012"#
    )]
    Resources {
        /// Exact resource type, such as string, id, or layout
        #[arg(long = "type", value_parser = non_empty)]
        kind: Option<String>,
        /// Exact resource entry name
        #[arg(long, value_parser = non_empty)]
        name: Option<String>,
        /// Case-sensitive resource name substring
        #[arg(long, value_parser = non_empty)]
        name_contains: Option<String>,
        /// Numeric resource ID, decimal or 0x-prefixed hexadecimal
        #[arg(long, value_parser = resource::parse_id)]
        id: Option<u32>,
        /// Case-sensitive substring of decoded resource value
        #[arg(long, value_parser = non_empty)]
        value: Option<String>,
        /// Regex for decoded resource value
        #[arg(long, value_parser = non_empty)]
        value_regex: Option<String>,
        /// Referenced ID, type/name, or package:type/name
        #[arg(long, value_parser = resource::validate_reference)]
        uses_resource: Option<String>,
    },
    /// Find class definitions
    #[command(
        visible_alias = "c",
        after_help = r#"With no filters, list all classes. Use full dotted names, not DEX descriptors.
--name is exact; use a trailing dot in --name-prefix for a package.
--inherits finds direct and transitive subclasses and implementors; the base class is excluded.
Filters are ANDed. With --mapping, class filters also match original names.

Examples:
  apkq app.apk c --name com.example.MainActivity
  apkq app.apk c --name-prefix com.example.
  apkq app.apk c --simple-name MainActivity
  apkq app.apk c --inherits android.app.Activity
  apkq app.apk --mapping mapping.txt c --inherits com.example.ItemBase"#
    )]
    Classes {
        /// Exact class name
        #[arg(long)]
        name: Option<JavaClass>,
        #[arg(
            long = "name-prefix",
            value_parser = parse_class_prefix,
            help = "Class name prefix, such as com.example."
        )]
        name_prefix: Option<String>,
        /// Exact class name without its package, such as MainActivity
        #[arg(long, value_parser = parse_simple_name)]
        simple_name: Option<String>,
        /// Direct or transitive subclasses and implementors
        #[arg(long)]
        inherits: Option<JavaClass>,
    },
    /// Find field definitions
    #[command(
        visible_alias = "f",
        after_help = r#"With no filters, list all fields. --class takes a full dotted class name; --name matches an exact field name. Both filters are ANDed.
With --mapping, filters also match original class and field names.

Examples:
  apkq app.apk f --class com.example.Config --name apiKey
  apkq app.apk --json f --name apiKey
  apkq app.apk --mapping mapping.txt f --name originalField"#
    )]
    Fields {
        /// Exact declaring class name
        #[arg(long)]
        class: Option<JavaClass>,
        /// Exact field name
        #[arg(long)]
        name: Option<String>,
    },
    /// Find method definitions; repeated reference filters are ANDed within one method
    #[command(
        visible_alias = "m",
        after_help = r#"With no filters, list all methods. --class takes a full dotted class name; --name is exact; --has-field requires a field declared in that class.
All filters are ANDed. Repeated reference options require references within the same method.
--uses-string matches case-sensitive substrings, including reads of initialized static string fields.
--calls Class#name matches any overload; add (parameters):returnType for an exact signature.
--uses-field Class#name matches any type; add :type to specify one.
Types use Java syntax: int, java.lang.String[], etc.
With --mapping, class/member filters also match original names.
Calls match explicit DEX invoke instructions.

Examples:
  apkq app.apk m --name onCreate
  apkq app.apk m --class com.example.MainActivity --has-field apiKey
  apkq app.apk m --uses-string token --uses-string secret
  apkq app.apk m --calls 'com.example.Client#send'
  apkq app.apk m --calls 'com.example.Client#send(int):void'
  apkq app.apk m --uses-field 'com.example.Config#key'
  apkq app.apk m --uses-field 'com.example.Config#key:java.lang.String'
  apkq app.apk m --uses-string token --uses-type java.lang.String
  apkq app.apk --mapping mapping.txt m --calls 'com.example.Client#send'"#
    )]
    Methods {
        /// Exact declaring class name
        #[arg(long)]
        class: Option<JavaClass>,
        /// Exact method name
        #[arg(long)]
        name: Option<String>,
        /// Keep methods declared in classes with a field of this name
        #[arg(long)]
        has_field: Option<String>,
        /// Referenced string fragment, including initialized static string fields
        #[arg(long = "uses-string", alias = "string", value_parser = non_empty)]
        strings: Vec<String>,
        /// Called method: Class#name or Class#name(parameters):returnType
        #[arg(long = "calls")]
        calls: Vec<JavaMethod>,
        /// Referenced type, such as java.lang.String
        #[arg(long = "uses-type")]
        types: Vec<JavaType>,
        /// Accessed field: Class#name or Class#name:type
        #[arg(long = "uses-field")]
        fields: Vec<JavaField>,
    },
}

pub(super) fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    if let Command::Resources {
        kind,
        name,
        name_contains,
        id,
        value,
        value_regex,
        uses_resource,
    } = &cli.command
    {
        let mapping = cli
            .mapping
            .as_deref()
            .map(resource::mapping::load)
            .transpose()?;

        return run_resources(
            &cli.input,
            Query {
                mapping: mapping.as_ref(),
                kind: kind.as_deref(),
                name: name.as_deref(),
                name_contains: name_contains.as_deref(),
                id: *id,
                value: value.as_deref(),
                value_regex: value_regex
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .map_err(|error| error.to_string())?
                    .as_ref(),
                uses_resource: uses_resource.as_deref(),
            },
            cli.json,
            cli.aligned,
        );
    }

    let apk = validate_apk(&cli.input)?;
    let mapping = cli.mapping.as_deref().map(mapping::load).transpose()?;
    let mut output = Vec::new();
    let started = Instant::now();

    let filter = match &cli.command {
        Command::Methods {
            strings,
            calls,
            types,
            fields,
            ..
        } if !strings.is_empty()
            || !calls.is_empty()
            || !types.is_empty()
            || !fields.is_empty() =>
        {
            Some(ReferenceFilter {
                strings,
                calls,
                types,
                fields,
                mapping: mapping.as_ref(),
            })
        }
        _ => None,
    };
    let index = dex::index_apk(&apk, filter.as_ref())?;

    match &cli.command {
        Command::Classes {
            name,
            name_prefix,
            simple_name,
            inherits,
            ..
        } => {
            let descendants = inherits
                .as_ref()
                .map(|parent| inheritors(&index, parent, mapping.as_ref()));

            for class in &index.classes {
                if !class_filters_match(
                    &class.class,
                    name.as_ref(),
                    name_prefix.as_deref(),
                    simple_name.as_deref(),
                    mapping.as_ref(),
                ) || descendants
                    .as_ref()
                    .is_some_and(|descendants| !descendants.contains(class.class.as_str()))
                {
                    continue;
                }

                output.push(Row {
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
        Command::Fields { class, name, .. } => {
            for field in &index.fields {
                if class
                    .as_ref()
                    .is_some_and(|class| !class_matches(&field.class, class, mapping.as_ref()))
                    || name
                        .as_deref()
                        .is_some_and(|name| !field_name_matches(field, name, mapping.as_ref()))
                {
                    continue;
                }

                let symbol =
                    JavaField::from_descriptor(&field.class, &field.field, &field.descriptor)?
                        .to_string();
                let originals = mapping
                    .as_ref()
                    .map(|mapping| {
                        mapping
                            .fields(&field.class, &field.field, &field.descriptor)
                            .iter()
                            .filter_map(|alias| {
                                mapping.original_class(&field.class).map(|owner| {
                                    JavaField::from_descriptor(
                                        owner,
                                        &alias.name,
                                        &alias.descriptor,
                                    )
                                    .map(|field| field.to_string())
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();

                push_aliases(
                    &mut output,
                    &field.dex,
                    'F',
                    symbol,
                    originals,
                    field.source_file.as_deref(),
                );
            }
        }
        Command::Methods {
            class,
            name,
            has_field,
            ..
        } => {
            let field_classes = has_field.as_deref().map(|name| {
                index
                    .fields
                    .iter()
                    .filter(|field| field_name_matches(field, name, mapping.as_ref()))
                    .map(|field| field.class.as_str())
                    .collect::<HashSet<_>>()
            });

            for method in &index.locations {
                if class
                    .as_ref()
                    .is_some_and(|class| !class_matches(&method.class, class, mapping.as_ref()))
                    || name
                        .as_deref()
                        .is_some_and(|name| !method_name_matches(method, name, mapping.as_ref()))
                    || field_classes
                        .as_ref()
                        .is_some_and(|classes| !classes.contains(method.class.as_str()))
                {
                    continue;
                }

                let symbol =
                    JavaMethod::from_descriptor(&method.class, &method.method, &method.descriptor)?
                        .to_string();
                let originals = mapping
                    .as_ref()
                    .map(|mapping| {
                        mapping
                            .methods(&method.class, &method.method, &method.descriptor)
                            .iter()
                            .filter_map(|alias| {
                                mapping.original_class(&method.class).map(|owner| {
                                    JavaMethod::from_descriptor(
                                        owner,
                                        &alias.name,
                                        &alias.descriptor,
                                    )
                                    .map(|method| method.to_string())
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();

                push_aliases(
                    &mut output,
                    &method.dex,
                    'M',
                    symbol,
                    originals,
                    method.source_file.as_deref(),
                );
            }
        }
        Command::Resources { .. } => unreachable!(),
    }

    output.sort();
    output.dedup();

    print_output(&output, cli.json, cli.aligned, cli.mapping.is_some())?;

    eprintln!(
        "searched in {:.3}s; {} match(es)",
        started.elapsed().as_secs_f64(),
        output.len()
    );

    Ok(())
}

fn run_resources(input: &Path, query: Query<'_>, json: bool, aligned: bool) -> Result<(), String> {
    let apk = validate_apk(input)?;
    let started = Instant::now();
    let mut rows = resource::index_apk(&apk, &query)?;

    rows.sort();
    rows.dedup();
    print_resources(&rows, json, aligned)?;

    eprintln!(
        "searched in {:.3}s; {} match(es)",
        started.elapsed().as_secs_f64(),
        rows.len()
    );
    Ok(())
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
    name_prefix: Option<&str>,
    simple_name: Option<&str>,
    mapping: Option<&Mapping>,
) -> bool {
    let original = mapping.and_then(|mapping| mapping.original_class(descriptor));
    let names = [Some(descriptor), original];

    name.is_none_or(|query| {
        names
            .iter()
            .flatten()
            .any(|name| *name == query.descriptor())
    }) && name_prefix
        .is_none_or(|prefix| names.iter().flatten().any(|name| name.starts_with(prefix)))
        && simple_name.is_none_or(|simple| {
            names
                .iter()
                .flatten()
                .filter_map(|name| descriptor_simple_name(name))
                .any(|name| name == simple)
        })
}

fn method_name_matches(
    method: &dex::MethodLocation,
    query: &str,
    mapping: Option<&Mapping>,
) -> bool {
    method.method == query
        || mapping.is_some_and(|mapping| {
            mapping
                .methods(&method.class, &method.method, &method.descriptor)
                .iter()
                .any(|alias| alias.name == query)
        })
}

fn field_name_matches(field: &dex::FieldLocation, query: &str, mapping: Option<&Mapping>) -> bool {
    field.field == query
        || mapping.is_some_and(|mapping| {
            mapping
                .fields(&field.class, &field.field, &field.descriptor)
                .iter()
                .any(|alias| alias.name == query)
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
        .filter(|name| class_matches(name, query, mapping))
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

fn non_empty(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("query value cannot be empty".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn parse_class_prefix(value: &str) -> Result<String, String> {
    let stem = value.strip_suffix('.').unwrap_or(value);
    if !valid_dotted_name(stem) {
        return Err(format!("invalid dotted class prefix: {value}"));
    }

    Ok(format!("L{}", value.replace('.', "/")))
}

fn parse_simple_name(value: &str) -> Result<String, String> {
    if value.contains('.') || !valid_name_part(value) {
        return Err(format!("invalid simple class name: {value}"));
    }

    Ok(value.to_owned())
}

fn descriptor_simple_name(descriptor: &str) -> Option<&str> {
    descriptor
        .strip_prefix('L')?
        .strip_suffix(';')?
        .rsplit('/')
        .next()
}

fn valid_dotted_name(value: &str) -> bool {
    value.split('.').all(valid_name_part)
}

fn valid_name_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | '$'))
}

fn validate_apk(input: &Path) -> Result<PathBuf, String> {
    if !input.is_file()
        || !input
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
    {
        return Err(format!("input is not an APK file: {}", input.display()));
    }

    Ok(input.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn accepts_short_command_aliases_and_combined_filters() {
        let cli =
            Cli::try_parse_from(["apkq", "app.apk", "--mapping", "mapping.txt", "--json", "m"])
                .unwrap();
        assert!(cli.mapping.is_some() && cli.json);
        assert!(Cli::try_parse_from(["apkq", "app.apk", "r", "--aligned"]).is_ok());

        assert!(matches!(
            Cli::try_parse_from(["apkq", "app.apk", "c", "--inherits", "com.example.Base"])
                .unwrap()
                .command,
            Command::Classes { .. }
        ));
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "c", "--simple-name", "MainActivity"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "c", "--simple-name", "com.example.Main"])
                .is_err()
        );
        assert!(matches!(
            Cli::try_parse_from(["apkq", "app.apk", "f", "--name", "apiKey"])
                .unwrap()
                .command,
            Command::Fields { .. }
        ));
        let cli = Cli::try_parse_from([
            "apkq",
            "app.apk",
            "m",
            "--uses-string",
            "a",
            "--uses-string",
            "b",
            "--uses-type",
            "com.example.Type",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Command::Methods { strings, types, .. } if strings.len() == 2 && types.len() == 1)
        );
        assert!(Cli::try_parse_from(["apkq", "app.apk", "m", "--string", "legacy"]).is_ok());
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "m", "--calls", "com.example.Client#send"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["apkq", "app.apk", "c", "--inherits", "LBase;"]).is_err());
        assert!(matches!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "r",
                "--type",
                "layout",
                "--uses-resource",
                "id/title"
            ])
            .unwrap()
            .command,
            Command::Resources {
                kind: Some(_),
                uses_resource: Some(_),
                ..
            }
        ));
        assert!(Cli::try_parse_from(["apkq", "app.apk", "r", "--id", "0x7f0a0012"]).is_ok());
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "r", "--uses-resource", "broken"]).is_err()
        );
    }
}

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use dexq::dex::{self, DexIndex, ReferenceFilter};
use dexq::mapping::{self, Mapping};
use dexq::query::{self, CallQuery, FieldQuery};

mod output;

use output::{Row, print_output, push_aliases};

#[derive(Parser)]
#[command(
    name = "dexq",
    about = "Query Android APKs directly",
    after_help = r#"Examples:
  dexq c app.apk --name com.example.MainActivity
  dexq f app.apk --class com.example.Config --name apiKey
  dexq m app.apk --uses-string token
  dexq m ./apks --mapping 'mapping.zip!path/to/mapping.txt' --json

Input: an APK or a directory searched recursively for APKs; nested APKs are searched too. Standalone DEX, JAR and AAR files are unsupported.
Output: TSV by default; --json and --aligned are available. Timing and count go to stderr. Columns: APK path, DEX entry, TYPE (C/F/M), DEX DESCRIPTOR, ORIGINAL mapped name, SOURCE file.
Mapping: --mapping mapping.txt or --mapping 'mapping.zip!path/to/mapping.txt'. Mapped class/member names can be used in queries and appear in output.
Scope: DEX definitions and explicit code references; no decompilation, reflection or runtime-generated strings.
Run 'dexq <command> --help' for query syntax."#
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Common {
    /// R8/ProGuard mapping file, or ZIP entry as archive.zip!path/to/mapping.txt
    #[arg(long, value_name = "FILE[!ENTRY]")]
    mapping: Option<String>,
    /// Emit a JSON array instead of TSV
    #[arg(long)]
    json: bool,
    /// Align text columns instead of TSV
    #[arg(long, conflicts_with = "json")]
    aligned: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Find class definitions
    #[command(
        visible_alias = "c",
        after_help = r#"With no filters, list all classes. Use full dotted names, not DEX descriptors.
--name is exact; use a trailing dot in --name-prefix for a package.
--inherits finds direct and transitive subclasses and implementors; the base class is excluded.
Filters are ANDed. With --mapping, class filters also match original names.

Examples:
  dexq c app.apk --name com.example.MainActivity
  dexq c app.apk --name-prefix com.example.
  dexq c app.apk --inherits android.app.Activity
  dexq c app.apk --mapping mapping.txt --inherits com.example.ItemBase"#
    )]
    Classes {
        /// APK file or directory to search recursively
        input: PathBuf,
        /// Exact class name
        #[arg(long, value_parser = query::parse_class)]
        name: Option<String>,
        #[arg(
            long = "name-prefix",
            value_parser = query::parse_class_prefix,
            help = "Class name prefix, such as com.example."
        )]
        name_prefix: Option<String>,
        /// Direct or transitive subclasses and implementors
        #[arg(long, value_parser = query::parse_class)]
        inherits: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Find field definitions
    #[command(
        visible_alias = "f",
        after_help = r#"With no filters, list all fields. --class takes a full dotted class name; --name matches an exact field name. Both filters are ANDed.
With --mapping, filters also match original class and field names.

Examples:
  dexq f app.apk --class com.example.Config --name apiKey
  dexq f ./apks --name apiKey --json
  dexq f app.apk --mapping mapping.txt --name originalField"#
    )]
    Fields {
        /// APK file or directory to search recursively
        input: PathBuf,
        /// Exact declaring class name
        #[arg(long, value_parser = query::parse_class)]
        class: Option<String>,
        /// Exact field name
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        common: Common,
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
Calls are explicit DEX invokes, not reflection or runtime dispatch targets.

Examples:
  dexq m app.apk --name onCreate
  dexq m app.apk --class com.example.MainActivity --has-field apiKey
  dexq m app.apk --uses-string token --uses-string secret
  dexq m app.apk --calls 'com.example.Client#send'
  dexq m app.apk --calls 'com.example.Client#send(int):void'
  dexq m app.apk --uses-field 'com.example.Config#key'
  dexq m app.apk --uses-field 'com.example.Config#key:java.lang.String'
  dexq m app.apk --uses-string token --uses-type java.lang.String
  dexq m app.apk --mapping mapping.txt --calls 'com.example.Client#send'"#
    )]
    Methods {
        /// APK file or directory to search recursively
        input: PathBuf,
        /// Exact declaring class name
        #[arg(long, value_parser = query::parse_class)]
        class: Option<String>,
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
        #[arg(long = "calls", value_parser = query::parse_call_query)]
        calls: Vec<CallQuery>,
        /// Referenced type, such as java.lang.String
        #[arg(long = "uses-type", value_parser = query::parse_type)]
        types: Vec<String>,
        /// Accessed field: Class#name or Class#name:type
        #[arg(long = "uses-field", value_parser = query::parse_field_query)]
        fields: Vec<FieldQuery>,
        #[command(flatten)]
        common: Common,
    },
}

pub(super) fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let (input, common) = match &cli.command {
        Command::Classes { input, common, .. }
        | Command::Fields { input, common, .. }
        | Command::Methods { input, common, .. } => (input, common),
    };

    let apks = collect_apks(input)?;
    let mapping = common.mapping.as_deref().map(mapping::load).transpose()?;
    let mut output = Vec::new();
    let started = Instant::now();

    for apk in apks {
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
        let apk_name = apk.to_string_lossy();

        match &cli.command {
            Command::Classes {
                name,
                name_prefix,
                inherits,
                ..
            } => {
                let descendants = inherits
                    .as_deref()
                    .map(|parent| inheritors(&index, parent, mapping.as_ref()));

                for class in &index.classes {
                    if name
                        .as_deref()
                        .is_some_and(|name| !class_matches(&class.class, name, mapping.as_ref()))
                        || name_prefix.as_deref().is_some_and(|prefix| {
                            !class.class.starts_with(prefix)
                                && !mapping
                                    .as_ref()
                                    .and_then(|mapping| mapping.original_class(&class.class))
                                    .is_some_and(|name| name.starts_with(prefix))
                        })
                        || descendants
                            .as_ref()
                            .is_some_and(|descendants| !descendants.contains(class.class.as_str()))
                    {
                        continue;
                    }

                    output.push(Row {
                        apk: apk_name.to_string(),
                        dex: class.dex.clone(),
                        kind: 'C',
                        descriptor: class.class.clone(),
                        original: mapping
                            .as_ref()
                            .and_then(|mapping| mapping.original_class(&class.class))
                            .map(str::to_owned),
                        source: class.source_file.clone(),
                    });
                }
            }
            Command::Fields { class, name, .. } => {
                for field in &index.fields {
                    if class
                        .as_deref()
                        .is_some_and(|class| !class_matches(&field.class, class, mapping.as_ref()))
                        || name
                            .as_deref()
                            .is_some_and(|name| !field_name_matches(field, name, mapping.as_ref()))
                    {
                        continue;
                    }

                    let descriptor =
                        format!("{}->{}:{}", field.class, field.field, field.descriptor);
                    let originals = mapping
                        .as_ref()
                        .map(|mapping| {
                            mapping
                                .fields(&field.class, &field.field, &field.descriptor)
                                .iter()
                                .filter_map(|alias| {
                                    mapping.original_class(&field.class).map(|owner| {
                                        format!("{owner}->{}:{}", alias.name, alias.descriptor)
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    push_aliases(
                        &mut output,
                        &apk_name,
                        &field.dex,
                        'F',
                        descriptor,
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
                        .as_deref()
                        .is_some_and(|class| !class_matches(&method.class, class, mapping.as_ref()))
                        || name.as_deref().is_some_and(|name| {
                            !method_name_matches(method, name, mapping.as_ref())
                        })
                        || field_classes
                            .as_ref()
                            .is_some_and(|classes| !classes.contains(method.class.as_str()))
                    {
                        continue;
                    }

                    let descriptor =
                        format!("{}->{}{}", method.class, method.method, method.descriptor);
                    let originals = mapping
                        .as_ref()
                        .map(|mapping| {
                            mapping
                                .methods(&method.class, &method.method, &method.descriptor)
                                .iter()
                                .filter_map(|alias| {
                                    mapping.original_class(&method.class).map(|owner| {
                                        format!("{owner}->{}{}", alias.name, alias.descriptor)
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    push_aliases(
                        &mut output,
                        &apk_name,
                        &method.dex,
                        'M',
                        descriptor,
                        originals,
                        method.source_file.as_deref(),
                    );
                }
            }
        }
    }

    output.sort();
    output.dedup();

    print_output(&output, common.json, common.aligned)?;

    eprintln!(
        "searched in {:.3}s; {} match(es)",
        started.elapsed().as_secs_f64(),
        output.len()
    );

    Ok(())
}

fn class_matches(descriptor: &str, query: &str, mapping: Option<&Mapping>) -> bool {
    descriptor == query
        || mapping
            .and_then(|mapping| mapping.original_class(descriptor))
            .is_some_and(|name| name == query)
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

fn inheritors<'a>(index: &'a DexIndex, query: &str, mapping: Option<&Mapping>) -> HashSet<&'a str> {
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

fn collect_apks(input: &Path) -> Result<Vec<PathBuf>, String> {
    if input.is_file() {
        if !input
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
        {
            return Err(format!("input is not an APK: {}", input.display()));
        }
        return Ok(vec![input.to_owned()]);
    }

    if !input.is_dir() {
        return Err(format!("input does not exist: {}", input.display()));
    }

    let mut directories = vec![input.to_owned()];
    let mut apks = Vec::new();

    while let Some(directory) = directories.pop() {
        for entry in
            fs::read_dir(&directory).map_err(|error| format!("{}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", entry.path().display()))?;

            if file_type.is_dir() {
                directories.push(entry.path());
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
            {
                apks.push(entry.path());
            }
        }
    }

    apks.sort();

    if apks.is_empty() {
        Err(format!("no APK files found in {}", input.display()))
    } else {
        Ok(apks)
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn accepts_short_command_aliases_and_combined_filters() {
        assert!(matches!(
            Cli::try_parse_from(["dexq", "c", "app.apk", "--inherits", "com.example.Base"])
                .unwrap()
                .command,
            Command::Classes { .. }
        ));
        assert!(matches!(
            Cli::try_parse_from(["dexq", "f", "app.apk", "--name", "apiKey"])
                .unwrap()
                .command,
            Command::Fields { .. }
        ));
        let cli = Cli::try_parse_from([
            "dexq",
            "m",
            "app.apk",
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
        assert!(Cli::try_parse_from(["dexq", "m", "app.apk", "--string", "legacy"]).is_ok());
        assert!(
            Cli::try_parse_from(["dexq", "m", "app.apk", "--calls", "com.example.Client#send"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["dexq", "c", "app.apk", "--inherits", "LBase;"]).is_err());
    }
}

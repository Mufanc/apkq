#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::{ArgGroup, Parser};
use dexq::cache::{self, DexIndexView};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "dexq",
    about = "Query classes, methods, fields, and referenced strings in Android APKs",
    group = ArgGroup::new("query")
        .required(true)
        .multiple(true)
        .args(["class", "method", "field", "strings"])
)]
struct Cli {
    /// APK file or a directory containing APK files
    input: PathBuf,

    /// Exact class name, dotted name, or DEX descriptor
    #[arg(short = 'c', long = "class", value_name = "NAME")]
    class: Option<String>,

    /// Exact method name
    #[arg(short = 'm', long = "method", value_name = "NAME")]
    method: Option<String>,

    /// Exact field name
    #[arg(short = 'f', long = "field", value_name = "NAME")]
    field: Option<String>,

    /// String fragment referenced by the same method; repeat for AND
    #[arg(
        short = 's',
        long = "string",
        value_name = "TEXT",
        value_parser = non_empty
    )]
    strings: Vec<String>,

    /// Emit a JSON array
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct OutputLocation {
    apk: String,
    dex: String,
    kind: char,
    location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let apk_paths = collect_apks(&cli.input)?;
    let strings = unique_strings(&cli.strings);
    let mut output = Vec::new();

    for apk in apk_paths {
        let cache_load = cache::load_or_build(&apk)?;
        let dex = cache_load.index.view()?;
        output.extend(query_apk(&apk, dex, &cli, &strings)?);
    }

    output.sort();
    output.dedup();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode JSON: {error}"))?
        );
    } else if output.is_empty() {
        println!("No matches.");
    } else {
        println!("APK/DEX\tKIND\tLOCATION\tSOURCE");
        for location in output {
            println!(
                "{}!{}\t{}\t{}\t{}",
                location.apk,
                location.dex,
                location.kind,
                location.location,
                location.source_file.as_deref().unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn query_apk(
    apk: &Path,
    dex: DexIndexView<'_>,
    cli: &Cli,
    strings: &[String],
) -> Result<Vec<OutputLocation>, String> {
    let apk = apk.display().to_string();
    let field_classes = cli
        .field
        .as_deref()
        .map(|field| matching_field_classes(dex, cli.class.as_deref(), field))
        .transpose()?;

    if cli.method.is_none() && strings.is_empty() {
        return if let Some(field) = cli.field.as_deref() {
            query_fields(&apk, dex, cli.class.as_deref(), field)
        } else {
            query_classes(
                &apk,
                dex,
                cli.class.as_deref().expect("clap requires a query"),
            )
        };
    }

    let mut method_ids = if strings.is_empty() {
        (0..dex.method_count()).collect::<HashSet<_>>()
    } else {
        methods_referencing_all(dex, strings)?
    };
    method_ids.retain(|&method_id| {
        let Ok(location) = dex.location(method_id) else {
            return false;
        };
        cli.method
            .as_deref()
            .is_none_or(|method| location.method == method)
            && cli
                .class
                .as_deref()
                .is_none_or(|class| class_matches(location.class, class))
            && field_classes
                .as_ref()
                .is_none_or(|classes| classes.contains(location.class))
    });

    method_ids
        .into_iter()
        .map(|method_id| {
            let location = dex.location(method_id)?;
            Ok(OutputLocation {
                apk: apk.clone(),
                dex: location.dex.to_owned(),
                kind: 'M',
                location: format!(
                    "{}->{}{}",
                    location.class, location.method, location.descriptor
                ),
                source_file: location.source_file.map(str::to_owned),
            })
        })
        .collect()
}

fn query_classes(
    apk: &str,
    dex: DexIndexView<'_>,
    class: &str,
) -> Result<Vec<OutputLocation>, String> {
    let mut output = Vec::new();
    for class_id in 0..dex.class_count() {
        let location = dex.class(class_id)?;
        if class_matches(location.class, class) {
            output.push(OutputLocation {
                apk: apk.to_owned(),
                dex: location.dex.to_owned(),
                kind: 'C',
                location: location.class.to_owned(),
                source_file: location.source_file.map(str::to_owned),
            });
        }
    }
    Ok(output)
}

fn query_fields(
    apk: &str,
    dex: DexIndexView<'_>,
    class: Option<&str>,
    field: &str,
) -> Result<Vec<OutputLocation>, String> {
    let mut output = Vec::new();
    for field_id in 0..dex.field_count() {
        let location = dex.field(field_id)?;
        if location.field == field && class.is_none_or(|class| class_matches(location.class, class))
        {
            output.push(OutputLocation {
                apk: apk.to_owned(),
                dex: location.dex.to_owned(),
                kind: 'F',
                location: format!(
                    "{}->{}:{}",
                    location.class, location.field, location.descriptor
                ),
                source_file: location.source_file.map(str::to_owned),
            });
        }
    }
    Ok(output)
}

fn matching_field_classes(
    dex: DexIndexView<'_>,
    class: Option<&str>,
    field: &str,
) -> Result<HashSet<String>, String> {
    let mut classes = HashSet::new();
    for field_id in 0..dex.field_count() {
        let location = dex.field(field_id)?;
        if location.field == field && class.is_none_or(|class| class_matches(location.class, class))
        {
            classes.insert(location.class.to_owned());
        }
    }
    Ok(classes)
}

fn methods_referencing_all(
    dex: DexIndexView<'_>,
    strings: &[String],
) -> Result<HashSet<usize>, String> {
    let mut candidates: Option<HashSet<usize>> = None;
    for query in strings {
        let mut matches = HashSet::new();
        for string_id in 0..dex.string_count() {
            if dex.string_value(string_id)?.contains(query) {
                matches.extend(dex.string_sites(string_id)?.map(|site| site.location_id));
            }
        }
        match &mut candidates {
            Some(candidates) => candidates.retain(|method_id| matches.contains(method_id)),
            None => candidates = Some(matches),
        }
        if candidates.as_ref().is_some_and(HashSet::is_empty) {
            break;
        }
    }
    Ok(candidates.unwrap_or_default())
}

fn class_matches(descriptor: &str, query: &str) -> bool {
    if query.starts_with('L') && query.ends_with(';') {
        return descriptor == query;
    }
    let Some(name) = descriptor
        .strip_prefix('L')
        .and_then(|name| name.strip_suffix(';'))
    else {
        return descriptor == query;
    };
    if query.contains('.') {
        name.replace('/', ".") == query
    } else {
        name.rsplit('/').next() == Some(query)
    }
}

fn collect_apks(input: &Path) -> Result<Vec<PathBuf>, String> {
    if input.is_file() {
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

fn unique_strings(strings: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    strings
        .iter()
        .filter(|value| seen.insert((*value).clone()))
        .cloned()
        .collect()
}

fn non_empty(value: &str) -> Result<String, String> {
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or_else(|| "string query cannot be empty".to_owned())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, class_matches, unique_strings};

    #[test]
    fn parses_the_compact_query_syntax() {
        let cli = Cli::try_parse_from([
            "dexq",
            "app.apk",
            "-m",
            "someMethod",
            "-s",
            "A value is ",
            "-s",
            "B value is ",
            "--json",
        ])
        .unwrap();
        assert_eq!(cli.method.as_deref(), Some("someMethod"));
        assert_eq!(cli.strings, ["A value is ", "B value is "]);
        assert!(cli.json);
    }

    #[test]
    fn requires_at_least_one_query_condition() {
        assert!(Cli::try_parse_from(["dexq", "app.apk"]).is_err());
    }

    #[test]
    fn requires_equals_for_string_values_starting_with_a_hyphen() {
        let cli = Cli::try_parse_from(["dexq", "app.apk", "--string=-thread-"]).unwrap();
        assert_eq!(cli.strings, ["-thread-"]);
        assert!(Cli::try_parse_from(["dexq", "app.apk", "--string", "-thread-"]).is_err());
    }

    #[test]
    fn matches_simple_dotted_and_descriptor_class_names() {
        let descriptor = "Lcom/example/PlayerManager;";
        assert!(class_matches(descriptor, "PlayerManager"));
        assert!(class_matches(descriptor, "com.example.PlayerManager"));
        assert!(class_matches(descriptor, descriptor));
        assert!(!class_matches(descriptor, "OtherManager"));
    }

    #[test]
    fn requires_dollar_notation_for_inner_classes() {
        let descriptor = "Lcom/ut/mini/UTHitBuilders$UTHitBuilder;";
        assert!(class_matches(descriptor, "UTHitBuilders$UTHitBuilder"));
        assert!(class_matches(
            descriptor,
            "com.ut.mini.UTHitBuilders$UTHitBuilder"
        ));
        assert!(!class_matches(descriptor, "UTHitBuilder"));
        assert!(!class_matches(
            descriptor,
            "com.ut.mini.UTHitBuilders.UTHitBuilder"
        ));
        assert!(class_matches("Lcom/example/Outer$1$1;", "Outer$1$1"));
        assert!(class_matches(
            "Lcom/example/EglRenderer$$Lambda$1;",
            "EglRenderer$$Lambda$1"
        ));
    }

    #[test]
    fn repeated_string_conditions_are_deduplicated() {
        assert_eq!(
            unique_strings(&["A".to_owned(), "B".to_owned(), "A".to_owned()]),
            ["A", "B"]
        );
    }
}

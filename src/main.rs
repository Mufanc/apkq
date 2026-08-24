#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::{ArgGroup, Parser};
use dexq::cache::{self, DexIndexView};
use dexq::dex::{CalledMethodRef, ClassLocationRef, FieldLocationRef, MethodLocationRef};
use dexq::mapping::{self, Mapping};
use regex::Regex;
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "dexq",
    about = "Query classes, methods, fields, and referenced strings in Android APKs",
    group = ArgGroup::new("query")
        .required(true)
        .multiple(true)
        .args([
            "class",
            "method",
            "field",
            "strings",
            "regexes",
            "callers_of",
            "inherits"
        ])
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

    /// Regular expression matched against strings referenced by the same method; repeat for AND
    #[arg(
        short = 'r',
        long = "regex",
        value_name = "REGEX",
        value_parser = non_empty
    )]
    regexes: Vec<String>,

    /// Find methods that invoke NAME, CLASS->NAME, or CLASS->NAME(DESCRIPTOR)
    #[arg(
        long = "callers-of",
        value_name = "[CLASS->]NAME[(DESCRIPTOR)]",
        value_parser = parse_method_query,
        conflicts_with_all = ["class", "method", "field", "strings", "regexes", "inherits"]
    )]
    callers_of: Option<MethodQuery>,

    /// Find classes that directly or indirectly extend or implement CLASS
    #[arg(
        long,
        value_name = "CLASS",
        value_parser = non_empty,
        conflicts_with_all = ["class", "method", "field", "strings", "regexes", "callers_of"]
    )]
    inherits: Option<String>,

    /// Emit a JSON array
    #[arg(long)]
    json: bool,

    /// Align plain-text output columns with spaces
    #[arg(long, conflicts_with = "json")]
    aligned: bool,

    /// R8/ProGuard mapping file, or ZIP entry as archive.zip!path/to/mapping.txt
    #[arg(long, value_name = "FILE[!ENTRY]")]
    mapping: Option<String>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct OutputLocation {
    file: String,
    #[serde(rename = "type")]
    kind: char,
    location: String,
    source: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MethodQuery {
    class: Option<String>,
    method: String,
    descriptor: Option<String>,
}

enum StringMatcher {
    Literal(String),
    Regex(Regex),
}

impl StringMatcher {
    fn is_match(&self, value: &str) -> bool {
        match self {
            Self::Literal(literal) => value.contains(literal),
            Self::Regex(regex) => regex.is_match(value),
        }
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let strings = string_matchers(&cli.strings, &cli.regexes)?;
    let apk_paths = collect_apks(&cli.input)?;
    let mapping = cli.mapping.as_deref().map(mapping::load).transpose()?;
    let mut output = Vec::new();

    for apk in apk_paths {
        let cache_load = cache::load_or_build(&apk)?;
        let dex = cache_load.index.view()?;
        output.extend(query_apk(dex, &cli, &strings, mapping.as_ref())?);
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
    } else if cli.aligned {
        print_aligned(&output);
    } else {
        println!("FILE\tTYPE\tLOCATION\tSOURCE");
        for location in output {
            println!(
                "{}\t{}\t{}\t{}",
                location.file,
                location.kind,
                location.location,
                location.source.as_deref().unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn print_aligned(output: &[OutputLocation]) {
    let file_width = output
        .iter()
        .map(|location| location.file.chars().count())
        .max()
        .unwrap_or_default()
        .max("FILE".len());
    let location_width = output
        .iter()
        .map(|location| location.location.chars().count())
        .max()
        .unwrap_or_default()
        .max("LOCATION".len());

    println!(
        "{:<file_width$}  {:<4}  {:<location_width$}  SOURCE",
        "FILE", "TYPE", "LOCATION"
    );
    for location in output {
        println!(
            "{:<file_width$}  {:<4}  {:<location_width$}  {}",
            location.file,
            location.kind,
            location.location,
            location.source.as_deref().unwrap_or_default()
        );
    }
}

fn query_apk(
    dex: DexIndexView<'_>,
    cli: &Cli,
    strings: &[StringMatcher],
    mapping: Option<&Mapping>,
) -> Result<Vec<OutputLocation>, String> {
    if let Some(query) = &cli.callers_of {
        return query_callers(dex, query, mapping);
    }
    if let Some(class) = cli.inherits.as_deref() {
        return query_inheritors(dex, class, mapping);
    }

    let field_classes = cli
        .field
        .as_deref()
        .map(|field| matching_field_classes(dex, cli.class.as_deref(), field, mapping))
        .transpose()?;

    if cli.method.is_none() && strings.is_empty() {
        return if let Some(field) = cli.field.as_deref() {
            query_fields(dex, cli.class.as_deref(), field, mapping)
        } else {
            query_classes(
                dex,
                cli.class.as_deref().expect("clap requires a query"),
                mapping,
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
            .is_none_or(|method| method_matches(&location, method, mapping))
            && cli
                .class
                .as_deref()
                .is_none_or(|class| class_matches(location.class, class, mapping))
            && field_classes
                .as_ref()
                .is_none_or(|classes| classes.contains(location.class))
    });

    let mut output = Vec::new();
    for method_id in method_ids {
        output.extend(method_output(&dex.location(method_id)?, mapping));
    }
    Ok(output)
}

fn query_callers(
    dex: DexIndexView<'_>,
    query: &MethodQuery,
    mapping: Option<&Mapping>,
) -> Result<Vec<OutputLocation>, String> {
    let targets = if mapping.is_none() {
        dex.called_methods_named(&query.method)?
    } else {
        0..dex.called_method_count()
    };
    let mut callers = HashSet::new();
    for target_id in targets {
        let target = dex.called_method(target_id)?;
        if called_method_matches(&target, query, mapping) {
            callers.extend(dex.callers(target_id)?);
        }
    }
    let mut output = Vec::new();
    for caller in callers {
        output.extend(method_output(&dex.location(caller)?, mapping));
    }
    Ok(output)
}

fn query_inheritors(
    dex: DexIndexView<'_>,
    query: &str,
    mapping: Option<&Mapping>,
) -> Result<Vec<OutputLocation>, String> {
    let mut children = HashMap::<String, Vec<usize>>::new();
    let mut class_names = Vec::with_capacity(dex.class_count());
    for class_id in 0..dex.class_count() {
        let class = dex.class(class_id)?;
        class_names.push(class.class.to_owned());
        if let Some(superclass) = class.superclass {
            children
                .entry(superclass.to_owned())
                .or_default()
                .push(class_id);
        }
        for interface in dex.class_interfaces(class_id)? {
            children
                .entry(interface?.to_owned())
                .or_default()
                .push(class_id);
        }
    }

    let roots = children
        .keys()
        .filter(|class| class_matches(class, query, mapping))
        .cloned()
        .collect::<Vec<_>>();
    let matches = descendant_ids(&children, &class_names, roots);

    let mut output = Vec::new();
    for class_id in matches {
        output.push(class_output(&dex.class(class_id)?, mapping));
    }
    Ok(output)
}

fn descendant_ids(
    children: &HashMap<String, Vec<usize>>,
    classes: &[String],
    roots: impl IntoIterator<Item = String>,
) -> HashSet<usize> {
    let mut pending = roots.into_iter().collect::<VecDeque<_>>();
    let mut visited = HashSet::new();
    let mut matches = HashSet::new();
    while let Some(parent) = pending.pop_front() {
        if !visited.insert(parent.clone()) {
            continue;
        }
        for &class_id in children.get(&parent).into_iter().flatten() {
            if matches.insert(class_id)
                && let Some(class) = classes.get(class_id)
            {
                pending.push_back(class.clone());
            }
        }
    }
    matches
}

fn query_classes(
    dex: DexIndexView<'_>,
    class: &str,
    mapping: Option<&Mapping>,
) -> Result<Vec<OutputLocation>, String> {
    let mut output = Vec::new();
    for class_id in 0..dex.class_count() {
        let location = dex.class(class_id)?;
        if class_matches(location.class, class, mapping) {
            output.push(class_output(&location, mapping));
        }
    }
    Ok(output)
}

fn query_fields(
    dex: DexIndexView<'_>,
    class: Option<&str>,
    field: &str,
    mapping: Option<&Mapping>,
) -> Result<Vec<OutputLocation>, String> {
    let mut output = Vec::new();
    for field_id in 0..dex.field_count() {
        let location = dex.field(field_id)?;
        if field_matches(&location, field, mapping)
            && class.is_none_or(|class| class_matches(location.class, class, mapping))
        {
            let location_name = mapping
                .and_then(|mapping| {
                    let class = mapping.original_class(location.class)?;
                    mapping
                        .fields(location.class, location.field, location.descriptor)
                        .first()
                        .map(|field| format!("{class}->{}:{}", field.name, field.descriptor))
                })
                .unwrap_or_else(|| {
                    format!(
                        "{}->{}:{}",
                        location.class, location.field, location.descriptor
                    )
                });
            output.push(OutputLocation {
                file: location.dex.to_owned(),
                kind: 'F',
                location: location_name,
                source: location.source_file.map(str::to_owned),
            });
        }
    }
    Ok(output)
}

fn matching_field_classes(
    dex: DexIndexView<'_>,
    class: Option<&str>,
    field: &str,
    mapping: Option<&Mapping>,
) -> Result<HashSet<String>, String> {
    let mut classes = HashSet::new();
    for field_id in 0..dex.field_count() {
        let location = dex.field(field_id)?;
        if field_matches(&location, field, mapping)
            && class.is_none_or(|class| class_matches(location.class, class, mapping))
        {
            classes.insert(location.class.to_owned());
        }
    }
    Ok(classes)
}

fn methods_referencing_all(
    dex: DexIndexView<'_>,
    strings: &[StringMatcher],
) -> Result<HashSet<usize>, String> {
    let mut candidates: Option<HashSet<usize>> = None;
    for query in strings {
        let mut matches = HashSet::new();
        for string_id in 0..dex.string_count() {
            if query.is_match(dex.string_value(string_id)?) {
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

fn class_matches(descriptor: &str, query: &str, mapping: Option<&Mapping>) -> bool {
    class_name_matches(descriptor, query)
        || mapping
            .and_then(|mapping| mapping.original_class(descriptor))
            .is_some_and(|original| class_name_matches(original, query))
}

fn class_name_matches(descriptor: &str, query: &str) -> bool {
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

fn method_matches(
    location: &MethodLocationRef<'_>,
    query: &str,
    mapping: Option<&Mapping>,
) -> bool {
    location.method == query
        || mapping.is_some_and(|mapping| {
            mapping
                .methods(location.class, location.method, location.descriptor)
                .iter()
                .any(|method| method.name == query)
        })
}

fn called_method_matches(
    target: &CalledMethodRef<'_>,
    query: &MethodQuery,
    mapping: Option<&Mapping>,
) -> bool {
    method_query_matches(target.class, target.method, target.descriptor, query)
        || mapping.is_some_and(|mapping| {
            let Some(class) = mapping.original_class(target.class) else {
                return false;
            };
            mapping
                .methods(target.class, target.method, target.descriptor)
                .iter()
                .any(|method| method_query_matches(class, &method.name, &method.descriptor, query))
        })
}

fn method_query_matches(class: &str, method: &str, descriptor: &str, query: &MethodQuery) -> bool {
    method == query.method
        && query
            .class
            .as_deref()
            .is_none_or(|query| class_name_matches(class, query))
        && query
            .descriptor
            .as_deref()
            .is_none_or(|query| descriptor == query)
}

fn method_output(
    location: &MethodLocationRef<'_>,
    mapping: Option<&Mapping>,
) -> Vec<OutputLocation> {
    let mapped = mapping
        .into_iter()
        .flat_map(|mapping| {
            let class = mapping.original_class(location.class);
            mapping
                .methods(location.class, location.method, location.descriptor)
                .iter()
                .filter_map(move |method| {
                    class.map(|class| format!("{class}->{}{}", method.name, method.descriptor))
                })
        })
        .collect::<Vec<_>>();
    let names = if mapped.is_empty() {
        vec![format!(
            "{}->{}{}",
            location.class, location.method, location.descriptor
        )]
    } else {
        mapped
    };
    names
        .into_iter()
        .map(|name| OutputLocation {
            file: location.dex.to_owned(),
            kind: 'M',
            location: name,
            source: location.source_file.map(str::to_owned),
        })
        .collect()
}

fn class_output(location: &ClassLocationRef<'_>, mapping: Option<&Mapping>) -> OutputLocation {
    OutputLocation {
        file: location.dex.to_owned(),
        kind: 'C',
        location: mapping
            .and_then(|mapping| mapping.original_class(location.class))
            .unwrap_or(location.class)
            .to_owned(),
        source: location.source_file.map(str::to_owned),
    }
}

fn field_matches(location: &FieldLocationRef<'_>, query: &str, mapping: Option<&Mapping>) -> bool {
    location.field == query
        || mapping.is_some_and(|mapping| {
            mapping
                .fields(location.class, location.field, location.descriptor)
                .iter()
                .any(|field| field.name == query)
        })
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

fn string_matchers(strings: &[String], regexes: &[String]) -> Result<Vec<StringMatcher>, String> {
    let mut matchers = unique_strings(strings)
        .into_iter()
        .map(StringMatcher::Literal)
        .collect::<Vec<_>>();
    for pattern in unique_strings(regexes) {
        let regex =
            Regex::new(&pattern).map_err(|error| format!("invalid regex {pattern:?}: {error}"))?;
        matchers.push(StringMatcher::Regex(regex));
    }
    Ok(matchers)
}

fn non_empty(value: &str) -> Result<String, String> {
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or_else(|| "string query cannot be empty".to_owned())
}

fn parse_method_query(value: &str) -> Result<MethodQuery, String> {
    let (class, member) = match value.split_once("->") {
        Some((class, member)) if !class.is_empty() && !member.contains("->") => {
            (Some(class.to_owned()), member)
        }
        Some(_) => return Err("method query must use CLASS->NAME(DESCRIPTOR)".to_owned()),
        None => (None, value),
    };
    let (method, descriptor) = match member.find('(') {
        Some(open) if open > 0 && member[open..].contains(')') => {
            (&member[..open], Some(member[open..].to_owned()))
        }
        Some(_) => return Err("method query has an invalid descriptor".to_owned()),
        None => (member, None),
    };
    if method.is_empty() {
        return Err("method name cannot be empty".to_owned());
    }
    Ok(MethodQuery {
        class,
        method: method.to_owned(),
        descriptor,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use clap::Parser;
    use serde_json::json;

    use super::{
        Cli, MethodQuery, OutputLocation, class_matches, descendant_ids, parse_method_query,
        string_matchers, unique_strings,
    };

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
            "-r",
            "error=[0-9]+",
            "--mapping",
            "maps.zip!release/mapping.txt",
            "--aligned",
        ])
        .unwrap();
        assert_eq!(cli.method.as_deref(), Some("someMethod"));
        assert_eq!(cli.strings, ["A value is ", "B value is "]);
        assert_eq!(cli.regexes, ["error=[0-9]+"]);
        assert_eq!(cli.mapping.as_deref(), Some("maps.zip!release/mapping.txt"));
        assert!(cli.aligned);
        assert!(!cli.json);
    }

    #[test]
    fn rejects_aligned_json_output() {
        assert!(
            Cli::try_parse_from(["dexq", "app.apk", "-m", "someMethod", "--aligned", "--json"])
                .is_err()
        );
    }

    #[test]
    fn parses_relationship_queries() {
        let callers = Cli::try_parse_from([
            "dexq",
            "app.apk",
            "--callers-of",
            "Lexample/Target;->work(I)V",
        ])
        .unwrap();
        assert_eq!(
            callers.callers_of,
            Some(MethodQuery {
                class: Some("Lexample/Target;".to_owned()),
                method: "work".to_owned(),
                descriptor: Some("(I)V".to_owned()),
            })
        );
        assert!(Cli::try_parse_from(["dexq", "app.apk", "--inherits", "Base"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "dexq",
                "app.apk",
                "--callers-of",
                "work",
                "--inherits",
                "Base"
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_bare_and_qualified_method_queries() {
        assert_eq!(
            parse_method_query("work").unwrap(),
            MethodQuery {
                class: None,
                method: "work".to_owned(),
                descriptor: None,
            }
        );
        assert!(parse_method_query("Target->").is_err());
        assert!(parse_method_query("work(").is_err());
    }

    #[test]
    fn finds_transitive_descendants_once() {
        let children = HashMap::from([
            ("LBase;".to_owned(), vec![0]),
            ("LChild;".to_owned(), vec![1]),
            ("LGrandchild;".to_owned(), vec![0]),
        ]);
        let classes = ["LChild;".to_owned(), "LGrandchild;".to_owned()];

        assert_eq!(
            descendant_ids(&children, &classes, ["LBase;".to_owned()]),
            HashSet::from([0, 1])
        );
    }

    #[test]
    fn serializes_only_the_public_output_columns() {
        let location = OutputLocation {
            file: "assets/inner.apk!classes2.dex".to_owned(),
            kind: 'M',
            location: "Lexample/Player;->play()V".to_owned(),
            source: Some("Player.java".to_owned()),
        };

        assert_eq!(
            serde_json::to_value(location).unwrap(),
            json!({
                "file": "assets/inner.apk!classes2.dex",
                "type": "M",
                "location": "Lexample/Player;->play()V",
                "source": "Player.java"
            })
        );
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
    fn matches_literal_and_regex_string_queries() {
        let matchers =
            string_matchers(&["status=".to_owned()], &["code=[0-9]+".to_owned()]).unwrap();
        assert!(
            matchers
                .iter()
                .all(|matcher| matcher.is_match("status=code=200"))
        );
        assert!(string_matchers(&[], &["[".to_owned()]).is_err());
    }

    #[test]
    fn matches_simple_dotted_and_descriptor_class_names() {
        let descriptor = "Lcom/example/PlayerManager;";
        assert!(class_matches(descriptor, "PlayerManager", None));
        assert!(class_matches(descriptor, "com.example.PlayerManager", None));
        assert!(class_matches(descriptor, descriptor, None));
        assert!(!class_matches(descriptor, "OtherManager", None));
    }

    #[test]
    fn requires_dollar_notation_for_inner_classes() {
        let descriptor = "Lcom/ut/mini/UTHitBuilders$UTHitBuilder;";
        assert!(class_matches(
            descriptor,
            "UTHitBuilders$UTHitBuilder",
            None
        ));
        assert!(class_matches(
            descriptor,
            "com.ut.mini.UTHitBuilders$UTHitBuilder",
            None
        ));
        assert!(!class_matches(descriptor, "UTHitBuilder", None));
        assert!(!class_matches(
            descriptor,
            "com.ut.mini.UTHitBuilders.UTHitBuilder",
            None
        ));
        assert!(class_matches("Lcom/example/Outer$1$1;", "Outer$1$1", None));
        assert!(class_matches(
            "Lcom/example/EglRenderer$$Lambda$1;",
            "EglRenderer$$Lambda$1",
            None
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

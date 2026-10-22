#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use apkq::archive::ApkArchive;
use apkq::dex::mapping;
use apkq::dex::{
    self, DecompiledClass, DexIndex, DisassembleTarget, Disassembly, DisassemblyFormat,
    ReferenceFilter,
};
use apkq::java::{JavaClass, JavaField, JavaMethod, JavaType};
use apkq::resource::{self, Query};
use clap::{Args, CommandFactory, Parser, Subcommand};
use regex::Regex;

mod output;

use output::Output;

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
  apkq app.apk d com.example.MainActivity
  apkq app.apk x 'com.example.MainActivity#onCreate(android.os.Bundle):void'
  apkq app.apk --mapping 'mapping.zip!path/to/mapping.txt' --json m --name originalMethod

Input: an APK; embedded APKs are searched recursively.
Output: queries use TSV by default; --aligned follows c/f/m/r. --json is available for every command. Timing and count go to stderr. Code rows contain DEX, TYPE (C/F/M), SYMBOL, optional ORIGINAL, and SOURCE. Resource rows contain nested ARCHIVE, ID, TYPE, NAME, optional ORIGINAL, CONFIG, VALUE, PATH, and USAGE.
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
    /// Emit JSON instead of text output
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn parse_class(value: &str) -> Result<JavaClass, String> {
        if value.starts_with('L') && value.ends_with(';') {
            JavaClass::from_descriptor(value)
        } else {
            value.parse()
        }
    }

    fn parse_method(value: &str) -> Result<JavaMethod, String> {
        if value.contains("->") {
            JavaMethod::from_descriptor(value)
        } else {
            value.parse()
        }
    }

    fn parse_field(value: &str) -> Result<JavaField, String> {
        if value.contains("->") {
            JavaField::from_descriptor(value)
        } else {
            value.parse()
        }
    }

    fn parse_type(value: &str) -> Result<JavaType, String> {
        if value.starts_with('[')
            || (value.starts_with('L') && value.ends_with(';'))
            || matches!(value, "V" | "Z" | "B" | "C" | "S" | "I" | "J" | "F" | "D")
        {
            JavaType::from_descriptor(value)
        } else {
            value.parse()
        }
    }

    fn parse_target(value: &str) -> Result<DisassembleTarget, String> {
        if value.contains("->") || (value.starts_with('L') && value.ends_with(';')) {
            DisassembleTarget::from_descriptor(value)
        } else {
            value.parse()
        }
    }

    fn validate(&self) -> Result<(), clap::Error> {
        if self.json && self.command.aligned() {
            return Err(Self::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--json cannot be combined with --aligned",
            ));
        }

        Ok(())
    }
}

#[derive(Args, Default)]
struct DexArgs {
    /// Exact DEX location, such as classes2.dex or assets/plugin.apk!classes.dex
    #[arg(long)]
    dex: Option<String>,
}

#[derive(Args, Default)]
struct TableArgs {
    /// Align tabular text output
    #[arg(long)]
    aligned: bool,
}

#[derive(Args, Default)]
struct OutputArgs {
    /// Write output to this file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Default)]
struct NameArgs {
    /// Exact item name
    #[arg(long, value_parser = non_empty, conflicts_with = "name_regex")]
    name: Option<String>,
    /// Rust regex matched against the item name
    #[arg(long)]
    name_regex: Option<Regex>,
}

#[derive(Subcommand)]
enum Command {
    /// Decompile one class to Java source
    #[command(
        visible_alias = "d",
        after_help = r#"CLASS accepts a dotted Java name or DEX descriptor. Embedded APKs are searched recursively. If more than one DEX defines the class, rerun with --dex using a location from the error.
With --mapping, CLASS may be an original or obfuscated name. Output uses actual APK symbols.
Source is written to stdout, or to --output. With --json, the output contains dex, class, and source.

Examples:
  apkq app.apk d com.example.MainActivity
  apkq app.apk d 'Lcom/example/MainActivity;'
  apkq app.apk d com.example.MainActivity --dex classes3.dex
  apkq app.apk d com.example.MainActivity --dex 'assets/plugin.apk!classes.dex'
  apkq app.apk --mapping mapping.txt d com.example.MainActivity
  apkq app.apk --json d com.example.MainActivity
  apkq app.apk d com.example.MainActivity -o MainActivity.java"#
    )]
    Decompile {
        /// Dotted Java class name or DEX descriptor
        #[arg(value_parser = Cli::parse_class)]
        class: JavaClass,
        #[command(flatten)]
        dex: DexArgs,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Disassemble a class or method with DEX program counters
    #[command(
        visible_alias = "x",
        after_help = r#"A dotted class name or DEX class descriptor selects the whole class. A method target uses Class#name or Class#name(parameters):returnType. DEX/smali methods such as Lcom/example/Client;->send(I)V are also accepted. An omitted signature is accepted only when it selects one method.
DEX_PC is the instruction offset from the method's insns array, measured in 16-bit code units. Embedded APKs are searched recursively. Use --dex to select an exact nested DEX location.
With --mapping, the target may use original or obfuscated names; output uses actual APK symbols. Text appends # pc=0x… to each executable instruction. Use -o to write text or JSON to a file. JSON contains dex, class, and methods with numeric instruction dex_pc values. Class annotations and static field initializers are not emitted.

Examples:
  apkq app.apk x 'com.example.MainActivity#onCreate(android.os.Bundle):void'
  apkq app.apk x com.example.Client
  apkq app.apk x 'Lcom/example/Client;->send(I)V'
  apkq app.apk x 'com.example.Client#send'
  apkq app.apk x 'com.example.Client#send(int):void' --dex classes2.dex
  apkq app.apk --mapping mapping.txt --json x 'com.example.Client#send'"#
    )]
    Disassemble {
        /// Class or method: Class, Class#name, or Class#name(parameters):returnType
        #[arg(value_name = "TARGET", value_parser = Cli::parse_target)]
        target: DisassembleTarget,
        #[command(flatten)]
        output: OutputArgs,
        #[command(flatten)]
        dex: DexArgs,
    },
    /// Find Android resources and references in compiled XML
    #[command(
        visible_alias = "r",
        after_help = r#"Use --list to list all resources. Resources are read from resources.arsc in each APK, including embedded APKs. IDs are scoped to their containing APK.
--type limits returned resource types, for example string, id, or layout. --name is exact; --name-regex and --value-regex use Rust regex syntax; --value is a case-sensitive substring. Exact and regex forms are alternatives. Filters are ANDed.
--uses-resource finds resources that directly reference an ID in their table value or compiled XML attributes. Give a numeric ID (0x7f...), type/name, or package:type/name. USAGE identifies the table value or XML view ID and attribute.

Examples:
  apkq app.apk r --type string --value 'Login failed'
  apkq app.apk r --type string --value-regex 'login|sign.?in'
  apkq app.apk r --type id --name-regex 'button(_text)?$'
  apkq app.apk r --type layout --name activity_login
  apkq app.apk r --id 0x7f0a0012
  apkq app.apk r --type layout --uses-resource string/login_failed
  apkq app.apk --json r --type layout --uses-resource 0x7f0a0012"#
    )]
    Resources {
        #[command(flatten)]
        table: TableArgs,
        /// List all resources
        #[arg(
            long,
            conflicts_with_all = ["kind", "name", "name_regex", "id", "value", "value_regex", "uses_resource"]
        )]
        list: bool,
        /// Exact resource type, such as string, id, or layout
        #[arg(long = "type", value_parser = non_empty)]
        kind: Option<String>,
        #[command(flatten)]
        name: NameArgs,
        /// Numeric resource ID, decimal or 0x-prefixed hexadecimal
        #[arg(long, value_parser = resource::Location::parse_id)]
        id: Option<u32>,
        /// Case-sensitive substring of decoded resource value
        #[arg(long, value_parser = non_empty, conflicts_with = "value_regex")]
        value: Option<String>,
        /// Regex for decoded resource value
        #[arg(long)]
        value_regex: Option<Regex>,
        /// Referenced ID, type/name, or package:type/name
        #[arg(long, value_parser = resource::Query::validate_reference)]
        uses_resource: Option<String>,
    },
    /// Find class definitions
    #[command(
        visible_alias = "c",
        after_help = r#"Use --list to list all classes. Class inputs accept dotted Java names or DEX descriptors.
--name is exact. --name-regex matches the full dotted class name using Rust regex syntax. They are alternatives.
--inherits finds direct and transitive subclasses and implementors; the base class is excluded.
Filters are ANDed. With --mapping, class filters also match original names.

Examples:
  apkq app.apk c --name com.example.MainActivity
  apkq app.apk c --name-regex '^com\.example\.'
  apkq app.apk c --name-regex '(Login|Register)Activity$'
  apkq app.apk c --inherits android.app.Activity
  apkq app.apk --mapping mapping.txt c --inherits com.example.ItemBase"#
    )]
    Classes {
        #[command(flatten)]
        table: TableArgs,
        #[command(flatten)]
        dex: DexArgs,
        /// List all classes
        #[arg(
            long,
            conflicts_with_all = ["name", "name_regex", "inherits"]
        )]
        list: bool,
        /// Exact class name
        #[arg(long, conflicts_with = "name_regex", value_parser = Cli::parse_class)]
        name: Option<JavaClass>,
        /// Rust regex matched against the full dotted class name
        #[arg(long)]
        name_regex: Option<Regex>,
        /// Direct or transitive subclasses and implementors
        #[arg(long, value_parser = Cli::parse_class)]
        inherits: Option<JavaClass>,
    },
    /// Find field definitions
    #[command(
        visible_alias = "f",
        after_help = r#"Use --list to list all fields. --class accepts a dotted Java name or DEX descriptor; --name is exact; --name-regex uses Rust regex syntax; the two name filters are alternatives. Filters are ANDed.
With --mapping, filters also match original class and field names.

Examples:
  apkq app.apk f --class com.example.Config --name apiKey
  apkq app.apk f --name-regex '^(is|has)[A-Z]'
  apkq app.apk --json f --name apiKey
  apkq app.apk --mapping mapping.txt f --name originalField"#
    )]
    Fields {
        #[command(flatten)]
        table: TableArgs,
        #[command(flatten)]
        dex: DexArgs,
        /// List all fields
        #[arg(
            long,
            conflicts_with_all = ["class", "name", "name_regex"]
        )]
        list: bool,
        /// Exact declaring class name
        #[arg(long, value_parser = Cli::parse_class)]
        class: Option<JavaClass>,
        #[command(flatten)]
        name: NameArgs,
    },
    /// Find method definitions; repeated reference filters are ANDed within one method
    #[command(
        visible_alias = "m",
        after_help = r#"Use --list to list all methods. --class accepts a dotted Java name or DEX descriptor; --name is exact; --name-regex uses Rust regex syntax; the two name filters are alternatives. --has-field requires a field declared in that class.
All filters are ANDed. Repeated reference options require references within the same method.
--uses-string matches case-sensitive substrings, including reads of initialized static string fields.
--calls Class#name matches any overload; add (parameters):returnType for an exact signature.
--uses-field Class#name matches any type; add :type to specify one. DEX/smali references such as Lcom/example/Client;->send(I)V and Lcom/example/Config;->key:Ljava/lang/String; are also accepted.
Types accept Java syntax (int, java.lang.String[]) or DEX descriptors (I, [Ljava/lang/String;).
With --mapping, class/member filters also match original names.
Calls match explicit DEX invoke instructions.

Examples:
  apkq app.apk m --name onCreate
  apkq app.apk m --name-regex '^(get|set)[A-Z]'
  apkq app.apk m --class com.example.MainActivity --has-field apiKey
  apkq app.apk m --uses-string token --uses-string secret
  apkq app.apk m --calls 'com.example.Client#send'
  apkq app.apk m --calls 'com.example.Client#send(int):void'
  apkq app.apk m --calls 'Lcom/example/Client;->send(I)V'
  apkq app.apk m --uses-field 'com.example.Config#key'
  apkq app.apk m --uses-field 'com.example.Config#key:java.lang.String'
  apkq app.apk m --uses-field 'Lcom/example/Config;->key:Ljava/lang/String;'
  apkq app.apk m --uses-string token --uses-type java.lang.String
  apkq app.apk --mapping mapping.txt m --calls 'com.example.Client#send'"#
    )]
    Methods {
        #[command(flatten)]
        table: TableArgs,
        #[command(flatten)]
        dex: DexArgs,
        /// List all methods
        #[arg(
            long,
            conflicts_with_all = ["class", "name", "name_regex", "has_field", "strings", "calls", "types", "fields"]
        )]
        list: bool,
        /// Exact declaring class name
        #[arg(long, value_parser = Cli::parse_class)]
        class: Option<JavaClass>,
        #[command(flatten)]
        name: NameArgs,
        /// Keep methods declared in classes with a field of this name
        #[arg(long)]
        has_field: Option<String>,
        /// Referenced string fragment, including initialized static string fields
        #[arg(long = "uses-string", alias = "string", value_parser = non_empty)]
        strings: Vec<String>,
        /// Called method: Class#name or Class#name(parameters):returnType
        #[arg(long = "calls", value_parser = Cli::parse_method)]
        calls: Vec<JavaMethod>,
        /// Referenced type, such as java.lang.String
        #[arg(long = "uses-type", value_parser = Cli::parse_type)]
        types: Vec<JavaType>,
        /// Accessed field: Class#name or Class#name:type
        #[arg(long = "uses-field", value_parser = Cli::parse_field)]
        fields: Vec<JavaField>,
    },
}

impl Command {
    fn aligned(&self) -> bool {
        match self {
            Self::Classes { table, .. }
            | Self::Fields { table, .. }
            | Self::Methods { table, .. }
            | Self::Resources { table, .. } => table.aligned,
            _ => false,
        }
    }

    fn selected_dex(&self) -> Option<&str> {
        match self {
            Self::Classes { dex, .. }
            | Self::Fields { dex, .. }
            | Self::Methods { dex, .. }
            | Self::Decompile { dex, .. }
            | Self::Disassemble { dex, .. } => dex.dex.as_deref(),
            _ => None,
        }
    }

    fn has_query(&self) -> bool {
        match self {
            Self::Decompile { .. } | Self::Disassemble { .. } => true,
            Self::Resources {
                list,
                kind,
                name: NameArgs { name, name_regex },
                id,
                value,
                value_regex,
                uses_resource,
                ..
            } => {
                *list
                    || kind.is_some()
                    || name.is_some()
                    || name_regex.is_some()
                    || id.is_some()
                    || value.is_some()
                    || value_regex.is_some()
                    || uses_resource.is_some()
            }
            Self::Classes {
                list,
                name,
                name_regex,
                inherits,
                ..
            } => *list || name.is_some() || name_regex.is_some() || inherits.is_some(),
            Self::Fields {
                list,
                class,
                name: NameArgs { name, name_regex },
                ..
            } => *list || class.is_some() || name.is_some() || name_regex.is_some(),
            Self::Methods {
                list,
                class,
                name: NameArgs { name, name_regex },
                has_field,
                strings,
                calls,
                types,
                fields,
                ..
            } => {
                *list
                    || class.is_some()
                    || name.is_some()
                    || name_regex.is_some()
                    || has_field.is_some()
                    || !strings.is_empty()
                    || !calls.is_empty()
                    || !types.is_empty()
                    || !fields.is_empty()
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Decompile { .. } => "decompile",
            Self::Disassemble { .. } => "disassemble",
            Self::Resources { .. } => "resources",
            Self::Classes { .. } => "classes",
            Self::Fields { .. } => "fields",
            Self::Methods { .. } => "methods",
        }
    }
}

pub(super) fn main() {
    let cli = Cli::parse();

    if let Err(error) = cli.validate() {
        error.exit();
    }

    if !cli.command.has_query() {
        let error = Cli::command()
            .try_get_matches_from(["apkq", "input.apk", cli.command.name(), "--help"])
            .expect_err("missing help output");

        error.print().expect("failed to print help");
        return;
    }

    if let Err(error) = cli.run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

impl Cli {
    fn run(self) -> Result<(), String> {
        if let Command::Disassemble {
            target,
            dex,
            output,
        } = &self.command
        {
            let started = Instant::now();
            let mapping = self.mapping.as_deref().map(mapping::load).transpose()?;
            let prepared = ApkArchive::open(&self.input)?;
            let (dex, descriptor, result) = Disassembly::from_apk(
                &prepared,
                target,
                dex.dex.as_deref(),
                mapping.as_ref(),
                if self.json {
                    DisassemblyFormat::Instructions
                } else {
                    DisassemblyFormat::Smali
                },
            )?;

            let class = JavaClass::from_descriptor(&descriptor)?.to_string();

            Output::print_disassembled(&dex, &class, &result, output.output.as_deref())?;
            eprintln!("disassembled in {:.3}s", started.elapsed().as_secs_f64());

            return Ok(());
        }

        if let Command::Decompile { class, dex, output } = &self.command {
            let started = Instant::now();
            let mapping = self.mapping.as_deref().map(mapping::load).transpose()?;
            let prepared = ApkArchive::open(&self.input)?;
            let result =
                DecompiledClass::from_apk(&prepared, class, dex.dex.as_deref(), mapping.as_ref())?;
            let actual = JavaClass::from_descriptor(&result.descriptor)?.to_string();

            Output::print_decompiled(
                &result.dex,
                &actual,
                &result.source,
                self.json,
                output.output.as_deref(),
            )?;
            eprintln!("decompiled in {:.3}s", started.elapsed().as_secs_f64());

            return Ok(());
        }

        if let Command::Resources {
            kind,
            name: NameArgs { name, name_regex },
            id,
            value,
            value_regex,
            uses_resource,
            ..
        } = &self.command
        {
            let mapping = self
                .mapping
                .as_deref()
                .map(resource::mapping::load)
                .transpose()?;

            return Self::run_resources(
                &self.input,
                Query {
                    mapping: mapping.as_ref(),
                    kind: kind.as_deref(),
                    name: name.as_deref(),
                    name_regex: name_regex.as_ref(),
                    id: *id,
                    value: value.as_deref(),
                    value_regex: value_regex.as_ref(),
                    uses_resource: uses_resource.as_deref(),
                },
                self.json,
                self.command.aligned(),
            );
        }

        let apk = &self.input;
        let mapping = self.mapping.as_deref().map(mapping::load).transpose()?;
        let started = Instant::now();

        let filter = match &self.command {
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

        let prepared = ApkArchive::open(apk)?;
        let index_dex = match &self.command {
            Command::Classes {
                inherits: Some(_), ..
            } => None,
            _ => self.command.selected_dex(),
        };

        let index = DexIndex::from_archive(&prepared, filter.as_ref(), index_dex)?;

        let query = match &self.command {
            Command::Classes {
                name,
                name_regex,
                inherits,
                ..
            } => dex::query::Query::Classes {
                name: name.as_ref(),
                name_regex: name_regex.as_ref(),
                inherits: inherits.as_ref(),
            },
            Command::Fields { class, name, .. } => dex::query::Query::Fields {
                class: class.as_ref(),
                name: name.name.as_deref(),
                name_regex: name.name_regex.as_ref(),
            },
            Command::Methods {
                class,
                name,
                has_field,
                ..
            } => dex::query::Query::Methods {
                class: class.as_ref(),
                name: name.name.as_deref(),
                name_regex: name.name_regex.as_ref(),
                has_field: has_field.as_deref(),
            },
            _ => unreachable!(),
        };

        let output = query.select(&index, mapping.as_ref(), self.command.selected_dex())?;

        Output::print_output(
            &output,
            self.json,
            self.command.aligned(),
            self.mapping.is_some(),
        )?;

        eprintln!(
            "searched in {:.3}s; {} match(es)",
            started.elapsed().as_secs_f64(),
            output.len()
        );

        Ok(())
    }

    fn run_resources(
        input: &Path,
        query: Query<'_>,
        json: bool,
        aligned: bool,
    ) -> Result<(), String> {
        let started = Instant::now();
        let show_original = query.mapping.is_some();
        let mut rows = query.index_apk(input)?;

        rows.sort();
        rows.dedup();
        Output::print_resources(&rows, json, aligned, show_original)?;

        eprintln!(
            "searched in {:.3}s; {} match(es)",
            started.elapsed().as_secs_f64(),
            rows.len()
        );

        Ok(())
    }
}

fn non_empty(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("query value cannot be empty".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn dispatches_format_before_parsing_nested_types() {
        let java = Cli::parse_method("Owner#call(I):void").unwrap();
        assert!(java.matches("LOwner;", "call", "(LI;)V"));
        let descriptor = Cli::parse_method("LOwner;->call(I)V").unwrap();
        assert!(descriptor.matches("LOwner;", "call", "(I)V"));
        let field = Cli::parse_field("Owner#value:V").unwrap();
        assert!(field.matches("LOwner;", "value", "LV;"));
    }

    #[test]
    fn accepts_smali_targets_and_reference_filters() {
        for arguments in [
            vec!["apkq", "app.apk", "x", "Lcom/example/Client;->send(I)V"],
            vec!["apkq", "app.apk", "x", "Lcom/example/Client;->send"],
            vec![
                "apkq",
                "app.apk",
                "m",
                "--calls",
                "Lcom/example/Client;->send(I)V",
                "--uses-field",
                "Lcom/example/Config;->key:Ljava/lang/String;",
                "--uses-type",
                "[Ljava/lang/String;",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }

    #[test]
    fn scopes_shared_options_to_supported_commands() {
        for command in ["c", "m", "f", "r"] {
            assert!(
                Cli::try_parse_from(["apkq", "app.apk", command, "--aligned", "--list"]).is_ok()
            );
            for arguments in [
                vec!["apkq", "app.apk", "--json", command, "--aligned", "--list"],
                vec!["apkq", "app.apk", command, "--aligned", "--list", "--json"],
            ] {
                assert!(
                    Cli::try_parse_from(arguments)
                        .and_then(|cli| cli.validate())
                        .is_err()
                );
            }
        }
        assert!(Cli::try_parse_from(["apkq", "app.apk", "--aligned", "c", "--list"]).is_err());
        for command in ["c", "m", "f"] {
            assert!(
                Cli::try_parse_from([
                    "apkq",
                    "app.apk",
                    command,
                    "--dex",
                    "classes2.dex",
                    "--list"
                ])
                .is_ok()
            );
        }
        for command in ["d", "x"] {
            assert!(
                Cli::try_parse_from([
                    "apkq",
                    "app.apk",
                    command,
                    "Lcom/example/Client;",
                    "--dex",
                    "classes2.dex",
                    "-o",
                    "result.txt"
                ])
                .is_ok()
            );
            assert!(
                Cli::try_parse_from([
                    "apkq",
                    "app.apk",
                    command,
                    "com.example.Client",
                    "--aligned"
                ])
                .is_err()
            );
        }
        assert!(Cli::try_parse_from(["apkq", "app.apk", "r", "--value-regex", "["]).is_err());
    }

    #[test]
    fn accepts_short_command_aliases_and_combined_filters() {
        let cli =
            Cli::try_parse_from(["apkq", "app.apk", "--mapping", "mapping.txt", "--json", "m"])
                .unwrap();
        assert!(cli.mapping.is_some() && cli.json);
        assert!(Cli::try_parse_from(["apkq", "app.apk", "r", "--aligned"]).is_ok());
        assert!(matches!(
            Cli::try_parse_from(["apkq", "app.apk", "d", "Lcom/example/MainActivity;"])
                .unwrap()
                .command,
            Command::Decompile { .. }
        ));
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "decompile",
                "com.example.MainActivity",
                "--dex",
                "assets/plugin.apk!classes.dex",
                "-o",
                "MainActivity.java"
            ])
            .is_ok()
        );
        assert!(matches!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "x",
                "com.example.MainActivity#onCreate(android.os.Bundle):void"
            ])
            .unwrap()
            .command,
            Command::Disassemble { .. }
        ));
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "disassemble",
                "com.example.Client#send",
                "--dex",
                "classes2.dex"
            ])
            .is_ok()
        );

        assert!(matches!(
            Cli::try_parse_from(["apkq", "app.apk", "c", "--inherits", "com.example.Base"])
                .unwrap()
                .command,
            Command::Classes { .. }
        ));
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "c",
                "--name-regex",
                "Main(Activity|Fragment)$"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["apkq", "app.apk", "c", "--name-regex", "["]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["apkq", "app.apk", "f", "--name", "apiKey"])
                .unwrap()
                .command,
            Command::Fields { .. }
        ));
        assert!(Cli::try_parse_from(["apkq", "app.apk", "f", "--name-regex", "^(is|has)"]).is_ok());
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
            Cli::try_parse_from(["apkq", "app.apk", "m", "--name-regex", "^(get|set)"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "m", "--calls", "com.example.Client#send"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["apkq", "app.apk", "c", "--inherits", "LBase;"]).is_ok());
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
            Cli::try_parse_from(["apkq", "app.apk", "r", "--name-regex", "^activity_"]).is_ok()
        );
        assert!(Cli::try_parse_from(["apkq", "app.apk", "r", "--name-regex", "["]).is_err());
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "r", "--uses-resource", "broken"]).is_err()
        );
    }

    #[test]
    fn requires_a_query_or_list() {
        for command in ["c", "f", "m", "r"] {
            let cli = Cli::try_parse_from(["apkq", "app.apk", command]).unwrap();
            assert!(!cli.command.has_query(), "{command}");

            assert!(
                Cli::try_parse_from(["apkq", "app.apk", command, "--list"])
                    .unwrap()
                    .command
                    .has_query(),
                "{command}"
            );
        }

        let cli = Cli::try_parse_from(["apkq", "app.apk", "c", "--aligned"]).unwrap();
        assert!(!cli.command.has_query());

        assert!(Cli::try_parse_from(["apkq", "app.apk", "c", "--list", "--name", "a.b"]).is_err());
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "f", "--list", "--name", "field"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "m", "--list", "--name", "method"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["apkq", "app.apk", "r", "--list", "--type", "string"]).is_err()
        );

        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "c",
                "--name",
                "a.b",
                "--name-regex",
                "b$"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "f",
                "--name",
                "field",
                "--name-regex",
                "field"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "m",
                "--name",
                "method",
                "--name-regex",
                "method"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "r",
                "--name",
                "title",
                "--name-regex",
                "title"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "apkq",
                "app.apk",
                "r",
                "--value",
                "Login",
                "--value-regex",
                "Login"
            ])
            .is_err()
        );
    }
}

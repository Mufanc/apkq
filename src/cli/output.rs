use std::fs;
use std::path::Path;

use apkq::dex::Disassembly;
use apkq::dex::query::Symbol;
use apkq::resource::Location;
use serde_json::json;

pub(super) struct Output;

impl Output {
    pub(super) fn print_disassembled(
        dex: &str,
        class: &str,
        result: &Disassembly,
        output: Option<&Path>,
    ) -> Result<(), String> {
        let rendered = match result {
            Disassembly::Instructions(methods) => {
                let methods = methods
                    .iter()
                    .map(|method| {
                        let instructions = method
                            .instructions
                            .iter()
                            .map(|instruction| {
                                json!({
                                    "dex_pc": instruction.dex_pc,
                                    "instruction": instruction.instruction,
                                })
                            })
                            .collect::<Vec<_>>();
                        json!({"method": method.method, "instructions": instructions})
                    })
                    .collect::<Vec<_>>();

                serde_json::to_string(&json!({"dex": dex, "class": class, "methods": methods}))
                    .map_err(|error| error.to_string())?
                    + "\n"
            }
            Disassembly::Smali(smali) => {
                format!("# dex: {dex}\n\n{}\n", smali.trim_matches('\n'))
            }
        };

        Self::write_output(&rendered, output)
    }

    pub(super) fn print_decompiled(
        dex: &str,
        class: &str,
        source: &str,
        json_output: bool,
        output: Option<&Path>,
    ) -> Result<(), String> {
        if json_output {
            let mut rendered = serde_json::to_string(&json!({
                "dex": dex,
                "class": class,
                "source": source,
            }))
            .map_err(|error| error.to_string())?;

            rendered.push('\n');

            return Self::write_output(&rendered, output);
        }

        if let Some(path) = output {
            let mut source = source.to_owned();

            if !source.ends_with('\n') {
                source.push('\n');
            }

            return fs::write(path, source).map_err(|error| format!("{}: {error}", path.display()));
        }

        println!("{}\n", source.trim_matches('\n'));

        Ok(())
    }

    fn write_output(output: &str, path: Option<&Path>) -> Result<(), String> {
        if let Some(path) = path {
            return fs::write(path, output).map_err(|error| format!("{}: {error}", path.display()));
        }

        print!("{output}");

        Ok(())
    }

    pub(super) fn print_output(
        output: &[Symbol],
        json: bool,
        aligned: bool,
        show_original: bool,
    ) -> Result<(), String> {
        if json {
            let values = output
                .iter()
                .map(|row| {
                    json!({
                        "dex": row.dex, "type": row.kind.to_string(),
                        "symbol": row.symbol, "original": row.original, "source": row.source,
                    })
                })
                .collect::<Vec<_>>();

            println!(
                "{}",
                serde_json::to_string(&values).map_err(|error| error.to_string())?
            );
        } else {
            let mut headings = vec!["DEX", "TYPE", "SYMBOL"];

            if show_original {
                headings.push("ORIGINAL");
            }

            headings.push("SOURCE");

            let fields = output
                .iter()
                .map(|row| {
                    let mut values =
                        vec![row.dex.clone(), row.kind.to_string(), row.symbol.clone()];

                    if show_original {
                        values.push(row.original.clone().unwrap_or_default());
                    }

                    values.push(row.source.clone().unwrap_or_default());

                    values
                })
                .collect::<Vec<_>>();

            Self::print_table(&headings, &fields, aligned);
        }

        Ok(())
    }

    fn print_table(headings: &[&str], rows: &[Vec<String>], aligned: bool) {
        let rows = rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| Self::tsv(&Self::non_empty(value)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        if aligned {
            let widths = headings
                .iter()
                .enumerate()
                .map(|(index, heading)| {
                    rows.iter()
                        .map(|row| row[index].chars().count())
                        .max()
                        .unwrap_or(0)
                        .max(heading.chars().count())
                })
                .collect::<Vec<_>>();

            println!(
                "{}",
                headings
                    .iter()
                    .enumerate()
                    .map(|(index, value)| format!("{value:<width$}", width = widths[index]))
                    .collect::<Vec<_>>()
                    .join("  ")
            );

            for row in rows {
                println!(
                    "{}",
                    row.iter()
                        .enumerate()
                        .map(|(index, value)| format!("{value:<width$}", width = widths[index]))
                        .collect::<Vec<_>>()
                        .join("  ")
                );
            }
        } else {
            println!("{}", headings.join("\t"));

            for row in rows {
                println!("{}", row.join("\t"));
            }
        }
    }

    fn tsv(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    pub(super) fn print_resources(
        rows: &[Location],
        json_output: bool,
        aligned: bool,
        show_original: bool,
    ) -> Result<(), String> {
        if json_output {
            let values = rows
                .iter()
                .map(|row| {
                    json!({
                        "archive": row.archive, "id": format!("0x{:08x}", row.id),
                        "type": row.kind, "name": row.name, "original": row.original,
                        "config": row.config, "value": row.value, "path": row.path,
                        "usage": row.usage,
                    })
                })
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string(&values).map_err(|error| error.to_string())?
            );

            return Ok(());
        }

        let mut headings = vec!["ARCHIVE", "ID", "TYPE", "NAME"];

        if show_original {
            headings.push("ORIGINAL");
        }

        headings.extend(["CONFIG", "VALUE", "PATH", "USAGE"]);

        let fields = rows
            .iter()
            .map(|row| {
                let mut fields = vec![
                    row.archive.clone(),
                    format!("0x{:08x}", row.id),
                    row.kind.clone(),
                    row.name.clone(),
                ];

                if show_original {
                    fields.push(row.original.clone().unwrap_or_else(|| "-".to_owned()));
                }

                fields.extend([
                    row.config.clone(),
                    Self::non_empty(&row.value),
                    row.path.clone().unwrap_or_else(|| "-".to_owned()),
                    row.usage.clone().unwrap_or_else(|| "-".to_owned()),
                ]);

                fields
            })
            .collect::<Vec<_>>();

        Self::print_table(&headings, &fields, aligned);

        Ok(())
    }

    fn non_empty(value: &str) -> String {
        if value.is_empty() { "-" } else { value }.to_owned()
    }
}

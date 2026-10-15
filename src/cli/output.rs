use apkq::resource::Location;
use serde_json::json;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Row {
    pub(super) dex: String,
    pub(super) kind: char,
    pub(super) symbol: String,
    pub(super) original: Option<String>,
    pub(super) source: Option<String>,
}

pub(super) fn print_output(
    output: &[Row],
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
    } else if aligned {
        print_aligned(output, show_original);
    } else {
        let heading = if show_original {
            "DEX\tTYPE\tSYMBOL\tORIGINAL\tSOURCE"
        } else {
            "DEX\tTYPE\tSYMBOL\tSOURCE"
        };
        println!("{heading}");

        for row in output {
            let mut fields = vec![tsv(&row.dex), row.kind.to_string(), tsv(&row.symbol)];
            if show_original {
                fields.push(tsv(row.original.as_deref().unwrap_or("-")));
            }
            fields.push(tsv(row.source.as_deref().unwrap_or("-")));
            println!("{}", fields.join("\t"));
        }
    }

    Ok(())
}

fn print_aligned(output: &[Row], show_original: bool) {
    let dex_width = output
        .iter()
        .map(|row| row.dex.chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    let symbol_width = output
        .iter()
        .map(|row| row.symbol.chars().count())
        .max()
        .unwrap_or(6)
        .max(6);

    let original_heading = if show_original { "  ORIGINAL" } else { "" };
    println!(
        "{:<dex_width$}  TYPE  {:<symbol_width$}{original_heading}  SOURCE",
        "DEX", "SYMBOL"
    );

    for row in output {
        let original = if show_original {
            format!("  {}", row.original.as_deref().unwrap_or("-"))
        } else {
            String::new()
        };
        println!(
            "{:<dex_width$}  {:<4}  {:<symbol_width$}{}  {}",
            row.dex,
            row.kind,
            row.symbol,
            original,
            row.source.as_deref().unwrap_or("-")
        );
    }
}

pub(super) fn push_aliases(
    output: &mut Vec<Row>,
    dex: &str,
    kind: char,
    symbol: String,
    originals: Vec<String>,
    source: Option<&str>,
) {
    if originals.is_empty() {
        output.push(Row {
            dex: dex.to_owned(),
            kind,
            symbol,
            original: None,
            source: source.map(str::to_owned),
        });
    } else {
        for original in originals {
            output.push(Row {
                dex: dex.to_owned(),
                kind,
                symbol: symbol.clone(),
                original: Some(original),
                source: source.map(str::to_owned),
            });
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
                non_empty(&row.value),
                row.path.clone().unwrap_or_else(|| "-".to_owned()),
                row.usage.clone().unwrap_or_else(|| "-".to_owned()),
            ]);
            fields
        })
        .collect::<Vec<_>>();
    if aligned {
        let widths = (0..headings.len())
            .map(|index| {
                fields
                    .iter()
                    .map(|row| row[index].chars().count())
                    .max()
                    .unwrap_or(0)
                    .max(headings[index].chars().count())
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            headings
                .iter()
                .enumerate()
                .map(|(index, heading)| format!("{heading:<width$}", width = widths[index]))
                .collect::<Vec<_>>()
                .join("  ")
        );
        for row in &fields {
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
        for row in &fields {
            println!(
                "{}",
                row.iter()
                    .map(|field| tsv(field))
                    .collect::<Vec<_>>()
                    .join("\t")
            );
        }
    }
    Ok(())
}

fn non_empty(value: &str) -> String {
    if value.is_empty() { "-" } else { value }.to_owned()
}

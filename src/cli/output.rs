use dexq::resource::Location;
use serde_json::json;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Row {
    pub(super) apk: String,
    pub(super) dex: String,
    pub(super) kind: char,
    pub(super) descriptor: String,
    pub(super) original: Option<String>,
    pub(super) source: Option<String>,
}

pub(super) fn print_output(output: &[Row], json: bool, aligned: bool) -> Result<(), String> {
    if json {
        let values = output
            .iter()
            .map(|row| {
                json!({
                    "apk": row.apk, "dex": row.dex, "type": row.kind.to_string(),
                    "descriptor": row.descriptor, "original": row.original, "source": row.source,
                })
            })
            .collect::<Vec<_>>();

        println!(
            "{}",
            serde_json::to_string(&values).map_err(|error| error.to_string())?
        );
    } else if aligned {
        print_aligned(output);
    } else {
        println!("APK\tDEX\tTYPE\tDESCRIPTOR\tORIGINAL\tSOURCE");

        for row in output {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                tsv(&row.apk),
                tsv(&row.dex),
                row.kind,
                tsv(&row.descriptor),
                tsv(row.original.as_deref().unwrap_or_default()),
                tsv(row.source.as_deref().unwrap_or_default())
            );
        }
    }

    Ok(())
}

fn print_aligned(output: &[Row]) {
    let apk_width = output
        .iter()
        .map(|row| row.apk.chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    let dex_width = output
        .iter()
        .map(|row| row.dex.chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    let descriptor_width = output
        .iter()
        .map(|row| row.descriptor.chars().count())
        .max()
        .unwrap_or(10)
        .max(10);

    println!(
        "{:<apk_width$}  {:<dex_width$}  TYPE  {:<descriptor_width$}  ORIGINAL  SOURCE",
        "APK", "DEX", "DESCRIPTOR"
    );

    for row in output {
        println!(
            "{:<apk_width$}  {:<dex_width$}  {:<4}  {:<descriptor_width$}  {}  {}",
            row.apk,
            row.dex,
            row.kind,
            row.descriptor,
            row.original.as_deref().unwrap_or_default(),
            row.source.as_deref().unwrap_or_default()
        );
    }
}

pub(super) fn push_aliases(
    output: &mut Vec<Row>,
    apk: &str,
    dex: &str,
    kind: char,
    descriptor: String,
    originals: Vec<String>,
    source: Option<&str>,
) {
    if originals.is_empty() {
        output.push(Row {
            apk: apk.to_owned(),
            dex: dex.to_owned(),
            kind,
            descriptor,
            original: None,
            source: source.map(str::to_owned),
        });
    } else {
        for original in originals {
            output.push(Row {
                apk: apk.to_owned(),
                dex: dex.to_owned(),
                kind,
                descriptor: descriptor.clone(),
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
    rows: &[(&str, &Location)],
    json_output: bool,
    aligned: bool,
) -> Result<(), String> {
    if json_output {
        let values = rows.iter().map(|(apk, row)| json!({
            "apk": apk, "archive": row.archive, "id": format!("0x{:08x}", row.id),
            "package": row.package, "type": row.kind, "name": row.name,
            "original": row.original,
            "config": row.config, "value": row.value, "path": row.path,
            "node": row.node, "attribute": row.attribute, "view_id": row.view_id, "line": row.line,
        })).collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string(&values).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    let headings = [
        "APK",
        "ARCHIVE",
        "ID",
        "PACKAGE",
        "TYPE",
        "NAME",
        "ORIGINAL",
        "CONFIG",
        "VALUE",
        "PATH",
        "NODE",
        "ATTRIBUTE",
        "VIEW_ID",
        "LINE",
    ];
    let fields = rows
        .iter()
        .map(|(apk, row)| {
            vec![
                (*apk).to_owned(),
                row.archive.clone(),
                format!("0x{:08x}", row.id),
                row.package.clone(),
                row.kind.clone(),
                row.name.clone(),
                row.original.clone().unwrap_or_default(),
                row.config.clone(),
                row.value.clone(),
                row.path.clone().unwrap_or_default(),
                row.node.clone().unwrap_or_default(),
                row.attribute.clone().unwrap_or_default(),
                row.view_id.clone().unwrap_or_default(),
                row.line.map(|line| line.to_string()).unwrap_or_default(),
            ]
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

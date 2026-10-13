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

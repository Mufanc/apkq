use std::path::Path;

use droidsaw_dex::DexFile;

use super::format::Dex;
use super::{
    PreparedArchive, is_classes_dex, join_label, open_archive, prepare_apk, read_dex_entry,
};

pub struct DecompiledClass {
    pub dex: String,
    pub descriptor: String,
    pub source: String,
}

pub fn decompile_apk(
    apk: &Path,
    descriptors: &[&str],
    dex: Option<&str>,
) -> Result<Vec<DecompiledClass>, String> {
    let prepared = prepare_apk(apk)?;
    let mut output = Vec::new();

    decompile_archive(&prepared, descriptors, dex, &mut output)?;

    if let Some(dex) = dex
        && output.is_empty()
    {
        return Err(format!("class was not found in DEX {dex}"));
    }

    Ok(output)
}

fn decompile_archive(
    prepared: &PreparedArchive,
    descriptors: &[&str],
    selected_dex: Option<&str>,
    output: &mut Vec<DecompiledClass>,
) -> Result<(), String> {
    let mut archive = open_archive(&prepared.bytes, &prepared.label)?;

    for entry_index in 0..archive.len() {
        let mut entry = archive
            .by_index(entry_index)
            .map_err(|error| format!("invalid ZIP entry in {}: {error}", prepared.label))?;
        let name = entry
            .name()
            .map_err(|error| format!("invalid ZIP entry name in {}: {error}", prepared.label))?
            .into_owned();

        if !is_classes_dex(&name) {
            continue;
        }

        let label = join_label(&prepared.label, &name);
        if selected_dex.is_some_and(|selected| selected != label) {
            continue;
        }

        let bytes = read_dex_entry(&prepared.bytes, &mut entry, &name, &prepared.label)?;
        let dex = Dex::parse(bytes)?;
        let descriptors = find_classes(&dex, descriptors)?;
        if descriptors.is_empty() {
            continue;
        }

        let bytes = dex.bytes();
        let parsed = DexFile::parse(bytes, None)
            .map_err(|error| format!("failed to parse {label}: {error}"))?;

        for descriptor in descriptors {
            let (_index, class) = parsed
                .find_class(&descriptor)
                .ok_or_else(|| format!("class {descriptor} disappeared while parsing {label}"))?;

            output.push(DecompiledClass {
                dex: label.clone(),
                descriptor,
                source: droidsaw_dex::classes::decompile_class(&parsed, bytes, class),
            });
        }
    }

    for nested in &prepared.nested {
        decompile_archive(nested, descriptors, selected_dex, output)?;
    }

    Ok(())
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

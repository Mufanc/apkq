use std::path::Path;

use super::mapping::Mapping;
use crate::java::JavaMethod;

use droidsaw_dex::DexFile;
use droidsaw_dex::decode;
use droidsaw_dex::smali;

use super::{
    PreparedArchive, is_classes_dex, join_label, open_archive, prepare_apk, read_dex_entry,
};

pub struct DisassembledInstruction {
    pub dex_pc: u32,
    pub instruction: String,
}

pub struct DisassembledClass {
    pub smali: String,
    pub methods: Vec<DisassembledMethod>,
}

pub struct DisassembledMethod {
    pub method: String,
    pub original: Option<String>,
    pub smali: String,
    pub instructions: Vec<DisassembledInstruction>,
}

pub fn disassemble_apk(
    apk: &Path,
    dex: &str,
    class: &str,
    selected: Option<(&str, &str)>,
    mapping: Option<&Mapping>,
) -> Result<DisassembledClass, String> {
    let prepared = prepare_apk(apk)?;

    disassemble_archive(&prepared, dex, class, selected, mapping)?
        .ok_or_else(|| format!("target {class} disappeared while parsing {dex}"))
}

fn disassemble_archive(
    prepared: &PreparedArchive,
    selected_dex: &str,
    class: &str,
    selected: Option<(&str, &str)>,
    mapping: Option<&Mapping>,
) -> Result<Option<DisassembledClass>, String> {
    let mut archive = open_archive(&prepared.bytes, &prepared.label)?;

    for entry_index in 0..archive.len() {
        let mut entry = archive
            .by_index(entry_index)
            .map_err(|error| format!("invalid ZIP entry in {}: {error}", prepared.label))?;
        let entry_name = entry
            .name()
            .map_err(|error| format!("invalid ZIP entry name in {}: {error}", prepared.label))?
            .into_owned();

        if !is_classes_dex(&entry_name) {
            continue;
        }

        let label = join_label(&prepared.label, &entry_name);
        if label != selected_dex {
            continue;
        }

        let bytes = read_dex_entry(&prepared.bytes, &mut entry, &entry_name, &prepared.label)?;
        let parsed = DexFile::parse(&bytes, None)
            .map_err(|error| format!("failed to parse {label}: {error}"))?;
        let (class_index, definition) = parsed
            .find_class(class)
            .ok_or_else(|| format!("class {class} disappeared while parsing {label}"))?;
        let methods = parsed
            .list_methods(class_index, &bytes)
            .map_err(|error| format!("failed to read methods from {label}: {error}"))?;

        let mut output = DisassembledClass {
            smali: String::new(),
            methods: Vec::new(),
        };

        if selected.is_none() {
            output.smali.push_str(&format!(
                ".class {}{class}\n",
                access_flags(definition.access_flags, false)
            ));

            if let Some(parent) = definition.superclass_idx {
                let parent = parsed
                    .get_type_descriptor(parent)
                    .map_err(|error| error.to_string())?;
                output.smali.push_str(&format!(".super {parent}\n"));
            }

            if let Some(interfaces) = parsed.type_lists.get(&definition.interfaces_off) {
                for interface in interfaces {
                    let interface = parsed
                        .get_type_descriptor(*interface)
                        .map_err(|error| error.to_string())?;
                    output.smali.push_str(&format!(".implements {interface}\n"));
                }
            }

            if definition.class_data_off != 0 {
                let data = decode::parse_class_data(&bytes, definition.class_data_off)
                    .map_err(|error| error.to_string())?;

                for field in data.static_fields.iter().chain(&data.instance_fields) {
                    let id = &parsed.fields[field.field_idx.0 as usize];
                    let name = parsed
                        .get_string(id.name_idx)
                        .map_err(|error| error.to_string())?;
                    let ty = parsed
                        .get_type_descriptor(id.type_idx)
                        .map_err(|error| error.to_string())?;
                    output.smali.push_str(&format!(
                        "\n.field {}{name}:{ty}\n",
                        access_flags(field.access_flags, true)
                    ));
                }
            }
        }

        for method in methods {
            let descriptor = method_descriptor(&method.parameters, &method.return_type);

            if selected
                .is_some_and(|(name, signature)| method.name != name || descriptor != signature)
            {
                continue;
            }

            let mut instructions = Vec::new();

            if method.has_code {
                let code = decode::parse_code_item(&bytes, method.code_off)
                    .map_err(|error| error.to_string())?;

                for instruction in &code.instructions {
                    if !code.payloads.contains_key(&instruction.addr) {
                        instructions.push(DisassembledInstruction {
                            dex_pc: instruction.addr,
                            instruction: smali::fmt_instruction(instruction, &parsed),
                        });
                    }
                }
            }

            let rendered = parsed
                .emit_smali_method(
                    &bytes,
                    method.method_idx,
                    method.access_flags,
                    method.code_off,
                )
                .map_err(|error| error.to_string())?;
            let rendered = annotate_instructions(&rendered, &instructions)?;
            let symbol = JavaMethod::from_descriptor(class, &method.name, &descriptor)?.to_string();

            output.smali.push('\n');
            output.smali.push_str(&rendered);
            output.methods.push(DisassembledMethod {
                original: mapping
                    .and_then(|mapping| {
                        let owner = mapping.original_class(class)?;
                        mapping
                            .methods(class, &method.name, &descriptor)
                            .next()
                            .map(|alias| {
                                JavaMethod::from_descriptor(owner, alias.name, alias.descriptor)
                                    .map(|method| method.to_string())
                            })
                    })
                    .transpose()?,
                method: symbol,
                smali: rendered,
                instructions,
            });
        }

        return Ok(Some(output));
    }

    for nested in &prepared.nested {
        if let Some(method) = disassemble_archive(nested, selected_dex, class, selected, mapping)? {
            return Ok(Some(method));
        }
    }

    Ok(None)
}

fn annotate_instructions(
    smali: &str,
    instructions: &[DisassembledInstruction],
) -> Result<String, String> {
    let mut pending = instructions.iter().peekable();
    let mut output = String::new();

    for line in smali.lines() {
        output.push_str(line);

        if let Some(instruction) = pending.peek()
            && line.trim() == instruction.instruction
        {
            output.push_str(&format!("  # pc={:#x}", instruction.dex_pc));
            pending.next();
        }

        output.push('\n');
    }

    if pending.next().is_some() {
        return Err("smali instruction output disagrees with decoded instructions".to_owned());
    }

    Ok(output)
}

fn access_flags(flags: u32, field: bool) -> String {
    let mut names = Vec::new();

    for (bit, name) in [
        (1, "public"),
        (2, "private"),
        (4, "protected"),
        (8, "static"),
        (16, "final"),
        (0x200, "interface"),
        (0x400, "abstract"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }

    if field {
        if flags & 0x40 != 0 {
            names.push("volatile");
        }
        if flags & 0x80 != 0 {
            names.push("transient");
        }
    }

    if names.is_empty() {
        String::new()
    } else {
        format!("{} ", names.join(" "))
    }
}

fn method_descriptor(parameters: &[String], return_type: &str) -> String {
    format!("({}){return_type}", parameters.concat())
}

#[cfg(test)]
mod tests {
    use super::{DisassembledInstruction, annotate_instructions, method_descriptor};

    #[test]
    fn annotates_only_executable_instructions() {
        let instructions = vec![DisassembledInstruction {
            dex_pc: 3,
            instruction: "return-void".to_owned(),
        }];
        let rendered = annotate_instructions(
            ".method public run()V\n    :addr_3\n    return-void\n.end method\n",
            &instructions,
        )
        .unwrap();
        assert!(rendered.contains("    return-void  # pc=0x3\n"));
        assert!(rendered.contains("    :addr_3\n"));
        assert!(annotate_instructions(".end method\n", &instructions).is_err());
    }

    #[test]
    fn builds_method_descriptor() {
        assert_eq!(
            method_descriptor(&["I".to_owned(), "Ljava/lang/String;".to_owned()], "V"),
            "(ILjava/lang/String;)V"
        );
    }
}

use super::mapping::Mapping;
use super::query::LocatedTarget;
use crate::java::{JavaClass, JavaMethod};
use std::str::FromStr;

use droidsaw_dex::DexFile;
use droidsaw_dex::decode;
use droidsaw_dex::smali;

use crate::archive::ApkArchive;

pub struct DisassembledInstruction {
    pub dex_pc: u32,
    pub instruction: String,
}

pub enum Disassembly {
    Smali(String),
    Instructions(Vec<DisassembledMethod>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DisassemblyFormat {
    Smali,
    Instructions,
}

pub struct DisassembledMethod {
    pub method: String,
    pub instructions: Vec<DisassembledInstruction>,
}

#[derive(Clone, Debug)]
pub enum DisassembleTarget {
    Class(JavaClass),
    Method(JavaMethod),
}

impl DisassembleTarget {
    pub fn from_descriptor(value: &str) -> Result<Self, String> {
        if value.contains("->") {
            JavaMethod::from_descriptor(value).map(Self::Method)
        } else {
            JavaClass::from_descriptor(value).map(Self::Class)
        }
    }
}

impl FromStr for DisassembleTarget {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.contains('#') {
            value.parse().map(Self::Method)
        } else {
            value.parse().map(Self::Class)
        }
    }
}

impl Disassembly {
    pub fn from_apk(
        prepared: &ApkArchive,
        target: &DisassembleTarget,
        selected_dex: Option<&str>,
        mapping: Option<&Mapping>,
        format: DisassemblyFormat,
    ) -> Result<(String, String, Disassembly), String> {
        let located = match target {
            DisassembleTarget::Class(query) => {
                LocatedTarget::from_class(prepared, query, selected_dex, mapping)?
            }
            DisassembleTarget::Method(query) => {
                LocatedTarget::from_method(prepared, query, selected_dex, mapping)?
            }
        };

        let selected = located
            .method
            .as_ref()
            .map(|(name, descriptor)| (name.as_str(), descriptor.as_str()));
        let result = Self::from_dex(
            &located.dex,
            &located.bytes,
            &located.class,
            selected,
            format,
        )?;

        Ok((located.dex, located.class, result))
    }

    fn from_dex(
        label: &str,
        bytes: &[u8],
        class: &str,
        selected: Option<(&str, &str)>,
        format: DisassemblyFormat,
    ) -> Result<Disassembly, String> {
        let parsed = DexFile::parse(bytes, None)
            .map_err(|error| format!("failed to parse {label}: {error}"))?;
        let (class_index, definition) = parsed
            .find_class(class)
            .ok_or_else(|| format!("class {class} disappeared while parsing {label}"))?;
        let methods = parsed
            .list_methods(class_index, bytes)
            .map_err(|error| format!("failed to read methods from {label}: {error}"))?;

        let mut smali_output = String::new();
        let mut instruction_output = Vec::new();

        if selected.is_none() && format == DisassemblyFormat::Smali {
            smali_output.push_str(&format!(
                ".class {}{class}\n",
                Self::access_flags(definition.access_flags, false)
            ));

            if let Some(parent) = definition.superclass_idx {
                let parent = parsed
                    .get_type_descriptor(parent)
                    .map_err(|error| error.to_string())?;
                smali_output.push_str(&format!(".super {parent}\n"));
            }

            if let Some(interfaces) = parsed.type_lists.get(&definition.interfaces_off) {
                for interface in interfaces {
                    let interface = parsed
                        .get_type_descriptor(*interface)
                        .map_err(|error| error.to_string())?;
                    smali_output.push_str(&format!(".implements {interface}\n"));
                }
            }

            if definition.class_data_off != 0 {
                let data = decode::parse_class_data(bytes, definition.class_data_off)
                    .map_err(|error| error.to_string())?;

                for field in data.static_fields.iter().chain(&data.instance_fields) {
                    let id = &parsed.fields[field.field_idx.0 as usize];
                    let name = parsed
                        .get_string(id.name_idx)
                        .map_err(|error| error.to_string())?;
                    let ty = parsed
                        .get_type_descriptor(id.type_idx)
                        .map_err(|error| error.to_string())?;
                    smali_output.push_str(&format!(
                        "\n.field {}{name}:{ty}\n",
                        Self::access_flags(field.access_flags, true)
                    ));
                }
            }
        }

        for method in methods {
            let descriptor = Self::method_descriptor(&method.parameters, &method.return_type);

            if selected
                .is_some_and(|(name, signature)| method.name != name || descriptor != signature)
            {
                continue;
            }

            let mut instructions = Vec::new();

            if method.has_code {
                let code = decode::parse_code_item(bytes, method.code_off)
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

            if format == DisassemblyFormat::Smali {
                let rendered = parsed
                    .emit_smali_method(
                        bytes,
                        method.method_idx,
                        method.access_flags,
                        method.code_off,
                    )
                    .map_err(|error| error.to_string())?;
                let rendered = Self::annotate_instructions(&rendered, &instructions)?;

                smali_output.push('\n');
                smali_output.push_str(&rendered);
            } else {
                let symbol = JavaMethod::from_parts(class, &method.name, &descriptor)?.to_string();

                instruction_output.push(DisassembledMethod {
                    method: symbol,
                    instructions,
                });
            }
        }

        Ok(match format {
            DisassemblyFormat::Smali => Self::Smali(smali_output),
            DisassemblyFormat::Instructions => Self::Instructions(instruction_output),
        })
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
}

#[cfg(test)]
mod tests {
    use super::{DisassembledInstruction, Disassembly};

    #[test]
    fn annotates_only_executable_instructions() {
        let instructions = vec![DisassembledInstruction {
            dex_pc: 3,
            instruction: "return-void".to_owned(),
        }];
        let rendered = Disassembly::annotate_instructions(
            ".method public run()V\n    :addr_3\n    return-void\n.end method\n",
            &instructions,
        )
        .unwrap();
        assert!(rendered.contains("    return-void  # pc=0x3\n"));
        assert!(rendered.contains("    :addr_3\n"));
        assert!(Disassembly::annotate_instructions(".end method\n", &instructions).is_err());
    }

    #[test]
    fn builds_method_descriptor() {
        assert_eq!(
            Disassembly::method_descriptor(&["I".to_owned(), "Ljava/lang/String;".to_owned()], "V"),
            "(ILjava/lang/String;)V"
        );
    }
}

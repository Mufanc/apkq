use std::borrow::Cow;

use super::code::CodeItem;
use super::filter::ResolvedFilter;
use super::format::{ClassData, Dex, EncodedValue, ProtoId};
use super::{ClassLocation, DexIndex, FieldLocation, MethodLocation, ReferenceFilter};

pub(super) fn parse_dex(
    bytes: Cow<'_, [u8]>,
    label: &str,
    filter: Option<&ReferenceFilter<'_>>,
    index: &mut DexIndex,
) -> Result<(), String> {
    let dex = Dex::parse(bytes).map_err(|error| format!("invalid DEX {label}: {error}"))?;

    let string_table = dex.strings();
    let strings = (0..string_table.len())
        .map(|index| string_table.get(index)?.value().map(Cow::into_owned))
        .collect::<Result<Vec<_>, _>>()?;

    let type_table = dex.types();
    let types = (0..type_table.len())
        .map(|index| type_table.get(index).map(|item| item.descriptor_index()))
        .collect::<Result<Vec<_>, _>>()?;

    let prototype_table = dex.prototypes();
    let prototypes = (0..prototype_table.len())
        .map(|index| {
            let prototype = prototype_table.get(index)?;
            prototype_descriptor(&prototype, &types, &strings)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let field_table = dex.fields();
    let fields = (0..field_table.len())
        .map(|index| {
            let field = field_table.get(index)?;
            Ok(FieldId {
                class: string_for_type(&types, &strings, field.class_index())?.to_owned(),
                name: strings
                    .get(field.name_index())
                    .ok_or_else(|| format!("bad field name index in {label}"))?
                    .clone(),
                descriptor: string_for_type(&types, &strings, field.type_index())?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let method_table = dex.methods();
    let methods = (0..method_table.len())
        .map(|index| {
            let method = method_table.get(index)?;
            let descriptor = prototypes
                .get(method.prototype_index())
                .ok_or_else(|| format!("bad prototype index in {label}"))?
                .clone();
            Ok(MethodId {
                class: string_for_type(&types, &strings, method.class_index())?.to_owned(),
                name: strings
                    .get(method.name_index())
                    .ok_or_else(|| format!("bad method name index in {label}"))?
                    .clone(),
                descriptor,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut static_strings_by_field = vec![None; fields.len()];

    if filter.is_some_and(|filter| !filter.strings.is_empty()) {
        collect_static_strings(&dex, &mut static_strings_by_field)?;
    }

    let resolved = filter.map(|filter| {
        ResolvedFilter::new(
            filter,
            &strings,
            &types,
            &fields,
            &methods,
            &static_strings_by_field,
        )
    });

    let classes = dex.classes();

    for class_index in 0..classes.len() {
        let class_def = classes.get(class_index)?;
        let class = string_for_type(&types, &strings, class_def.class_index())?.to_owned();
        let superclass = class_def
            .superclass_index()
            .map(|index| string_for_type(&types, &strings, index).map(str::to_owned))
            .transpose()?;
        let source_file = class_def
            .source_index()
            .map(|index| {
                strings
                    .get(index)
                    .cloned()
                    .ok_or_else(|| format!("bad source file index in {label}"))
            })
            .transpose()?;
        let mut interfaces = Vec::new();

        if let Some(type_list) = class_def.interfaces()? {
            interfaces.reserve(type_list.len());
            for type_index in 0..type_list.len() {
                interfaces.push(
                    string_for_type(&types, &strings, type_list.type_index(type_index)?)?
                        .to_owned(),
                );
            }
        }

        index.classes.push(ClassLocation {
            dex: label.to_owned(),
            class: class.clone(),
            superclass,
            interfaces,
            source_file: source_file.clone(),
        });

        if let Some(class_data) = class_def.data()? {
            index_class_data(
                class_data,
                dex.bytes(),
                label,
                &class,
                source_file.as_deref(),
                &fields,
                &methods,
                resolved.as_ref(),
                index,
            )?;
        }
    }

    Ok(())
}

fn prototype_descriptor(
    prototype: &ProtoId<'_>,
    types: &[usize],
    strings: &[String],
) -> Result<String, String> {
    let mut descriptor = "(".to_owned();

    if let Some(parameters) = prototype.parameters()? {
        for index in 0..parameters.len() {
            descriptor.push_str(string_for_type(
                types,
                strings,
                parameters.type_index(index)?,
            )?);
        }
    }

    descriptor.push(')');
    descriptor.push_str(string_for_type(
        types,
        strings,
        prototype.return_type_index(),
    )?);

    Ok(descriptor)
}

fn string_for_type<'a>(
    types: &[usize],
    strings: &'a [String],
    type_index: usize,
) -> Result<&'a str, String> {
    let string_index = *types
        .get(type_index)
        .ok_or_else(|| format!("bad type index {type_index}"))?;
    strings
        .get(string_index)
        .map(String::as_str)
        .ok_or_else(|| format!("bad descriptor string index {string_index}"))
}

fn collect_static_strings(
    dex: &Dex<'_>,
    strings_by_field: &mut [Option<usize>],
) -> Result<(), String> {
    let classes = dex.classes();

    for class_index in 0..classes.len() {
        let class_def = classes.get(class_index)?;
        let (Some(mut class_data), Some(mut values)) =
            (class_def.data()?, class_def.static_values()?)
        else {
            continue;
        };

        let mut static_fields = Vec::new();

        while let Some(field) = class_data.next_field()? {
            if !field.is_static() {
                break;
            }
            static_fields.push(field.index());
        }

        if values.len() > static_fields.len() {
            return Err("static_values has more values than static fields".to_owned());
        }

        for field_index in static_fields.into_iter().take(values.len()) {
            if let Some(EncodedValue::String(string_index)) = values.next()? {
                let value = strings_by_field
                    .get_mut(field_index)
                    .ok_or("static field index is out of bounds")?;
                *value = Some(string_index);
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn index_class_data(
    mut class_data: ClassData<'_>,
    bytes: &[u8],
    label: &str,
    class: &str,
    source_file: Option<&str>,
    fields: &[FieldId],
    methods: &[MethodId],
    filter: Option<&ResolvedFilter>,
    index: &mut DexIndex,
) -> Result<(), String> {
    while let Some(encoded) = class_data.next_field()? {
        let field = fields
            .get(encoded.index())
            .ok_or_else(|| format!("bad encoded field index in {label}"))?;

        index.fields.push(FieldLocation {
            dex: label.to_owned(),
            class: if field.class == class {
                class.to_owned()
            } else {
                field.class.clone()
            },
            field: field.name.clone(),
            descriptor: field.descriptor.clone(),
            source_file: source_file.map(str::to_owned),
        });
    }

    while let Some(encoded) = class_data.next_method()? {
        let method = methods
            .get(encoded.index())
            .ok_or_else(|| format!("bad encoded method index in {label}"))?;

        if let Some(filter) = filter {
            let Some(code_offset) = encoded.code_offset() else {
                continue;
            };
            let references = CodeItem::parse(bytes, code_offset)?.references()?;
            filter.validate(&references)?;

            if !filter.matches(&references) {
                continue;
            }
        }

        index.locations.push(MethodLocation {
            dex: label.to_owned(),
            class: if method.class == class {
                class.to_owned()
            } else {
                method.class.clone()
            },
            method: method.name.clone(),
            descriptor: method.descriptor.clone(),
            source_file: source_file.map(str::to_owned),
        });
    }

    Ok(())
}

pub(super) struct MethodId {
    pub(super) class: String,
    pub(super) name: String,
    pub(super) descriptor: String,
}

pub(super) struct FieldId {
    pub(super) class: String,
    pub(super) name: String,
    pub(super) descriptor: String,
}

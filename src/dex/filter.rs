use super::ReferenceFilter;
use super::code::CodeReferences;
use super::parse::{FieldId, MethodId};

pub(super) struct ResolvedFilter {
    pub(super) strings: Vec<Vec<bool>>,
    pub(super) static_fields: Vec<Vec<bool>>,
    pub(super) calls: Vec<Vec<bool>>,
    pub(super) types: Vec<Vec<bool>>,
    pub(super) fields: Vec<Vec<bool>>,
    pub(super) string_count: usize,
    pub(super) type_count: usize,
    pub(super) field_count: usize,
    pub(super) method_count: usize,
}

impl ResolvedFilter {
    pub(super) fn new(
        filter: &ReferenceFilter<'_>,
        strings: &[String],
        types: &[usize],
        fields: &[FieldId],
        methods: &[MethodId],
        static_strings_by_field: &[Option<usize>],
    ) -> Self {
        let type_count = types.len();
        let field_count = fields.len();

        let strings_matched = filter
            .strings
            .iter()
            .map(|query| {
                strings
                    .iter()
                    .map(|value| value.contains(query))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let static_fields = strings_matched
            .iter()
            .map(|matched| {
                static_strings_by_field
                    .iter()
                    .map(|string_idx| {
                        string_idx
                            .and_then(|idx| matched.get(idx))
                            .copied()
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .collect();
        let calls = filter
            .calls
            .iter()
            .map(|query| {
                methods
                    .iter()
                    .map(|method| {
                        super::method_matches(
                            query,
                            &method.class,
                            &method.name,
                            &method.descriptor,
                            filter.mapping,
                        )
                    })
                    .collect()
            })
            .collect();
        let types = filter
            .types
            .iter()
            .map(|query| {
                types
                    .iter()
                    .map(|&string_idx| {
                        strings.get(string_idx).is_some_and(|value| {
                            value == query.descriptor()
                                || filter
                                    .mapping
                                    .and_then(|mapping| mapping.original_class(value))
                                    .is_some_and(|alias| alias == query.descriptor())
                        })
                    })
                    .collect()
            })
            .collect();
        let fields = filter
            .fields
            .iter()
            .map(|query| {
                fields
                    .iter()
                    .map(|field| {
                        query.matches(&field.class, &field.name, &field.descriptor)
                            || filter.mapping.is_some_and(|mapping| {
                                mapping.original_class(&field.class).is_some_and(|class| {
                                    mapping
                                        .fields(&field.class, &field.name, &field.descriptor)
                                        .any(|alias| {
                                            query.matches(class, alias.name, alias.descriptor)
                                        })
                                })
                            })
                    })
                    .collect()
            })
            .collect();

        Self {
            strings: strings_matched,
            static_fields,
            calls,
            types,
            fields,
            string_count: strings.len(),
            type_count,
            field_count,
            method_count: methods.len(),
        }
    }

    pub(super) fn validate(&self, refs: &CodeReferences) -> Result<(), String> {
        for (indices, size, kind) in [
            (&refs.strings, self.string_count, "string"),
            (&refs.types, self.type_count, "type"),
            (&refs.fields, self.field_count, "field"),
            (&refs.static_fields, self.field_count, "static field"),
            (&refs.methods, self.method_count, "method"),
        ] {
            if indices.iter().any(|(index, _)| *index >= size) {
                return Err(format!("bad {kind} reference index"));
            }
        }

        Ok(())
    }

    pub(super) fn matches(&self, refs: &CodeReferences) -> bool {
        self.strings
            .iter()
            .zip(&self.static_fields)
            .all(|(strings, fields)| {
                refs.strings
                    .iter()
                    .any(|(idx, _)| strings.get(*idx) == Some(&true))
                    || refs
                        .static_fields
                        .iter()
                        .any(|(idx, _)| fields.get(*idx) == Some(&true))
            })
            && self.calls.iter().all(|matched| {
                refs.methods
                    .iter()
                    .any(|(idx, _)| matched.get(*idx) == Some(&true))
            })
            && self.types.iter().all(|matched| {
                refs.types
                    .iter()
                    .any(|(idx, _)| matched.get(*idx) == Some(&true))
            })
            && self.fields.iter().all(|matched| {
                refs.fields
                    .iter()
                    .any(|(idx, _)| matched.get(*idx) == Some(&true))
            })
    }
}

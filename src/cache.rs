use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use directories::ProjectDirs;
use rkyv::rancor::Error;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Serialize};

use crate::dex::{
    self, CalledMethodRef, ClassLocationRef, DexIndex, DexSource, DexStats, FieldLocationRef,
    MethodLocationRef, ReferenceKind, StringSiteRef,
};

const CACHE_MAGIC: [u8; 8] = *b"DEXQ0002";
const CACHE_VERSION: u32 = 2;
const NO_TEXT: u32 = u32::MAX;

#[derive(Archive, Serialize)]
struct CacheData {
    magic: [u8; 8],
    version: u32,
    fingerprint: [u8; 32],
    text: Vec<u8>,
    classes: Vec<CachedClass>,
    locations: Vec<CachedLocation>,
    fields: Vec<CachedField>,
    strings: Vec<CachedString>,
    interfaces: Vec<TextRange>,
    called_methods: Vec<CachedCalledMethod>,
    caller_ids: Vec<u32>,
    site_location_ids: Vec<u32>,
    site_pcs: Vec<u32>,
    site_kinds: Vec<u8>,
    stats: CachedStats,
}

#[derive(Archive, Clone, Copy, Serialize)]
struct TextRange {
    offset: u32,
    length: u32,
}

#[derive(Archive, Serialize)]
struct CachedLocation {
    class_id: u32,
    method: TextRange,
    descriptor: TextRange,
}

#[derive(Archive, Serialize)]
struct CachedClass {
    dex: TextRange,
    class: TextRange,
    superclass: TextRange,
    interface_start: u32,
    interface_count: u32,
    source_file: TextRange,
}

#[derive(Archive, Serialize)]
struct CachedCalledMethod {
    class: TextRange,
    method: TextRange,
    descriptor: TextRange,
    caller_start: u32,
    caller_count: u32,
}

#[derive(Archive, Serialize)]
struct CachedField {
    class_id: u32,
    field: TextRange,
    descriptor: TextRange,
}

#[derive(Archive, Serialize)]
struct CachedString {
    value: TextRange,
    site_start: u32,
    site_count: u32,
}

#[derive(Archive, Serialize)]
struct CachedStats {
    archives: u64,
    dex_files: u64,
    strings: u64,
    methods_with_code: u64,
    referenced_strings: u64,
    const_string_references: u64,
    static_value_fields: u64,
    static_value_references: u64,
}

pub struct CacheLoad {
    pub cache_bytes: u64,
    pub cache_hit: bool,
    pub cache_path: PathBuf,
    pub index_seconds: f64,
    pub prepare_seconds: f64,
    pub storage_seconds: f64,
    pub index: LoadedDexIndex,
}

pub struct LoadedDexIndex {
    bytes: AlignedVec,
}

#[derive(Clone, Copy)]
pub struct DexIndexView<'a> {
    archived: &'a ArchivedCacheData,
    pub stats: DexStats,
}

impl LoadedDexIndex {
    pub fn view(&self) -> Result<DexIndexView<'_>, String> {
        let archived = rkyv::access::<ArchivedCacheData, Error>(&self.bytes)
            .map_err(|error| format!("invalid loaded cache: {error}"))?;
        Ok(DexIndexView {
            archived,
            stats: stats_from_archived(&archived.stats),
        })
    }
}

impl<'a> DexIndexView<'a> {
    pub fn class_count(self) -> usize {
        self.archived.classes.len()
    }

    pub fn class(self, index: usize) -> Result<ClassLocationRef<'a>, String> {
        let location = self
            .archived
            .classes
            .get(index)
            .ok_or_else(|| format!("cached class index out of bounds: {index}"))?;
        let source_file = (location.source_file.offset.to_native() != NO_TEXT)
            .then(|| self.text(&location.source_file))
            .transpose()?;
        let superclass = (location.superclass.offset.to_native() != NO_TEXT)
            .then(|| self.text(&location.superclass))
            .transpose()?;
        Ok(ClassLocationRef {
            dex: self.text(&location.dex)?,
            class: self.text(&location.class)?,
            superclass,
            source_file,
        })
    }

    pub fn class_interfaces(
        self,
        index: usize,
    ) -> Result<impl Iterator<Item = Result<&'a str, String>> + 'a, String> {
        let location = self
            .archived
            .classes
            .get(index)
            .ok_or_else(|| format!("cached class index out of bounds: {index}"))?;
        let start = location.interface_start.to_native() as usize;
        let end = start
            .checked_add(location.interface_count.to_native() as usize)
            .ok_or("cached interface range overflow")?;
        let interfaces = self
            .archived
            .interfaces
            .get(start..end)
            .ok_or("cached interface range is invalid")?;
        Ok(interfaces.iter().map(move |interface| self.text(interface)))
    }

    pub fn method_count(self) -> usize {
        self.archived.locations.len()
    }

    pub fn field_count(self) -> usize {
        self.archived.fields.len()
    }

    pub fn called_method_count(self) -> usize {
        self.archived.called_methods.len()
    }

    pub fn called_method(self, index: usize) -> Result<CalledMethodRef<'a>, String> {
        let method = self
            .archived
            .called_methods
            .get(index)
            .ok_or_else(|| format!("cached called method index out of bounds: {index}"))?;
        Ok(CalledMethodRef {
            class: self.text(&method.class)?,
            method: self.text(&method.method)?,
            descriptor: self.text(&method.descriptor)?,
        })
    }

    pub fn called_methods_named(self, name: &str) -> Result<std::ops::Range<usize>, String> {
        Ok(self.called_method_bound(name, false)?..self.called_method_bound(name, true)?)
    }

    pub fn callers(self, index: usize) -> Result<impl Iterator<Item = usize> + 'a, String> {
        let method = self
            .archived
            .called_methods
            .get(index)
            .ok_or_else(|| format!("cached called method index out of bounds: {index}"))?;
        let start = method.caller_start.to_native() as usize;
        let end = start
            .checked_add(method.caller_count.to_native() as usize)
            .ok_or("cached caller range overflow")?;
        let callers = self
            .archived
            .caller_ids
            .get(start..end)
            .ok_or("cached caller range is invalid")?;
        Ok(callers.iter().map(|caller| caller.to_native() as usize))
    }

    pub fn field(self, index: usize) -> Result<FieldLocationRef<'a>, String> {
        let location = self
            .archived
            .fields
            .get(index)
            .ok_or_else(|| format!("cached field index out of bounds: {index}"))?;
        let class = self.cached_class(location.class_id.to_native() as usize)?;
        let source_file = self.source_file(class)?;
        Ok(FieldLocationRef {
            dex: self.text(&class.dex)?,
            class: self.text(&class.class)?,
            field: self.text(&location.field)?,
            descriptor: self.text(&location.descriptor)?,
            source_file,
        })
    }

    pub fn string_count(self) -> usize {
        self.archived.strings.len()
    }

    pub fn string_value(self, index: usize) -> Result<&'a str, String> {
        let value = self
            .archived
            .strings
            .get(index)
            .ok_or_else(|| format!("cached string index out of bounds: {index}"))?;
        self.text(&value.value)
    }

    pub fn string_site_count(self, index: usize) -> Result<usize, String> {
        let value = self
            .archived
            .strings
            .get(index)
            .ok_or_else(|| format!("cached string index out of bounds: {index}"))?;
        Ok(value.site_count.to_native() as usize)
    }

    pub fn string_sites(
        self,
        index: usize,
    ) -> Result<impl Iterator<Item = StringSiteRef> + 'a, String> {
        let value = self
            .archived
            .strings
            .get(index)
            .ok_or_else(|| format!("cached string index out of bounds: {index}"))?;
        let start = value.site_start.to_native() as usize;
        let count = value.site_count.to_native() as usize;
        let end = start
            .checked_add(count)
            .ok_or("cached site range overflow")?;
        let location_ids = self
            .archived
            .site_location_ids
            .get(start..end)
            .ok_or("cached location site range is invalid")?;
        let pcs = self
            .archived
            .site_pcs
            .get(start..end)
            .ok_or("cached pc site range is invalid")?;
        let kinds = self
            .archived
            .site_kinds
            .get(start..end)
            .ok_or("cached kind site range is invalid")?;
        Ok(location_ids
            .iter()
            .zip(pcs)
            .zip(kinds)
            .map(|((location_id, pc), kind)| StringSiteRef {
                location_id: location_id.to_native() as usize,
                pc: pc.to_native(),
                kind: if *kind == 0 {
                    ReferenceKind::ConstString
                } else {
                    ReferenceKind::StaticValue
                },
            }))
    }

    pub fn location(self, index: usize) -> Result<MethodLocationRef<'a>, String> {
        let location = self
            .archived
            .locations
            .get(index)
            .ok_or_else(|| format!("cached location index out of bounds: {index}"))?;
        let class = self.cached_class(location.class_id.to_native() as usize)?;
        let source_file = self.source_file(class)?;
        Ok(MethodLocationRef {
            dex: self.text(&class.dex)?,
            class: self.text(&class.class)?,
            method: self.text(&location.method)?,
            descriptor: self.text(&location.descriptor)?,
            source_file,
        })
    }

    fn cached_class(self, index: usize) -> Result<&'a ArchivedCachedClass, String> {
        self.archived
            .classes
            .get(index)
            .ok_or_else(|| format!("cached class index out of bounds: {index}"))
    }

    fn called_method_bound(self, name: &str, after_equal: bool) -> Result<usize, String> {
        let mut low = 0;
        let mut high = self.called_method_count();
        while low < high {
            let middle = low + (high - low) / 2;
            let method = self.called_method(middle)?.method;
            if method < name || (after_equal && method == name) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        Ok(low)
    }

    fn source_file(self, class: &'a ArchivedCachedClass) -> Result<Option<&'a str>, String> {
        (class.source_file.offset.to_native() != NO_TEXT)
            .then(|| self.text(&class.source_file))
            .transpose()
    }

    fn text(self, range: &ArchivedTextRange) -> Result<&'a str, String> {
        let start = range.offset.to_native() as usize;
        let length = range.length.to_native() as usize;
        let end = start
            .checked_add(length)
            .ok_or("cached text range overflow")?;
        let bytes = self
            .archived
            .text
            .get(start..end)
            .ok_or("cached text range is invalid")?;
        std::str::from_utf8(bytes).map_err(|error| format!("cached text is not UTF-8: {error}"))
    }
}

impl DexSource for DexIndexView<'_> {
    fn stats(&self) -> DexStats {
        self.stats
    }

    fn string_count(&self) -> usize {
        (*self).string_count()
    }

    fn string_value(&self, index: usize) -> Result<&str, String> {
        (*self).string_value(index)
    }

    fn string_site_count(&self, index: usize) -> Result<usize, String> {
        (*self).string_site_count(index)
    }

    fn visit_string_sites(
        &self,
        index: usize,
        visit: &mut dyn FnMut(StringSiteRef),
    ) -> Result<(), String> {
        for site in (*self).string_sites(index)? {
            visit(site);
        }
        Ok(())
    }

    fn location(&self, index: usize) -> Result<MethodLocationRef<'_>, String> {
        (*self).location(index)
    }
}

pub fn load_or_build(apk: &Path) -> Result<CacheLoad, String> {
    let prepare_started = Instant::now();
    let prepared = dex::prepare_apk(apk)?;
    let prepare_seconds = prepare_started.elapsed().as_secs_f64();
    let fingerprint = prepared.fingerprint();
    let cache_path = cache_path(fingerprint)?;
    let storage_started = Instant::now();
    if cache_path.is_file()
        && let Ok(index) = load_cache(&cache_path, fingerprint)
    {
        return Ok(CacheLoad {
            cache_bytes: cache_size(&cache_path)?,
            cache_hit: true,
            cache_path,
            index_seconds: 0.0,
            prepare_seconds,
            storage_seconds: storage_started.elapsed().as_secs_f64(),
            index,
        });
    }

    let index_started = Instant::now();
    let parsed = dex::index_prepared(&prepared)?;
    let index_seconds = index_started.elapsed().as_secs_f64();
    let storage_started = Instant::now();
    write_cache(&cache_path, fingerprint, &parsed)?;
    let index = load_cache(&cache_path, fingerprint)?;
    Ok(CacheLoad {
        cache_bytes: cache_size(&cache_path)?,
        cache_hit: false,
        cache_path,
        index_seconds,
        prepare_seconds,
        storage_seconds: storage_started.elapsed().as_secs_f64(),
        index,
    })
}

fn cache_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn cache_path(fingerprint: [u8; 32]) -> Result<PathBuf, String> {
    let root = if let Some(path) = env::var_os("DEXQ_CACHE_DIR") {
        PathBuf::from(path)
    } else {
        ProjectDirs::from("", "", "dexq")
            .ok_or("failed to locate the system cache directory")?
            .cache_dir()
            .join("v2")
    };
    let name = blake3::Hash::from_bytes(fingerprint).to_hex();
    Ok(root.join(format!("{name}.rkyv")))
}

fn write_cache(path: &Path, fingerprint: [u8; 32], parsed: &DexIndex) -> Result<(), String> {
    let parent = path.parent().ok_or("cache path has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    let data = compact(parsed, fingerprint)?;
    let bytes = rkyv::to_bytes::<Error>(&data)
        .map_err(|error| format!("failed to serialize DEX cache: {error}"))?;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temporary, &bytes).map_err(|error| format!("{}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| {
        format!(
            "failed to publish cache {} as {}: {error}",
            temporary.display(),
            path.display()
        )
    })
}

fn load_cache(path: &Path, fingerprint: [u8; 32]) -> Result<LoadedDexIndex, String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = AlignedVec::new();
    io::copy(&mut file, &mut bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    let archived = rkyv::access::<ArchivedCacheData, Error>(&bytes)
        .map_err(|error| format!("invalid cache {}: {error}", path.display()))?;
    if archived.magic != CACHE_MAGIC
        || archived.version != CACHE_VERSION
        || archived.fingerprint != fingerprint
    {
        return Err(format!("cache header mismatch: {}", path.display()));
    }
    Ok(LoadedDexIndex { bytes })
}

fn compact(parsed: &DexIndex, fingerprint: [u8; 32]) -> Result<CacheData, String> {
    let mut text = Vec::new();
    let mut interned = HashMap::new();
    let mut class_ids = HashMap::new();
    let mut classes = Vec::with_capacity(parsed.classes.len());
    let mut interfaces = Vec::new();
    for (class_id, location) in parsed.classes.iter().enumerate() {
        class_ids.insert(
            (location.dex.as_str(), location.class.as_str()),
            u32::try_from(class_id).map_err(|_| "too many classes")?,
        );
        let interface_start = u32::try_from(interfaces.len()).map_err(|_| "too many interfaces")?;
        for interface in &location.interfaces {
            interfaces.push(intern(interface, &mut interned, &mut text)?);
        }
        classes.push(CachedClass {
            dex: intern(&location.dex, &mut interned, &mut text)?,
            class: intern(&location.class, &mut interned, &mut text)?,
            superclass: optional_text(location.superclass.as_deref(), &mut interned, &mut text)?,
            interface_start,
            interface_count: u32::try_from(location.interfaces.len())
                .map_err(|_| "too many interfaces")?,
            source_file: optional_text(location.source_file.as_deref(), &mut interned, &mut text)?,
        });
    }
    let mut locations = Vec::with_capacity(parsed.locations.len());
    for location in &parsed.locations {
        locations.push(CachedLocation {
            class_id: *class_ids
                .get(&(location.dex.as_str(), location.class.as_str()))
                .ok_or("method owner class is missing")?,
            method: intern(&location.method, &mut interned, &mut text)?,
            descriptor: intern(&location.descriptor, &mut interned, &mut text)?,
        });
    }
    let mut fields = Vec::with_capacity(parsed.fields.len());
    for location in &parsed.fields {
        fields.push(CachedField {
            class_id: *class_ids
                .get(&(location.dex.as_str(), location.class.as_str()))
                .ok_or("field owner class is missing")?,
            field: intern(&location.field, &mut interned, &mut text)?,
            descriptor: intern(&location.descriptor, &mut interned, &mut text)?,
        });
    }

    let mut strings = Vec::with_capacity(parsed.strings.len());
    let mut site_location_ids = Vec::new();
    let mut site_pcs = Vec::new();
    let mut site_kinds = Vec::new();
    for string in &parsed.strings {
        let site_start = u32::try_from(site_location_ids.len()).map_err(|_| "too many sites")?;
        let site_count = u32::try_from(string.sites.len()).map_err(|_| "too many sites")?;
        for site in &string.sites {
            site_location_ids
                .push(u32::try_from(site.location_id).map_err(|_| "too many method locations")?);
            site_pcs.push(site.pc);
            site_kinds.push(match site.kind {
                ReferenceKind::ConstString => 0,
                ReferenceKind::StaticValue => 1,
            });
        }
        strings.push(CachedString {
            value: intern(&string.value, &mut interned, &mut text)?,
            site_start,
            site_count,
        });
    }

    let mut called = parsed.called_methods.iter().collect::<Vec<_>>();
    called.sort_unstable_by(|left, right| {
        (&left.method, &left.class, &left.descriptor).cmp(&(
            &right.method,
            &right.class,
            &right.descriptor,
        ))
    });
    let mut called_methods = Vec::new();
    let mut caller_ids = Vec::new();
    let mut index = 0;
    while let Some(method) = called.get(index) {
        let mut end = index + 1;
        while called.get(end).is_some_and(|candidate| {
            candidate.class == method.class
                && candidate.method == method.method
                && candidate.descriptor == method.descriptor
        }) {
            end += 1;
        }
        let mut callers = called[index..end]
            .iter()
            .flat_map(|method| method.callers.iter().copied())
            .collect::<Vec<_>>();
        callers.sort_unstable();
        callers.dedup();
        let caller_start = u32::try_from(caller_ids.len()).map_err(|_| "too many callers")?;
        for caller in callers {
            caller_ids.push(u32::try_from(caller).map_err(|_| "too many method locations")?);
        }
        called_methods.push(CachedCalledMethod {
            class: intern(&method.class, &mut interned, &mut text)?,
            method: intern(&method.method, &mut interned, &mut text)?,
            descriptor: intern(&method.descriptor, &mut interned, &mut text)?,
            caller_start,
            caller_count: u32::try_from(caller_ids.len()).map_err(|_| "too many callers")?
                - caller_start,
        });
        index = end;
    }

    Ok(CacheData {
        magic: CACHE_MAGIC,
        version: CACHE_VERSION,
        fingerprint,
        text,
        classes,
        locations,
        fields,
        strings,
        interfaces,
        called_methods,
        caller_ids,
        site_location_ids,
        site_pcs,
        site_kinds,
        stats: CachedStats::from(&parsed.stats),
    })
}

fn optional_text<'a>(
    value: Option<&'a str>,
    interned: &mut HashMap<&'a str, TextRange>,
    text: &mut Vec<u8>,
) -> Result<TextRange, String> {
    value
        .map(|value| intern(value, interned, text))
        .transpose()
        .map(|range| {
            range.unwrap_or(TextRange {
                offset: NO_TEXT,
                length: 0,
            })
        })
}

fn intern<'a>(
    value: &'a str,
    interned: &mut HashMap<&'a str, TextRange>,
    text: &mut Vec<u8>,
) -> Result<TextRange, String> {
    if let Some(range) = interned.get(value) {
        return Ok(*range);
    }
    let range = TextRange {
        offset: u32::try_from(text.len()).map_err(|_| "cached text exceeds 4 GiB")?,
        length: u32::try_from(value.len()).map_err(|_| "cached string exceeds 4 GiB")?,
    };
    text.extend_from_slice(value.as_bytes());
    interned.insert(value, range);
    Ok(range)
}

impl From<&DexStats> for CachedStats {
    fn from(stats: &DexStats) -> Self {
        Self {
            archives: stats.archives as u64,
            dex_files: stats.dex_files as u64,
            strings: stats.strings as u64,
            methods_with_code: stats.methods_with_code as u64,
            referenced_strings: stats.referenced_strings as u64,
            const_string_references: stats.const_string_references as u64,
            static_value_fields: stats.static_value_fields as u64,
            static_value_references: stats.static_value_references as u64,
        }
    }
}

fn stats_from_archived(stats: &ArchivedCachedStats) -> DexStats {
    DexStats {
        archives: stats.archives.to_native() as usize,
        dex_files: stats.dex_files.to_native() as usize,
        strings: stats.strings.to_native() as usize,
        methods_with_code: stats.methods_with_code.to_native() as usize,
        referenced_strings: stats.referenced_strings.to_native() as usize,
        const_string_references: stats.const_string_references.to_native() as usize,
        static_value_fields: stats.static_value_fields.to_native() as usize,
        static_value_references: stats.static_value_references.to_native() as usize,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rkyv::rancor::Error;

    use super::{LoadedDexIndex, TextRange, compact, intern};
    use crate::dex::{CalledMethod, ClassLocation, DexIndex, DexStats, MethodLocation};

    #[test]
    fn interns_text_once() {
        let mut text = Vec::new();
        let mut interned = HashMap::new();
        let first = intern("same", &mut interned, &mut text).unwrap();
        let second = intern("same", &mut interned, &mut text).unwrap();
        assert_eq!(first.offset, second.offset);
        assert_eq!(text, b"same");
        let _range: TextRange = first;
    }

    #[test]
    fn compacts_callers_and_class_relations() {
        let parsed = DexIndex {
            classes: vec![ClassLocation {
                dex: "classes.dex".to_owned(),
                class: "LChild;".to_owned(),
                superclass: Some("LParent;".to_owned()),
                interfaces: vec!["LRunnable;".to_owned()],
                source_file: Some("Child.java".to_owned()),
            }],
            locations: vec![MethodLocation {
                dex: "classes.dex".to_owned(),
                class: "LChild;".to_owned(),
                method: "run".to_owned(),
                descriptor: "()V".to_owned(),
                source_file: Some("Child.java".to_owned()),
            }],
            fields: Vec::new(),
            strings: Vec::new(),
            called_methods: vec![CalledMethod {
                class: "LTarget;".to_owned(),
                method: "work".to_owned(),
                descriptor: "()V".to_owned(),
                callers: vec![0, 0],
            }],
            stats: DexStats::default(),
        };
        let data = compact(&parsed, [0; 32]).unwrap();
        let index = LoadedDexIndex {
            bytes: rkyv::to_bytes::<Error>(&data).unwrap(),
        };
        let view = index.view().unwrap();

        let class = view.class(0).unwrap();
        assert_eq!(class.superclass, Some("LParent;"));
        assert_eq!(
            view.class_interfaces(0)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            ["LRunnable;"]
        );
        assert_eq!(view.called_methods_named("work").unwrap(), 0..1);
        assert_eq!(view.callers(0).unwrap().collect::<Vec<_>>(), [0]);
    }
}

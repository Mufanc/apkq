use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crc32fast::Hasher;
use rkyv::rancor::Error;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Serialize};

use crate::input::FileSpec;

const FORMAT: &[u8] = b"apkq-mapping-cache-v4\0";
static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) enum Cache<T> {
    Parsed(T),
    Archived(ArchivedBytes),
}

#[derive(Debug)]
pub(crate) struct ArchivedBytes(AlignedVec);

impl AsRef<[u8]> for ArchivedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn load<T, A>(
    kind: &str,
    spec: &str,
    parse: impl FnOnce(&[u8]) -> Result<T, String>,
    validate: impl Fn(&[u8]) -> bool,
) -> Result<Cache<T>, String>
where
    T: Archive<Archived = A>
        + for<'a> Serialize<
            rkyv::api::high::HighSerializer<
                AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                Error,
            >,
        >,
{
    let source = FileSpec::open(spec)?;
    let path = cache_path(kind, source.size(), source.crc32());

    if let Some(bytes) = path.as_deref().and_then(|path| read(path, &validate)) {
        return Ok(Cache::Archived(bytes));
    }

    let mapping = parse(&source.into_bytes(spec)?)?;

    if let Some(path) = path {
        write(&path, &mapping);
    }

    Ok(Cache::Parsed(mapping))
}

fn cache_path(kind: &str, size: u64, content_crc32: u32) -> Option<PathBuf> {
    let root = cache_root()?;
    let mut metadata = Hasher::new();

    metadata.update(FORMAT);
    metadata.update(&size.to_le_bytes());

    Some(root.join(format!(
        "{kind}-{:08x}-{content_crc32:08x}.bin",
        metadata.finalize()
    )))
}

fn cache_root() -> Option<PathBuf> {
    if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(path).join("apkq"));
    }

    if cfg!(target_os = "windows") {
        return env::var_os("LOCALAPPDATA").map(|path| PathBuf::from(path).join("apkq"));
    }

    let home = env::var_os("HOME").map(PathBuf::from)?;

    if cfg!(target_os = "macos") {
        Some(home.join("Library/Caches/apkq"))
    } else {
        Some(home.join(".cache/apkq"))
    }
}

fn read(path: &Path, validate: impl Fn(&[u8]) -> bool) -> Option<ArchivedBytes> {
    let file = fs::File::open(path).ok()?;
    let size = usize::try_from(file.metadata().ok()?.len()).ok()?;
    let mut bytes = AlignedVec::with_capacity(size);
    let mut file = file;

    std::io::copy(&mut file, &mut bytes).ok()?;

    if bytes.len() <= size_of::<u32>() {
        let _ = fs::remove_file(path);
        return None;
    }

    let checksum_at = bytes.len() - size_of::<u32>();
    let checksum = u32::from_le_bytes(bytes[checksum_at..].try_into().ok()?);
    bytes.resize(checksum_at, 0);

    if crc32fast::hash(&bytes) == checksum && validate(&bytes) {
        Some(ArchivedBytes(bytes))
    } else {
        let _ = fs::remove_file(path);
        None
    }
}

fn write<T>(path: &Path, mapping: &T)
where
    T: for<'a> Serialize<
        rkyv::api::high::HighSerializer<AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, Error>,
    >,
{
    let Ok(bytes) = rkyv::to_bytes::<Error>(mapping) else {
        return;
    };
    let checksum = crc32fast::hash(&bytes).to_le_bytes();
    let Some(parent) = path.parent() else {
        return;
    };

    if fs::create_dir_all(parent).is_err() {
        return;
    }

    let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp-{}-{id}", std::process::id()));

    let written = fs::File::create(&temporary)
        .and_then(|mut file| {
            use std::io::Write;

            file.write_all(&bytes)?;
            file.write_all(&checksum)
        })
        .is_ok();

    if written && fs::rename(&temporary, path).is_ok() {
        return;
    }

    let _ = fs::remove_file(temporary);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rkyv::rancor::Error;
    use rkyv::{Archive, Serialize};

    use super::{cache_path, read, write};

    #[derive(Archive, Debug, Eq, PartialEq, Serialize)]
    struct Value {
        text: String,
    }

    #[test]
    fn cache_name_contains_kind_and_two_crc32_values() {
        let path = cache_path("dex", 38_877_233, 0x4f01e355).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();

        assert!(name.starts_with("dex-"));
        assert!(name.ends_with("-4f01e355.bin"));
        assert_eq!(name.len(), "dex-00000000-4f01e355.bin".len());
    }

    #[test]
    fn reads_valid_cache_and_discards_corruption() {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("apkq-cache-test-{id}"));
        let path = directory.join("mapping.bin");
        let value = Value {
            text: "cached".to_owned(),
        };

        write(&path, &value);
        let bytes = read(&path, |bytes| {
            rkyv::access::<ArchivedValue, Error>(bytes).is_ok()
        })
        .unwrap();
        assert_eq!(
            rkyv::access::<ArchivedValue, Error>(bytes.as_ref())
                .unwrap()
                .text,
            "cached"
        );
        drop(bytes);

        fs::write(&path, b"invalid").unwrap();
        assert!(
            read(&path, |bytes| rkyv::access::<ArchivedValue, Error>(bytes)
                .is_ok())
            .is_none()
        );
        assert!(!path.exists());

        fs::remove_dir(directory).unwrap();
    }
}

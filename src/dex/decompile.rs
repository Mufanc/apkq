use crate::archive::ApkArchive;
use crate::java::JavaClass;

use droidsaw_dex::DexFile;

use super::mapping::Mapping;
use super::query::LocatedTarget;

pub struct DecompiledClass {
    pub dex: String,
    pub descriptor: String,
    pub source: String,
}

impl DecompiledClass {
    pub fn from_apk(
        prepared: &ApkArchive,
        query: &JavaClass,
        selected: Option<&str>,
        mapping: Option<&Mapping>,
    ) -> Result<DecompiledClass, String> {
        let target = LocatedTarget::from_class(prepared, query, selected, mapping)?;
        let parsed = DexFile::parse(&target.bytes, None)
            .map_err(|error| format!("failed to parse {}: {error}", target.dex))?;
        let (_, class) = parsed
            .find_class(&target.class)
            .ok_or("selected class disappeared")?;
        let source = droidsaw_dex::classes::decompile_class(&parsed, &target.bytes, class);

        Ok(DecompiledClass {
            dex: target.dex,
            descriptor: target.class,
            source,
        })
    }
}

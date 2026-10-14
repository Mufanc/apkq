# dexq

`dexq` searches Android APKs directly. It reads DEX metadata, scans method bytecode, and queries compiled Android resources. It does not create a database or cache file, and it does not invoke a decompiler.

## Build

```sh
cargo build --release
```

## Queries

```sh
dexq classes app.apk --name com.example.MainActivity
dexq c app.apk --name-prefix com.example.
dexq c app.apk --inherits android.app.Activity
dexq fields app.apk --class com.example.Config --name apiKey
dexq f app.apk --name apiKey
dexq methods app.apk --name onCreate
dexq m app.apk --uses-string token --uses-string secret
dexq m app.apk --calls 'com.example.Client#send'
dexq m app.apk --calls 'com.example.Client#send(int):void'
dexq m app.apk --uses-type com.example.Secret
dexq m app.apk --uses-field 'com.example.Config#apiKey:java.lang.String'
dexq r app.apk --type string --value 'Login failed'
dexq r app.apk --type string --value-regex 'login|sign.?in'
dexq r app.apk --type id --name-contains button
dexq r app.apk --type layout --name activity_login
dexq r app.apk --id 0x7f0a0012
dexq r app.apk --type layout --uses-resource string/login_failed
dexq r app.apk --type layout --uses-resource 0x7f0a0012 --json
```

`c`, `f`, `m`, and `r` are aliases for `classes`, `fields`, `methods`, and `resources`. A file input must be an APK; a directory input recursively searches its APKs. Embedded APKs are followed recursively, including their separate resource tables.

`resources` reads `resources.arsc`. `--type` limits the resource type in the result (`string`, `id`, `layout`, etc.); `--name` is exact, while `--name-contains` and `--value` are case-sensitive substrings. `--value-regex` searches decoded values with Rust regex syntax. `--id` accepts decimal or `0x` hexadecimal. Filters are combined with AND. `--uses-resource` accepts an ID, `type/name`, or `package:type/name` and finds direct references in table values and compiled XML attributes. XML hits include the node path, attribute, view ID when present, and source line. IDs and symbolic names are resolved separately in each nested APK.

All filters in a command are combined with AND. In `methods`, every reference filter must match within the **same method**. Repeat `--uses-string` for multiple string fragments. String matching is case-sensitive substring matching and includes reads of static string fields initialized in DEX. Query types use dotted Java names (`com.example.Client`, `int`, `java.lang.String[]`). Members use `Class#name`; `--calls` may add `(parameterTypes):returnType` for an exact signature, and `--uses-field` may add `:type`. Without a signature or type, all members with that class and name match. `methods --has-field` keeps methods whose declaring class defines the named field. `--name` is an exact class, method, or field name. `classes --inherits` includes direct and transitive subclasses and interface implementors.

The default output is TSV. Code queries include APK, DEX entry, kind, descriptor, original mapped name, and source file. Resource queries include APK, nested archive path, ID, package, type, name, configuration, value, file path, and reference location. Use `--aligned` for space-aligned text or `--json` for an array of objects. Timing and match count are printed to stderr. Supply an R8/ProGuard mapping file, or an entry in a ZIP, to search original code names and include them in results:

```sh
dexq m app.apk --mapping 'mappings.zip!release/mapping.txt' --name originalMethod --json
```

## Limits

- Each CLI invocation reads the APK again; there is no persistent cache or database.
- Bare DEX, JAR, and AAR inputs are not supported.
- Strings generated at runtime or stored only in resources or native libraries are outside code reference search; use `resources` for compiled resources.
- Method calls are explicit DEX invokes, not reflection, JNI, or resolved runtime targets of virtual dispatch.
- `--uses-resource` searches direct references in compiled resources; it does not find DEX code references, dynamically built resource IDs, or transitive references.
- Regex is available for resource values only. SQL and decompilation are outside dexq. Use ASC or another decompiler to inspect matched classes.

## Code layout

- `src/cli.rs` handles commands and query dispatch; `src/cli/output.rs` formats results.
- `src/dex.rs` reads APK archives; `src/dex/parse.rs` reads DEX structures, `filter.rs` resolves query targets, and `code.rs` scans instructions.
- `src/query.rs` parses JavaDoc-style query values; `src/mapping.rs` reads R8/ProGuard mappings.
- `src/resource.rs` queries resource tables and compiled XML.

# dexq

`dexq` searches Android APKs directly. It reads DEX metadata and scans method bytecode for the requested references. It does not create a database or cache file, and it does not invoke a decompiler.

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
```

`c`, `f`, and `m` are aliases for `classes`, `fields`, and `methods`. A file input must be an APK; a directory input recursively searches its APKs. Embedded APKs are followed recursively.

All filters in a command are combined with AND. In `methods`, every reference filter must match within the **same method**. Repeat `--uses-string` for multiple string fragments. String matching is case-sensitive substring matching and includes reads of static string fields initialized in DEX. Query types use dotted Java names (`com.example.Client`, `int`, `java.lang.String[]`). Members use `Class#name`; `--calls` may add `(parameterTypes):returnType` for an exact signature, and `--uses-field` may add `:type`. Without a signature or type, all members with that class and name match. `methods --has-field` keeps methods whose declaring class defines the named field. `--name` is an exact class, method, or field name. `classes --inherits` includes direct and transitive subclasses and interface implementors.

The default output is TSV with APK, DEX entry, kind, descriptor, original mapped name, and source file. Use `--aligned` for space-aligned text or `--json` for an array of objects. Timing and match count are printed to stderr. Supply an R8/ProGuard mapping file, or an entry in a ZIP, to search original names and include them in results:

```sh
dexq m app.apk --mapping 'mappings.zip!release/mapping.txt' --name originalMethod --json
```

## Limits

- Each CLI invocation reads the APK again; there is no persistent cache or database.
- Bare DEX, JAR, and AAR inputs are not supported.
- Strings generated at runtime or stored only in resources or native libraries are outside code reference search.
- Method calls are explicit DEX invokes, not reflection, JNI, or resolved runtime targets of virtual dispatch.
- Regex queries, SQL, and decompilation are outside dexq. Use ASC or another decompiler to inspect matched classes.

## Code layout

- `src/cli.rs` handles commands and query dispatch; `src/cli/output.rs` formats results.
- `src/dex.rs` reads APK archives; `src/dex/parse.rs` reads DEX structures, `filter.rs` resolves query targets, and `code.rs` scans instructions.
- `src/query.rs` parses JavaDoc-style query values; `src/mapping.rs` reads R8/ProGuard mappings.

# dexq

`dexq` searches Android APKs directly. It reads DEX metadata, scans method bytecode, and queries compiled Android resources.

## Build

```sh
cargo build --release
```

## Queries

```sh
dexq app.apk classes --name com.example.MainActivity
dexq app.apk c --name-prefix com.example.
dexq app.apk c --inherits android.app.Activity
dexq app.apk fields --class com.example.Config --name apiKey
dexq app.apk f --name apiKey
dexq app.apk methods --name onCreate
dexq app.apk m --uses-string token --uses-string secret
dexq app.apk m --calls 'com.example.Client#send'
dexq app.apk m --calls 'com.example.Client#send(int):void'
dexq app.apk m --uses-type com.example.Secret
dexq app.apk m --uses-field 'com.example.Config#apiKey:java.lang.String'
dexq app.apk r --type string --value 'Login failed'
dexq app.apk r --type string --value-regex 'login|sign.?in'
dexq app.apk r --type id --name-contains button
dexq app.apk r --type layout --name activity_login
dexq app.apk r --id 0x7f0a0012
dexq app.apk r --type layout --uses-resource string/login_failed
dexq app.apk --json r --type layout --uses-resource 0x7f0a0012
```

`c`, `f`, `m`, and `r` are aliases for `classes`, `fields`, `methods`, and `resources`. Pass an APK as input. Embedded APKs are followed recursively, including their separate resource tables.

`resources` reads `resources.arsc`. `--type` limits the resource type in the result (`string`, `id`, `layout`, etc.); `--name` is exact, while `--name-contains` and `--value` are case-sensitive substrings. `--value-regex` searches decoded values with Rust regex syntax. `--id` accepts decimal or `0x` hexadecimal. Filters are combined with AND. `--uses-resource` accepts an ID, `type/name`, or `package:type/name` and finds direct references in table values and compiled XML attributes. XML hits include the node path, attribute, view ID when present, and source line. IDs and symbolic names are resolved separately in each nested APK.

All filters in a command are combined with AND. In `methods`, every reference filter must match within the **same method**. Repeat `--uses-string` for multiple string fragments. String matching is case-sensitive substring matching and includes reads of static string fields initialized in DEX. Query types use dotted Java names (`com.example.Client`, `int`, `java.lang.String[]`). Members use `Class#name`; `--calls` may add `(parameterTypes):returnType` for an exact signature, and `--uses-field` may add `:type`. Without a signature or type, all members with that class and name match. `methods --has-field` keeps methods whose declaring class defines the named field. `--name` is an exact class, method, or field name. `classes --inherits` includes direct and transitive subclasses and interface implementors.

The default output is TSV. Code queries include APK, DEX entry, kind, descriptor, optional original mapped name, and source file. Resource queries include APK, nested archive path, ID, type, name, configuration, value, file path, and usage. Use `--aligned` for space-aligned text or `--json` for an array of objects. Timing and match count are printed to stderr. Supply a mapping file, or an entry in a ZIP, to search mapped names. Code queries use R8/ProGuard mappings; resource queries use AndResGuard mappings:

```sh
dexq app.apk --mapping 'mappings.zip!release/mapping.txt' --json m --name originalMethod
```

## Search semantics

- Code string queries inspect DEX constants and initialized static string fields. Use `resources` to query compiled resource strings.
- Method call queries match explicit DEX invoke instructions.
- Resource reference queries match direct references in resource table values and compiled XML attributes.
- Resource value queries support Rust regular expressions.
- Use ASC or another decompiler to inspect matched classes and methods.

## Code layout

- `src/cli.rs` handles commands and query dispatch; `src/cli/output.rs` formats results.
- `src/dex.rs` reads APK archives; `src/dex/parse.rs` reads DEX structures, `filter.rs` resolves query targets, and `code.rs` scans instructions.
- `src/query.rs` parses JavaDoc-style query values; `src/dex/mapping.rs` reads R8/ProGuard mappings.
- `src/resource.rs` queries resource tables and compiled XML.

# apkq

`apkq` searches Android APKs directly. It reads DEX metadata, scans method bytecode, and queries compiled Android resources.

## Build

```sh
cargo build --release
```

## Queries

```sh
apkq app.apk c --list
apkq app.apk classes --name com.example.MainActivity
apkq app.apk c --name-regex '^com\.example\.'
apkq app.apk c --name-regex '(Login|Register)Activity$'
apkq app.apk c --inherits android.app.Activity
apkq app.apk fields --class com.example.Config --name apiKey
apkq app.apk f --name-regex '^(is|has)[A-Z]'
apkq app.apk f --name apiKey
apkq app.apk methods --name onCreate
apkq app.apk m --name-regex '^(get|set)[A-Z]'
apkq app.apk m --uses-string token --uses-string secret
apkq app.apk m --calls 'com.example.Client#send'
apkq app.apk m --calls 'com.example.Client#send(int):void'
apkq app.apk m --uses-type com.example.Secret
apkq app.apk m --uses-field 'com.example.Config#apiKey:java.lang.String'
apkq app.apk r --type string --value 'Login failed'
apkq app.apk r --type string --value-regex 'login|sign.?in'
apkq app.apk r --type id --name-regex 'button(_text)?$'
apkq app.apk r --type layout --name activity_login
apkq app.apk r --id 0x7f0a0012
apkq app.apk r --type layout --uses-resource string/login_failed
apkq app.apk --json r --type layout --uses-resource 0x7f0a0012
apkq app.apk d com.example.MainActivity
apkq app.apk d com.example.MainActivity -o MainActivity.java
```

`c`, `f`, `m`, `r`, and `d` are aliases for `classes`, `fields`, `methods`, `resources`, and `decompile`. Pass an APK as input. Embedded APKs are followed recursively, including their separate resource tables.

`decompile` accepts a dotted class name or DEX descriptor and writes Java-like source to stdout. Use `-o` to write it to a file. If the same class occurs in multiple DEX files, use `--dex` with the exact nested DEX location. `--mapping` lets the command locate a class by its original name; generated source retains the names emitted by the decompiler.

Running a subcommand without a query prints its help. Use `--list` to return every item; `--list` cannot be combined with query filters. `--name` and `--name-regex` are alternatives. Resource `--value` and `--value-regex` are alternatives too.

`resources` reads `resources.arsc`. `--type` limits the resource type in the result (`string`, `id`, `layout`, etc.); `--name` is exact, `--name-regex` searches resource names with Rust regex syntax, and `--value` is a case-sensitive substring. `--value-regex` searches decoded values with Rust regex syntax. `--id` accepts decimal or `0x` hexadecimal. Filters are combined with AND. `--uses-resource` accepts an ID, `type/name`, or `package:type/name` and finds direct references in table values and compiled XML attributes. XML hits include the node path, attribute, view ID when present, and source line. IDs and symbolic names are resolved separately in each nested APK.

All filters in a command are combined with AND. In `methods`, every reference filter must match within the **same method**. Repeat `--uses-string` for multiple string fragments. String matching is case-sensitive substring matching and includes reads of static string fields initialized in DEX. Query types use dotted Java names (`com.example.Client`, `int`, `java.lang.String[]`). Members use `Class#name`; `--calls` may add `(parameterTypes):returnType` for an exact signature, and `--uses-field` may add `:type`. Without a signature or type, all members with that class and name match. `methods --has-field` keeps methods whose declaring class defines the named field. `--name` is exact. `classes --name-regex` matches the full dotted Java class name; method, field, and resource `--name-regex` match the item name. All regular expressions use Rust regex syntax, and `--inherits` includes direct and transitive subclasses and interface implementors.

The default output is TSV. Code queries include the DEX entry, kind, a Java/Javadoc-style symbol that can be reused in queries, an optional original mapped symbol, and source file. Resource queries include the nested archive path, ID, type, name, configuration, value, file path, and usage. Use `--aligned` for space-aligned text or `--json` for an array of objects. Timing and match count are printed to stderr. Supply a mapping file, or an entry in a ZIP, to search mapped names. Code queries use R8/ProGuard mappings; resource queries use AndResGuard mappings:

```sh
apkq app.apk --mapping 'mappings.zip!release/mapping.txt' --json m --name originalMethod
```

## Search semantics

- Code string queries inspect DEX constants and initialized static string fields. Use `resources` to query compiled resource strings.
- Method call queries match explicit DEX invoke instructions.
- Resource reference queries match direct references in resource table values and compiled XML attributes.
- Resource value queries support Rust regular expressions.
- `decompile` emits one matched class as Java-like source.

## Code layout

- `src/cli.rs` handles commands and query dispatch; `src/cli/output.rs` formats results.
- `src/dex.rs` reads APK archives; `src/dex/parse.rs` reads DEX structures, `filter.rs` resolves query targets, and `code.rs` scans instructions.
- `src/java.rs` parses and formats Java-style symbols; `src/dex/mapping.rs` reads R8/ProGuard mappings.
- `src/resource.rs` queries resource tables and compiled XML.

## Acknowledgements

apkq's on-demand APK and DEX query workflow is inspired by [Droid ASC](https://github.com/MG1937/ASC), which demonstrated that compiled Android artifacts can be queried directly without building a global analysis database. Java-like class decompilation is provided by [droidsaw-dex](https://github.com/droidsaw/droidsaw-dex).

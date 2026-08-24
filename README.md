# dexq

`dexq` is a read-only CLI for querying DEX metadata and string references
directly from Android APKs. It parses DEX files itself, follows embedded APKs,
and does not invoke JADX, `unzip`, or other system commands.

## Capabilities

- Query classes, methods, and fields by exact name.
- Find methods that call a method.
- Find classes that extend a class or implement an interface.
- Find methods that reference literal or regex-matched strings.
- Combine class, method, field, and string conditions with AND semantics.
- Apply R8/ProGuard mappings during name matching and output.
- Recursively index `classes*.dex` files in embedded APKs.
- Cache compact DEX indexes by code-content fingerprint.
- Emit TSV, aligned text, or JSON.

String queries cover direct `const-string` references and reads from string
fields initialized through `static_values_off`.

## Build

```sh
cargo build --release
target/release/dexq --help
```

To install the current checkout:

```sh
cargo install --path .
```

## Usage

```text
dexq [OPTIONS] <--class <NAME>|--method <NAME>|--field <NAME>|
                 --string <TEXT>|--regex <REGEX>|--callers-of <METHOD>|
                 --inherits <CLASS>> <INPUT>
```

`INPUT` is one APK or a directory containing APK files.

| Option | Query |
| --- | --- |
| `-c, --class <NAME>` | Exact class name |
| `-m, --method <NAME>` | Exact method name |
| `-f, --field <NAME>` | Exact field name |
| `-s, --string <TEXT>` | Literal substring referenced by a method |
| `-r, --regex <REGEX>` | Regular expression matched against referenced strings |
| `--callers-of <METHOD>` | Methods that invoke the named method |
| `--inherits <CLASS>` | Classes that directly or indirectly extend or implement the class |
| `--mapping <FILE[!ENTRY]>` | R8/ProGuard mapping file |
| `--aligned` | Space-aligned terminal output |
| `--json` | JSON output |

Examples:

```sh
dexq app.apk -c com.example.PlayerManager
dexq app.apk -m updateState -s 'state='
dexq app.apk -r '^request .* failed$'
dexq app.apk -s 'request ' -r 'code=[45][0-9]{2}'
dexq app.apk -m originalMethod --mapping mapping.txt
dexq app.apk --callers-of 'Lcom/example/Player;->play()V'
dexq app.apk --inherits android.view.View
dexq app.apk -c OriginalName \
  --mapping 'mappings.zip!release/mapping.txt' --json
```

Repeated and mixed query conditions are ANDed. In particular, every `-s` and
`-r` condition must be satisfied by strings referenced from the same method.
A field condition combined with a method or string condition restricts results
to methods in classes that declare that field.

`--callers-of` accepts a method name, `CLASS->NAME`, or a full
`CLASS->NAME(DESCRIPTOR)` reference. It and `--inherits` are standalone query
modes. Callers are deduplicated, and inheritance results are transitive.

Class queries accept simple names, dotted Java names, and DEX descriptors:

```text
PlayerManager
com.example.PlayerManager
Lcom/example/PlayerManager;
```

Inner classes must use `$`, for example `Outer$Inner`.

## Mapping

`--mapping` accepts a plain R8/ProGuard mapping file or one explicit entry in a
ZIP archive:

```sh
dexq app.apk -m originalMethod \
  --mapping 'mapping.zip!build/outputs/mapping/release/mapping.txt'
```

Queries then accept either original or obfuscated class, method, and field
names. Mapped names replace `LOCATION` in the result. Nested ZIP selection is
not supported.

## Output

The default format is tab-separated:

```text
FILE          TYPE  LOCATION                                                SOURCE
classes3.dex  F     Lcom/example/Model;->state:I                            Model.java
```

`TYPE` is `C`, `M`, or `F`. `FILE` is the path inside the input APK; embedded
archives are separated with `!`:

```text
classes2.dex
assets/plugin.apk!classes.dex
assets/base.apk!assets/feature.apk!classes2.dex
```

`--aligned` changes only text alignment. `--json` emits objects with exactly
`file`, `type`, `location`, and `source`; it is mutually exclusive with
`--aligned`.

## Data flow

```text
APK bytes
  -> recursive ZIP traversal
  -> DEX strings, classes, fields, methods, and references
  -> compact on-disk index
  -> query filters
  -> TSV / aligned text / JSON
```

The project uses Rust edition 2024 and forbids `unsafe` in its own code.

## Cache

Indexes are stored under `dexq/v2` in the platform cache directory. Set
`DEXQ_CACHE_DIR` to override the location.

The cache key is derived from the recursive DEX tree. Changes to resources,
signatures, manifests, or native libraries do not invalidate an unchanged DEX
index.

## Limits

- Inputs must be APK files; bare DEX, JAR, and AAR inputs are not supported.
- Embedded APK traversal is limited to three levels.
- Strings produced at runtime or stored only in resources or native libraries
  are outside the index.
- Caller queries cover explicit DEX method invocations, not reflection, JNI, or
  resolved runtime targets of virtual dispatch.
- Regex syntax follows Rust's `regex` crate and excludes look-around and
  backreferences.

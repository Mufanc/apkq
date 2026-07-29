# dexq

Query DEX classes, methods, fields, and string references directly from APKs
and embedded APKs.

```sh
cargo build --release

target/release/dexq app.apk -c PlayerManager
target/release/dexq app.apk -m updateState
target/release/dexq app.apk -f mCurrentPlayer
target/release/dexq app.apk -s "request failed: "
target/release/dexq app.apk -m someMethod -s "A value is "
target/release/dexq app.apk -s "A is " -s "B is " --json
target/release/dexq app.apk -s "request failed: " --aligned
target/release/dexq app.apk -c OriginalName --mapping mapping.txt
target/release/dexq app.apk -m originalMethod \
  --mapping 'mappings.zip!path/to/mapping.txt'
```

The first positional argument may be an APK or a directory containing APKs.
`-c/--class`, `-m/--method`, and `-f/--field` use exact name matching, while
`-s/--string` uses substring matching. Multiple conditions are combined with
AND. Repeating `-s` requires the same method to reference every string. When a
field condition is combined with method or string conditions, only methods in
classes that declare the field are returned.

Class names may be simple names, fully qualified Java names, or DEX descriptors,
such as `PlayerManager`, `com.example.PlayerManager`, or
`Lcom/example/PlayerManager;`. Inner classes must use `$`, for example
`Outer$Inner` or `com.example.Outer$Inner`.

`--mapping` accepts an R8/ProGuard mapping file. It may also select one file
inside a ZIP using `archive.zip!entry/path`; nested ZIPs are not supported.
Class, method, and field queries then accept original or obfuscated names, and
mapped names replace `LOCATION` in the output.

Plain output is tab-separated by default. Pass `--aligned` for space-aligned
columns intended for terminal display. `FILE` is the path inside the input APK,
such as `classes.dex` or `assets/inner.apk!classes2.dex`; the input APK name is
not repeated.

The project forbids `unsafe` in its own code. Parsing does not invoke a shell,
`unzip`, or other system commands. DEX indexes are cached under `dexq/v1` in
the system cache directory. Set `DEXQ_CACHE_DIR` to override this location.

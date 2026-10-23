# apkq

An Android APK analysis tool for developers and AI agents. apkq searches compiled code and resources directly, helping turn fragments from logs, screenshots, or class names into code locations to investigate.

## What it can do

- **Find code.** Query classes, fields, and methods by name or regular expression. Follow class inheritance and interface implementations.
- **Search method references.** Find methods that use strings, call a method, reference a type, or access a field. Combine filters to narrow down a code path.
- **Trace UI resources.** Search resource strings, view ID names, and layout names. Find direct resource references in compiled XML and resource table values, including the view ID and attribute when available.
- **Read Java-like source.** Decompile a selected class to inspect its implementation.
- **Inspect precise instructions.** Disassemble a class or method into smali with DEX program counters for runtime debugging tools.
- **Search original names.** Apply R8/ProGuard mappings to code queries and AndResGuard mappings to resource queries.

## Designed for agent workflows

**Direct queries without an analysis database.** Search the APK without first importing it into a separate project or building a persistent code index. Parsed mappings are cached for reuse.

**Nested APKs included.** Embedded APKs are searched recursively, with DEX and resource locations retained so results can be traced to the correct artifact.

**Composable filters.** Filters are combined with AND; method reference filters must match within the same method. Java-like and DEX/smali symbol inputs share the same matching rules.

**Structured output.** Queries support TSV, aligned tables, and JSON. Disassembly JSON includes numeric DEX program counters. Results go to stdout; timing and counts go to stderr.

**Mapping-aware navigation.** Search using original names while retaining actual APK symbols. Decompilation and disassembly use mappings to locate targets and preserve the names in the APK.

**Works with [Yaya](https://github.com/Mufanc/yaya).** Use apkq to locate code and inspect DEX instructions, then use Yaya to set breakpoints and inspect the running app. Method signatures and DEX program counters connect static analysis with runtime debugging.

## Guidance

The CLI includes detailed help covering query syntax, examples, and matching behavior. Start with `apkq --help` or `apkq app.apk <command> --help`. For help with an investigation, ask an LLM to run apkq, consult `--help`, or RTFSC when implementation details matter.

Code string searches inspect DEX constants and initialized static string fields; text stored in Android resources is queried separately through `resources`. Java-like decompilation targets one class, while disassembly targets a class or method.

## Acknowledgements

apkq's direct APK query workflow is inspired by [Droid ASC](https://github.com/MG1937/ASC). Java-like decompilation and smali generation are provided by [droidsaw-dex](https://github.com/droidsaw/droidsaw-dex).

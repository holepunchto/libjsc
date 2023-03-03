# libjsc

ABI compatible replacement for https://github.com/holepunchto/libjs built on JavaScriptCore.

## Differences

Being built on JavaScriptCore, the library has some differences from its V8 counterpart.

- **Only supports Darwin:** The library links against the builtin JavaScriptCore framework on Darwin and as such is only officially supported on Darwin targets.

- **No module support:** The builtin JavaScriptCore framework on Darwin does not expose an API for module loading and so the `js_module_t` API is therefore not available.

## License

Apache-2.0

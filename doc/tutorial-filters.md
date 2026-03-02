# Filters and diagnostics

This tutorial covers filtering the quickfix list by error kind and toggling diagnostic virtual text.

## Filtering errors

`:SanityFilter [<kind> ...]` narrows the quickfix list to errors matching the given kinds:

```vim
:SanityFilter Leak_DefinitelyLost
:SanityFilter Race
```

Called with no arguments, it lists the available kinds and presets.

### Built-in presets

| Preset | Matches |
|---|---|
| `errors` | Invalid access, uninitialised values, overflows |
| `leaks` | All leak types |
| `races` | Data races |
| `threading` | All threading-related kinds |

```vim
:SanityFilter leaks
```

### Clearing filters

`:SanityClearFilter` restores the full, unfiltered quickfix list.

## Diagnostics

`:SanityDiagnostics` toggles diagnostic virtual text on source lines involved in errors. Pass `on` or `off` to set explicitly:

```vim
:SanityDiagnostics on
:SanityDiagnostics off
:SanityDiagnostics      " toggles
```

## Exporting errors

`:SanityExport [<file>]` writes the current error set to a JSON file (default: `sanity-export.json`). The export respects the active filter, so you can export a subset of errors:

```vim
:SanityFilter leaks
:SanityExport leaks.json
```

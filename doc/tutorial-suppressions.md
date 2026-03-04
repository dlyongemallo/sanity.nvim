# Suppressions

This tutorial covers queuing, saving, and auditing suppressions for valgrind and sanitizer errors.

## Queuing suppressions

`:SanitySuppress` queues a suppression entry for the error at the cursor. Nothing is written to disk yet; suppressions accumulate in memory until you save them.

You can bind this to a key for quick access:

```lua
opts = {
  keymaps = {
    suppress = "<a-x>",
  },
}
```

## Saving suppressions

`:SanitySaveSuppressions [<file>]` writes all queued suppressions to disk.

- **With a filename:** all suppressions are appended to that single file.
- **Without arguments:** suppressions are partitioned by tool and written to the default files (`.valgrind.supp`, `.lsan.supp`, `.tsan.supp`). The default file names are configurable via `opts.suppression_files`.

### Suppression formats

Valgrind suppressions are full `{ ... }` blocks with `fun:` entries. Sanitizer suppressions use the `type:function` format accepted by LSan and TSan.

ASan memory errors (e.g. heap-use-after-free) have no runtime suppression mechanism. Instead, ASan uses ignorelist files passed via `-fsanitize-ignorelist=` at compile time. The plugin will suggest this when you try to suppress an ASan error.

## Passing suppressions to valgrind

Existing suppression files can be passed to valgrind automatically via `opts.valgrind_suppressions`:

```lua
opts = {
  valgrind_suppressions = { ".valgrind.supp" },
}
```

Each file in the list is passed as `--suppressions=<file>` when `:SanityRunValgrind` runs.

## Auditing suppressions

`:SanityAuditSuppressions` shows which suppressions from your configured files were used or unused. For valgrind suppressions, it reports exact usage counts from the last run. For TSan and LSan suppression files, entries are listed but usage data is not available (sanitizer runs do not report suppression counts). This helps identify stale suppressions that can be removed.

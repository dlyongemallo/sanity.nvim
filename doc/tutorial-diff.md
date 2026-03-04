# Run-to-run diff

The fix-verify loop is the core workflow when using dynamic analysis tools: fix a bug, re-run, and check whether the fix worked and nothing new appeared. sanity.nvim tracks this automatically.

## Walkthrough

Using [examples/demo.c](../examples/demo.c) as an example, compile the demo and open it in Neovim:

```bash
gcc -g -pthread examples/demo.c -o examples/demo
nvim examples/demo.c
```

Run valgrind from inside Neovim:

```vim
:SanityRunValgrind --track-origins=no --tool=memcheck --show-reachable=yes ./examples/demo
```

The quickfix list fills with errors. Now fix one of the bugs without leaving Neovim (for instance, the use-after-free in `demonstrate_use_after_free` by removing the read after `free(data)`). Then recompile and re-run:

```vim
:!gcc -g -pthread % -o examples/demo
:SanityRunValgrind --track-origins=no --tool=memcheck --show-reachable=yes ./examples/demo
```

The notification now includes a diff summary such as `(0 new, 2 fixed, 8 unchanged)`. Diffs persist across sessions: fingerprints are saved to `.sanity-snapshot.json` in the working directory after each load and restored on the first load of a new session. The file path is configurable via `opts.snapshot_file`; set it to `false` to disable persistence. Consider adding the snapshot file to your `.gitignore`.

## Viewing the full diff

```vim
:SanityDiff
```

A floating window opens showing exactly which errors are new (`+`), fixed (`-`), and unchanged (`=`), grouped by kind and location. This makes it easy to confirm your fix worked without introducing regressions.

## Track origins

When `:SanityRunValgrind` finds uninitialised value errors and `--track-origins` was not already specified, the plugin can automatically re-run with `--track-origins=yes` for more detailed origin tracking. Set `track_origins` in setup options to `true` (always re-run), `false` (never), or `"ask"` (prompt; the default).

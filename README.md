# sanity.nvim

A Neovim plugin for integrating dynamic analysis tools such as `valgrind` (`memcheck` and `helgrind`) and sanitizers (address and thread).

## Installation

This plugin depends on [xml2lua](https://github.com/manoelcampos/xml2lua). The instructions below for [lazy.nvim](https://github.com/folke/lazy.nvim) will install the dependency automatically.

```lua
{
  'dlyongemallo/sanity.nvim',
  cmd = { "SanityLoadLog", "SanityRunValgrind" },
  opts = {
    -- picker = "fzf-lua",  -- "telescope", "mini.pick", "snacks"; nil to auto-detect
    -- keymaps = {
    --   stack_next = "]s",   -- set to false to disable
    --   stack_prev = "[s",   -- set to false to disable
    --   show_stack = false,  -- set to a key (e.g., "<a-s>") to enable
    --   explain    = false,  -- set to a key (e.g., "<a-e>") to enable
    --   related    = false,  -- set to a key (e.g., "<a-r>") to enable
    --   suppress   = false,  -- set to a key (e.g., "<a-x>") to enable
    --   debug      = false,  -- set to a key (e.g., "<a-d>") to enable
    -- },
    -- track_origins = "ask",  -- true (always), false (never), "ask" (prompt on uninit errors)
    -- stack_fold_limit = 6,  -- fold long call chains in :SanityStack; 0 to disable
    -- valgrind_suppressions = { ".valgrind.supp" },  -- passed as --suppressions= to valgrind
  },
  dependencies = {
    {
      'vhyrro/luarocks.nvim',
      opts = {
        rocks = { 'xml2lua' },
      }
    }
  },
}
```

The `cmd` field makes lazy.nvim defer loading until one of those commands is first used. Keymaps (`]s`/`[s`) are also deferred until a log is actually loaded.

## Quick start

```bash
gcc -g program.c -o ./program
nvim program.c
```

```vim
:SanityRunValgrind ./program
:copen
```

See the [getting started tutorial](doc/tutorial-getting-started.md) for sanitizer usage, loading logs, and more.

## Commands

| Command | Arguments | Purpose |
|---|---|---|
| `:SanityRunValgrind <cmd>` | 1 required | Run `valgrind` on `<cmd>`, parse XML output, populate quickfix. |
| `:SanityLoadLog [file ...]` | 0+ | Auto-detect format and load files; opens a picker with no args. |
| `:SanityStack` | none | Toggle interactive split showing error stacks with live source preview. |
| `:SanityStackNext` / `:SanityStackPrev` | none | Navigate deeper/shallower in the call stack. |
| `:SanityDiagnostics [on\|off]` | optional | Toggle diagnostic virtual text. |
| `:SanityFilter [kind ...]` | 0+ | Filter quickfix list by error kind; no args lists available kinds. |
| `:SanityClearFilter` | none | Clear active filter. |
| `:SanityRelated` | none | Jump to another error sharing the same memory address. |
| `:SanityExplain` | none | Show floating window explaining the error kind at cursor. |
| `:SanitySuppress` | none | Queue a suppression entry for the error at cursor. |
| `:SanitySaveSuppressions [file]` | optional | Write queued suppressions to file(s); partitions by tool when no file given. |
| `:SanityAuditSuppressions` | none | Report which suppressions were used/unused in the last `valgrind` run. |
| `:SanityExport [file]` | optional | Export current errors to JSON (default: `sanity-export.json`); respects active filter. |
| `:SanityDiff` | none | Show detailed run-to-run diff in a floating window. |
| `:SanityDebug` | none | Set breakpoint via nvim-dap or copy GDB command to clipboard. |

## Tutorials

- **[Getting started](doc/tutorial-getting-started.md)** -- Running `valgrind`, loading sanitizer logs, and navigating the quickfix list
- **[Stacks and navigation](doc/tutorial-stacks.md)** -- Interactive stack exploration, related errors, and error explanations
- **[Filters and diagnostics](doc/tutorial-filters.md)** -- Narrowing errors by kind, presets, and diagnostic virtual text
- **[Suppressions](doc/tutorial-suppressions.md)** -- Queuing, saving, and auditing suppressions
- **[Run-to-run diff](doc/tutorial-diff.md)** -- Tracking fixes and regressions across runs

## Lualine

If you use [lualine.nvim](https://github.com/nvim-lualine/lualine.nvim), enable the built-in `quickfix` extension so that the quickfix statusline shows the sanity title (including any active filter) instead of `[No Name]`:

```lua
require('lualine').setup {
  extensions = { 'quickfix' },
}
```

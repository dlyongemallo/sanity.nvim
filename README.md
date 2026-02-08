# sanity.nvim

A neovim plugin for valgrind (memcheck and helgrind) and sanitizers (address and thread) integration.

## Installation

This plugin depends on [xml2lua](https://github.com/manoelcampos/xml2lua). The instructions below for [lazy.nvim](https://github.com/folke/lazy.nvim) will install the dependency automatically.

```lua
{
  'dlyongemallo/sanity.nvim',
  opts = {
    -- picker = "fzf-lua",  -- "telescope", "mini.pick", "snacks"; nil to auto-detect
    -- keymaps = {
    --   stack_next = "]s",   -- set to false to disable
    --   stack_prev = "[s",   -- set to false to disable
    --   show_stack = false,  -- set to a key (e.g. "gS") to enable
    -- },
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

## Usage

```vim
:Valgrind <command>
:SanityLoadLog [<file> ...]
:SanityStack
:SanityStackNext
:SanityStackPrev
:SanityDiagnostics [on|off]
```
The output will be populated into the quickfix list. `:SanityLoadLog` auto-detects the file format (valgrind XML or sanitizer log) and accepts multiple files. When called with no arguments, a file picker opens with multi-select support, filtered to `*.xml`, `*.log`, and `*.txt` files (requires [fzf-lua](https://github.com/ibhagwan/fzf-lua), [telescope.nvim](https://github.com/nvim-telescope/telescope.nvim), [mini.pick](https://github.com/echasnovski/mini.pick), or [snacks.nvim](https://github.com/folke/snacks.nvim)).

`:SanityStack` opens an interactive split showing all error stacks at the current cursor line with live source preview. Navigate frames with `]s`/`[s`, jump to a frame with `<CR>`, or close with `q`. `:SanityStackNext` and `:SanityStackPrev` navigate deeper into or out of a stack from the current position. By default these are also mapped to `]s` and `[s` respectively (configurable via `opts.keymaps`, or set to `false` to disable).

`:SanityDiagnostics` toggles diagnostic virtual text on source lines involved in errors. Pass `on` or `off` to set explicitly.

### Examples

```bash
gcc -g -lpthread program.c -o ./program
vim program.c
```

```vim
:Valgrind --tool=memcheck ./program
:copen
```

Note that `--tool=memcheck` is optional as it is the default tool for valgrind.

```vim
:Valgrind --tool=helgrind ./program
:copen
```

Alternatively, you can save the output to a xml file and load it in neovim.

```bash
valgrind --tool=memcheck --xml=yes --xml-file=memcheck.xml ./program
vim program.c
```

```vim
:SanityLoadLog memcheck.xml
:copen
```

```bash
valgrind --tool=helgrind --xml=yes --xml-file=helgrind.xml ./program
vim program.c
```

```vim
:SanityLoadLog helgrind.xml
:copen
```

For sanitizers, you can do the following:

```bash
gcc -g -fsanitize=address program.c -o ./program
./program 2> asan.log
```

```vim
:SanityLoadLog asan.log
```

```bash
gcc -g -fsanitize=thread -lpthread program.c -o ./program
./program 2> tsan.log
vim program.c
```

```vim
:SanityLoadLog tsan.log
```

You can also load multiple files at once:

```vim
:SanityLoadLog memcheck.xml tsan.log
```

It is recommended to use the [Trouble](https://github.com/folke/trouble.nvim) plugin to display the quickfix list in a more useful way.

### Lualine

If you use [lualine.nvim](https://github.com/nvim-lualine/lualine.nvim), enable the built-in `quickfix` extension so that the quickfix statusline shows the sanity title (including any active filter) instead of `[No Name]`:

```lua
require('lualine').setup {
  extensions = { 'quickfix' },
}
```

Further examples may be found in [examples/demo.c](examples/demo.c).

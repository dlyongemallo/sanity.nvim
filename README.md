# sanity.nvim

A neovim plugin for valgrind (memcheck and helgrind) and sanitizers (address and thread) integration.

## Installation

This plugin depends on [xml2lua](https://github.com/manoelcampos/xml2lua). The instructions below for [lazy.nvim](https://github.com/folke/lazy.nvim) will install the dependency automatically.

```lua
{
  'dlyongemallo/sanity.nvim',
  config = true,
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
:ValgrindLoadXml <xml-file>
:SanitizerLoadLog <log-file>
```
The output will be populated into the quickfix list.

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
:ValgrindLoadXml memcheck.xml
:copen
```

```bash
valgrind --tool=helgrind --xml=yes --xml-file=helgrind.xml ./program
vim program.c
```

```vim
:ValgrindLoadXml helgrind.xml
:copen
```

For sanitizers, you can do the following:

```bash
gcc -g -fsanitize=address program.c -o ./program
./program 2> asan.log
```

```vim
:SanitizerLoadLog asan.log
```

```bash
gcc -g -fsanitize=thread -lpthread program.c -o ./program
./program 2> tsan.log
vim program.c
```

```vim
:SanitizerLoadLog tsan.log
```

It is recommended to use the [Trouble](https://github.com/folke/trouble.nvim) plugin to display the quickfix list in a more useful way.

Further examples may be found in [examples/demo.c](examples/demo.c).

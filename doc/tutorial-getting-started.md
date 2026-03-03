# Getting started

This tutorial walks through the basics of using `sanity.nvim`: running `valgrind`, loading sanitizer logs, and navigating the quickfix list.

## Prerequisites

After [installing the plugin](../README.md#installation), compile your program with debug symbols (`-g`) so that `valgrind` and sanitizers can report source locations.

## Running `valgrind` from Neovim

```bash
gcc -g -lpthread program.c -o ./program
nvim program.c
```

```vim
:SanityRunValgrind --tool=memcheck ./program
:copen
```

`--tool=memcheck` is optional as it is the default tool for `valgrind`. For thread-related errors, use helgrind:

```vim
:SanityRunValgrind --tool=helgrind ./program
:copen
```

`valgrind` runs asynchronously; you can keep editing while it works. When it finishes, the quickfix list is populated with errors.

## Loading existing log files

If you already have `valgrind` XML output or sanitizer logs, load them directly:

```bash
valgrind --tool=memcheck --xml=yes --xml-file=memcheck.xml ./program
nvim program.c
```

```vim
:SanityLoadLog memcheck.xml
:copen
```

Helgrind logs work the same way:

```bash
valgrind --tool=helgrind --xml=yes --xml-file=helgrind.xml ./program
nvim program.c
```

```vim
:SanityLoadLog helgrind.xml
:copen
```

## Sanitizer logs

Sanitizer output is also supported. Redirect stderr to a file and load it:

```bash
gcc -g -fsanitize=address program.c -o ./program
./program 2> asan.log
```

```vim
:SanityLoadLog asan.log
```

ThreadSanitizer works similarly:

```bash
gcc -g -fsanitize=thread -lpthread program.c -o ./program
./program 2> tsan.log
nvim program.c
```

```vim
:SanityLoadLog tsan.log
```

MemorySanitizer detects reads of uninitialised memory. It requires a fully instrumented build (including libc), so it is typically used with clang and an MSAN-instrumented libc/toolchain (see the [Clang MSAN documentation](https://clang.llvm.org/docs/MemorySanitizer.html) for setup details). The following command shows only how to compile and run your programme once such a toolchain is in place:

```bash
# assumes an MSAN-instrumented libc/toolchain is already configured
clang -g -fsanitize=memory program.c -o ./program
./program 2> msan.log
nvim program.c
```

```vim
:SanityLoadLog msan.log
```

UndefinedBehaviorSanitizer catches undefined behaviour such as signed integer overflow, null pointer dereferences, and invalid shifts. For best results, enable stack traces:

```bash
gcc -g -fsanitize=undefined -fno-omit-frame-pointer program.c -o ./program
UBSAN_OPTIONS=print_stacktrace=1 ./program 2> ubsan.log
nvim program.c
```

```vim
:SanityLoadLog ubsan.log
```

## Loading multiple files

`:SanityLoadLog` auto-detects the file format (`valgrind` XML or sanitizer log) and accepts multiple files:

```vim
:SanityLoadLog memcheck.xml tsan.log
```

When called with no arguments, a file picker opens with multi-select support, filtered to `*.xml`, `*.log`, and `*.txt` files. This requires a picker plugin: [fzf-lua](https://github.com/ibhagwan/fzf-lua), [telescope.nvim](https://github.com/nvim-telescope/telescope.nvim), [mini.pick](https://github.com/echasnovski/mini.pick), or [snacks.nvim](https://github.com/folke/snacks.nvim).

## Navigating errors

Quickfix entries carry a `type` marker (`E`/`W`/`I`) reflecting error severity. The native quickfix window displays this marker, and plugins like [trouble.nvim](https://github.com/folke/trouble.nvim) can leverage it for severity-based highlighting or sorting.

Further examples may be found in [examples/demo.c](../examples/demo.c).

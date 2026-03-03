# Stacks and navigation

This tutorial covers interactive stack exploration, jumping between related errors, and reading error explanations.

## Interactive stack view

`:SanityStack` opens a split showing all error stacks at the current cursor line with live source preview. Inside the stack window:

- `]s` / `[s` -- navigate between frames
- `<CR>` -- jump to the frame's source location
- `q` -- close the stack window

## Stack navigation from the editor

`:SanityStackNext` and `:SanityStackPrev` let you navigate deeper into or out of a stack directly from your source buffer, without opening the stack window. By default these are mapped to `]s` and `[s` respectively. You can change or disable the mappings in setup:

```lua
opts = {
  keymaps = {
    stack_next = "]s",   -- set to false to disable
    stack_prev = "[s",   -- set to false to disable
    show_stack = false,  -- set to a key (e.g., "<a-s>") to enable
  },
}
```

## Related errors

`:SanityRelated` jumps to a related location sharing the same memory address. This includes other stacks within the same error (e.g. both sides of a data race) and other errors referencing the same address. You can bind it to a key:

```lua
opts = {
  keymaps = {
    related = "<a-r>",
  },
}
```

## Error explanations

`:SanityExplain` shows a floating window explaining the error kind at the cursor -- what the error means, why it happens, and common fixes.

```lua
opts = {
  keymaps = {
    explain = "<a-e>",
  },
}
```

## Debugging errors

`:SanityDebug` helps debug the error at the cursor. When [nvim-dap](https://github.com/mfussenegger/nvim-dap) is available, it jumps to the error location and sets a breakpoint. Otherwise, it copies a GDB `break` command to the system clipboard.

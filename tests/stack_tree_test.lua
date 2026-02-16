vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")

local function fmt(prefix, func_name, basename, line)
  return string.format("%s%-28s %s:%d", prefix, func_name, basename, line)
end

local function stack(frames, label, sub_labels)
  return { label = label, frames = frames, sub_labels = sub_labels }
end

local function frame(func_name, file, line)
  return { func = func_name, file = file, line = line }
end

local function render(kind, message, stacks, query_file, query_line)
  M._reset_state()
  local err = M._new_error(kind, message, "test", stacks, {})
  local buf_lines = M._build_stack_content(query_file, query_line, { err.id })
  return buf_lines
end

local TOP = "┌"
local MID = "│"
local BOT = "└"
local CLOSE = "┘"

describe("tree rendering", function()
  it("two stacks with shared caller render as a tree", function()
    local lines = render(
      "Race", "data race",
      {
        stack({
          frame("write_buf", "src/io.c", 10),
          frame("main", "src/main.c", 100),
        }),
        stack({
          frame("read_buf", "src/io.c", 20),
          frame("main", "src/main.c", 100),
        }),
      },
      "src/io.c", 10
    )
    assert_eq(lines, {
      "[Race] data race",
      fmt(" " .. TOP .. "  ", "write_buf", "io.c", 10),
      fmt(TOP .. CLOSE .. "  ", "read_buf", "io.c", 20),
      fmt(BOT .. "  ", "main", "main.c", 100),
    })
  end)

  it("thread-aware composition merges operation with creation stack", function()
    local lines = render(
      "Race", "data race",
      {
        stack({ frame("write_buf", "src/io.c", 10) }, "by thread T1"),
        stack({ frame("read_buf", "src/io.c", 20) }, "by thread T2"),
        stack(
          { frame("spawn", "src/thread.c", 30), frame("main", "src/main.c", 100) },
          "Thread T1 (tid=1) created"
        ),
        stack(
          { frame("spawn", "src/thread.c", 30), frame("main", "src/main.c", 100) },
          "Thread T2 (tid=2) created"
        ),
      },
      "src/io.c", 10
    )
    assert_eq(lines, {
      "[Race] data race",
      "  ┌ by thread T1:",
      fmt("  │  ", "write_buf", "io.c", 10),
      " ┌┴ Thread T1 (tid=1) created:",
      fmt("┌┘   ", "spawn", "thread.c", 30),
      fmt("│  ", "main", "main.c", 100),
      "└   by thread T2:",
      fmt("     ", "read_buf", "io.c", 20),
    })
  end)

  it("two operations in the same thread do not duplicate the creation label", function()
    local lines = render(
      "Race", "data race",
      {
        stack({ frame("write_buf", "src/io.c", 10) }, "by thread T1"),
        stack({ frame("read_buf", "src/io.c", 20) }, "by thread T1"),
        stack(
          { frame("spawn", "src/thread.c", 30), frame("main", "src/main.c", 100) },
          "Thread T1 (tid=1) created"
        ),
      },
      "src/io.c", 10
    )
    assert_eq(lines, {
      "[Race] data race",
      "  ┌ by thread T1:",
      fmt("  │  ", "write_buf", "io.c", 10),
      "  ├ by thread T1:",
      fmt("  │  ", "read_buf", "io.c", 20),
      " ┌┴ Thread T1 (tid=1) created:",
      fmt("┌┘   ", "spawn", "thread.c", 30),
      fmt("└  ", "main", "main.c", 100),
    })
  end)

  it("invalid-write shared tail keeps caller link connected", function()
    local lines = render(
      "InvalidWrite", "Invalid write of size 1",
      {
        stack({
          frame("write_to_buffer", "demo.c", 151),
          frame("process_data", "demo.c", 158),
          frame("demonstrate_buffer_overflow", "demo.c", 164),
          frame("main", "demo.c", 328),
        }, "Invalid write of size 1"),
        stack({
          frame("process_data", "demo.c", 156),
          frame("demonstrate_buffer_overflow", "demo.c", 164),
          frame("main", "demo.c", 328),
        }, "Address 0x4a5cc50 is 0 bytes after a block of size 16 alloc'd"),
      },
      "demo.c", 151
    )
    assert_eq(lines, {
      "[InvalidWrite] Invalid write of size 1",
      "   ┌ Invalid write of size 1:",
      "  ┌┘  write_to_buffer              demo.c:151",
      "  │   process_data                 demo.c:158",
      "  ├  Address 0x4a5cc50 is 0 bytes after a block of size 16 alloc'd:",
      " ┌┘   process_data                 demo.c:156",
      "┌┴  demonstrate_buffer_overflow  demo.c:164",
      "└  main                         demo.c:328",
    })
  end)

  it("strip_label trims whitespace and trailing colon", function()
    assert_eq(M._strip_label("  by thread T1:  "), "by thread T1")
  end)
end)

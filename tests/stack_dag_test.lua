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

local function render_multi(errs_spec, query_file, query_line)
  M._reset_state()
  local ids = {}
  for _, spec in ipairs(errs_spec) do
    local err = M._new_error(spec.kind, spec.message, "test", spec.stacks, {})
    table.insert(ids, err.id)
  end
  local buf_lines = M._build_stack_content(query_file, query_line, ids)
  return buf_lines
end

local TOP = "┌"
local MID = "│"
local BRANCH = "├"
local BOT = "└"
local CLOSE = "┘"
local MERGE = "┴"
local HORIZ = "─"

describe("dag-like join rendering", function()
  it("factors common callee frames into a cap", function()
    local lines = render(
      "Race", "data race",
      {
        stack({
          frame("log_it", "src/log.c", 5),
          frame("path_a", "src/a.c", 10),
          frame("top_a", "src/top_a.c", 100),
        }),
        stack({
          frame("log_it", "src/log.c", 5),
          frame("path_b", "src/b.c", 20),
          frame("top_b", "src/top_b.c", 200),
        }),
      },
      "src/log.c", 5
    )
    assert_eq(lines, {
      "[Race] data race",
      fmt("  " .. TOP .. HORIZ .. " ", "log_it", "log.c", 5),
      fmt(TOP .. CLOSE .. "  ", "path_a", "a.c", 10),
      fmt(MID .. "  ", "top_a", "top_a.c", 100),
      fmt(MID .. BOT .. "  ", "path_b", "b.c", 20),
      fmt(BOT .. "  ", "top_b", "top_b.c", 200),
    })
  end)

  it("factors common leaves after initial extraction passes", function()
    local lines = render_multi({
      { kind = "Leak", message = "r1",
        stacks = { stack({
          frame("alloc", "src/a.c", 10),
          frame("foo", "src/f.c", 20),
          frame("main", "src/main.c", 100),
        }, "r1") } },
      { kind = "Leak", message = "r2",
        stacks = { stack({
          frame("alloc", "src/a.c", 10),
          frame("bar", "src/b.c", 30),
          frame("main", "src/main.c", 100),
        }, "r2") } },
      { kind = "Leak", message = "r3",
        stacks = { stack({
          frame("alloc", "src/a.c", 10),
          frame("baz", "src/z.c", 40),
          frame("main", "src/main.c", 100),
        }, "r3") } },
      { kind = "Leak", message = "r4",
        stacks = { stack({
          frame("init", "src/i.c", 15),
          frame("bar", "src/b.c", 30),
          frame("main", "src/main.c", 100),
        }, "r4") } },
      { kind = "Leak", message = "r5",
        stacks = { stack({
          frame("init", "src/i.c", 15),
          frame("baz", "src/z.c", 40),
          frame("main", "src/main.c", 100),
        }, "r5") } },
    }, "src/a.c", 10)

    assert_eq(lines, {
      "[Leak] r1 (+4 more)",
      fmt("  " .. TOP .. HORIZ .. " ", "alloc", "a.c", 10),
      fmt("  " .. BRANCH .. HORIZ .. " ", "init", "i.c", 15),
      " " .. TOP .. MERGE .. " r1:",
      fmt(" " .. MID .. "  ", "foo", "f.c", 20),
      " " .. BRANCH .. HORIZ .. " r2:",
      " " .. BRANCH .. HORIZ .. " r4:",
      fmt(" " .. MID .. "  ", "bar", "b.c", 30),
      " " .. BRANCH .. HORIZ .. " r3:",
      " " .. BRANCH .. HORIZ .. " r5:",
      fmt(TOP .. CLOSE .. "  ", "baz", "z.c", 40),
      fmt(BOT .. "  ", "main", "main.c", 100),
    })
  end)
end)

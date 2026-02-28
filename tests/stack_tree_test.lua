vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

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
  T.reset_state()
  local err = T.new_error(kind, message, "test", stacks, {})
  local buf_lines = T.build_stack_content(query_file, query_line, { err.id })
  return buf_lines
end

local function render_multi(errs_spec, query_file, query_line)
  T.reset_state()
  local ids = {}
  for _, spec in ipairs(errs_spec) do
    local err = T.new_error(spec.kind, spec.message, "test", spec.stacks, {})
    table.insert(ids, err.id)
  end
  return T.build_stack_content(query_file, query_line, ids)
end

local TOP = "┌"
local MID = "│"
local BRANCH = "├"
local BOT = "└"
local CLOSE = "┘"
local MERGE = "┴"

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
      TOP .. " by thread T1:",
      BRANCH .. " Thread T1 (tid=1) created:",
      fmt(BRANCH .. "  ", "write_buf", "io.c", 10),
      fmt(BRANCH .. "  ", "spawn", "thread.c", 30),
      fmt(MID .. "  ", "main", "main.c", 100),
      BOT .. " by thread T2:",
      fmt("   ", "read_buf", "io.c", 20),
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
      " " .. TOP .. " by thread T1:",
      fmt(" " .. MID .. "  ", "write_buf", "io.c", 10),
      " " .. BRANCH .. " by thread T1:",
      fmt(" " .. MID .. "  ", "read_buf", "io.c", 20),
      TOP .. MERGE .. " Thread T1 (tid=1) created:",
      fmt(BRANCH .. "  ", "spawn", "thread.c", 30),
      fmt(BOT .. "  ", "main", "main.c", 100),
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
      " " .. TOP .. " Invalid write of size 1:",
      fmt(" " .. BRANCH .. "  ", "write_to_buffer", "demo.c", 151),
      fmt(" " .. MID .. "  ", "process_data", "demo.c", 158),
      " " .. BRANCH .. " Address 0x4a5cc50 is 0 bytes after a block of size 16 alloc'd:",
      fmt(TOP .. CLOSE .. "  ", "process_data", "demo.c", 156),
      fmt(BRANCH .. "  ", "demonstrate_buffer_overflow", "demo.c", 164),
      fmt(BOT .. "  ", "main", "demo.c", 328),
    })
  end)

  it("linear chain collapses cascading close brackets", function()
    -- A -> B -> C with a sibling branch D sharing root.
    -- Without collapsing: A-B-C would use depths 1-2-3 with ┌┘ cascades.
    -- With collapsing: A-B-C renders flat at depth 1.
    local lines = render(
      "Race", "data race",
      {
        stack({
          frame("inner", "src/deep.c", 1),
          frame("middle", "src/mid.c", 2),
          frame("outer", "src/out.c", 3),
          frame("main", "src/main.c", 100),
        }),
        stack({
          frame("other", "src/other.c", 50),
          frame("main", "src/main.c", 100),
        }),
      },
      "src/deep.c", 1
    )
    assert_eq(lines, {
      "[Race] data race",
      fmt(" " .. TOP .. "  ", "inner", "deep.c", 1),
      fmt(" " .. BRANCH .. "  ", "middle", "mid.c", 2),
      fmt(" " .. MID .. "  ", "outer", "out.c", 3),
      fmt(TOP .. CLOSE .. "  ", "other", "other.c", 50),
      fmt(BOT .. "  ", "main", "main.c", 100),
    })
  end)

  it("folds long chains with a summary line", function()
    T.set_config("stack_fold_limit", 6)
    local lines, fmap = (function()
      T.reset_state()
      local err = T.new_error("Race", "data race", "test", {
        stack({
          frame("f1", "src/a.c", 1),
          frame("f2", "src/a.c", 2),
          frame("f3", "src/a.c", 3),
          frame("f4", "src/a.c", 4),
          frame("f5", "src/a.c", 5),
          frame("f6", "src/a.c", 6),
          frame("f7", "src/a.c", 7),
          frame("f8", "src/a.c", 8),
          frame("main", "src/main.c", 100),
        }),
        stack({
          frame("other", "src/b.c", 50),
          frame("main", "src/main.c", 100),
        }),
      }, {})
      return T.build_stack_content("src/a.c", 1, { err.id })
    end)()
    -- Should show first 2, summary, last 1 of the 8-frame chain.
    assert_eq(lines[1], "[Race] data race")
    assert_eq(lines[2], fmt(" " .. TOP .. "  ", "f1", "a.c", 1))
    assert_eq(lines[3], fmt(" " .. BRANCH .. "  ", "f2", "a.c", 2))
    assert_eq(lines[4], " " .. BRANCH .. "  ... (5 more)")
    assert_eq(lines[5], fmt(" " .. MID .. "  ", "f8", "a.c", 8))
    -- Summary line stores collapsed frames.
    assert_eq(type(fmap[4].collapsed_frames), "table")
    assert_eq(#fmap[4].collapsed_frames, 5)
    -- Reset fold limit so other tests are not affected.
    T.set_config("stack_fold_limit", 0)
  end)

  it("strip_label trims whitespace and trailing colon", function()
    assert_eq(T.strip_label("  by thread T1:  "), "by thread T1")
  end)
end)

describe("compute_sharing_ratio", function()
  it("returns 0 for a single stack", function()
    assert_eq(T.compute_sharing_ratio({
      stack({ frame("a", "x.c", 1) }),
    }), 0)
  end)

  it("returns 0 when no frames are shared", function()
    assert_eq(T.compute_sharing_ratio({
      stack({ frame("a", "x.c", 1) }),
      stack({ frame("b", "y.c", 2) }),
    }), 0)
  end)

  it("returns 1 when all frames are shared", function()
    assert_eq(T.compute_sharing_ratio({
      stack({ frame("a", "x.c", 1), frame("b", "y.c", 2) }),
      stack({ frame("a", "x.c", 1), frame("b", "y.c", 2) }),
    }), 1)
  end)

  it("returns correct ratio for partial sharing", function()
    -- 3 unique keys (x.c:1, m.c:100, y.c:2), 1 shared (m.c:100): 1/3.
    local r = T.compute_sharing_ratio({
      stack({ frame("a", "x.c", 1), frame("main", "m.c", 100) }),
      stack({ frame("b", "y.c", 2), frame("main", "m.c", 100) }),
    })
    assert_eq(string.format("%.2f", r), "0.33")
  end)
end)

describe("flat section rendering", function()
  it("does not mark recursive frames as shared", function()
    -- fn_a calls itself recursively (same file:line). Only one stack has it,
    -- so it should NOT be marked as shared.
    local lines = render_multi({
      { kind = "Race", message = "r1",
        stacks = { stack({
          frame("fn_a", "src/a.c", 10),
          frame("fn_a", "src/a.c", 10),
          frame("caller", "src/top.c", 99),
        }, "stack A") } },
      { kind = "Race", message = "r2",
        stacks = { stack({
          frame("fn_b", "src/b.c", 20),
          frame("other", "src/other.c", 50),
        }, "stack B") } },
      { kind = "Race", message = "r3",
        stacks = { stack({
          frame("fn_c", "src/c.c", 30),
          frame("last", "src/last.c", 60),
        }, "stack C") } },
    }, "src/a.c", 10)
    -- fn_a appears twice in stack A but in no other stack: no * marker.
    assert_eq(lines[3], fmt(TOP .. "  ", "fn_a", "a.c", 10))
    assert_eq(lines[4], fmt(BRANCH .. "  ", "fn_a", "a.c", 10))
  end)

  it("marks shared frames with * in flat sections", function()
    -- 3 errors, only main is shared between first two.
    -- Sharing ratio: unique = {a.c:10, main.c:100, b.c:20, c.c:30, setup.c:300}
    -- shared = {main.c:100} = 1/5 = 0.2, below 0.3 threshold.
    local lines = render_multi({
      { kind = "Race", message = "r1",
        stacks = { stack({
          frame("fn_a", "src/a.c", 10),
          frame("main", "src/main.c", 100),
        }, "stack A") } },
      { kind = "Race", message = "r2",
        stacks = { stack({
          frame("fn_b", "src/b.c", 20),
          frame("main", "src/main.c", 100),
        }, "stack B") } },
      { kind = "Race", message = "r3",
        stacks = { stack({
          frame("fn_c", "src/c.c", 30),
          frame("setup", "src/setup.c", 300),
        }, "stack C") } },
    }, "src/a.c", 10)
    -- main.c:100 appears in stacks A and B, so it gets *.
    assert_eq(lines[4],
      string.format("└  %-27s* %s:%d", "main", "main.c", 100))
    assert_eq(lines[8],
      string.format("└  %-27s* %s:%d", "main", "main.c", 100))
    -- setup.c:300 is not shared, no *.
    assert_eq(lines[12], fmt(BOT .. "  ", "setup", "setup.c", 300))
  end)

  it("renders low-sharing stacks as flat sections with shared markers", function()
    -- 3 errors with completely disjoint stacks (0% sharing) triggers flat sections.
    local lines = render_multi({
      { kind = "Race", message = "r1",
        stacks = { stack({
          frame("fn_a", "src/a.c", 10),
          frame("main", "src/main.c", 100),
        }, "access by T1") } },
      { kind = "Race", message = "r2",
        stacks = { stack({
          frame("fn_b", "src/b.c", 20),
          frame("init", "src/init.c", 200),
        }, "access by T2") } },
      { kind = "Race", message = "r3",
        stacks = { stack({
          frame("fn_c", "src/c.c", 30),
          frame("setup", "src/setup.c", 300),
        }, "access by T3") } },
    }, "src/a.c", 10)

    -- All stacks are disjoint: flat sections, no * markers.
    assert_eq(lines, {
      "[Race] r1 (+2 more)",
      " access by T1:",
      fmt(TOP .. "  ", "fn_a", "a.c", 10),
      fmt(BOT .. "  ", "main", "main.c", 100),
      "",
      " access by T2:",
      fmt(TOP .. "  ", "fn_b", "b.c", 20),
      fmt(BOT .. "  ", "init", "init.c", 200),
      "",
      " access by T3:",
      fmt(TOP .. "  ", "fn_c", "c.c", 30),
      fmt(BOT .. "  ", "setup", "setup.c", 300),
    })
  end)
end)

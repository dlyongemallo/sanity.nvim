vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")

describe("generate_suppression", function()
  it("generates valgrind Memcheck:Addr for InvalidWrite", function()
    M._reset_state()
    local err = M._new_error("InvalidWrite", "Invalid write of size 4", "valgrind", {
      { label = "stack", frames = { { func = "bad_write", file = "a.c", line = 1 } } },
    }, {})
    local text, tool = M._generate_suppression(err)
    assert(text, "expected suppression text")
    assert_eq(tool, "valgrind")
    assert(text:find("Memcheck:Addr"), "expected Memcheck:Addr")
    assert(text:find("fun:bad_write"), "expected fun:bad_write")
  end)

  it("generates valgrind Memcheck:Leak with match-leak-kinds", function()
    M._reset_state()
    local err = M._new_error("Leak_DefinitelyLost", "definitely lost", "valgrind", {
      { label = "stack", frames = { { func = "alloc", file = "a.c", line = 1 } } },
    }, {})
    local text, tool = M._generate_suppression(err)
    assert(text, "expected suppression text")
    assert_eq(tool, "valgrind")
    assert(text:find("Memcheck:Leak"), "expected Memcheck:Leak")
    assert(text:find("match%-leak%-kinds: definite"), "expected match-leak-kinds: definite")
  end)

  it("generates valgrind Helgrind:Race for Race", function()
    M._reset_state()
    local err = M._new_error("Race", "data race", "valgrind", {
      { label = "stack", frames = { { func = "racy_fn", file = "a.c", line = 1 } } },
    }, {})
    local text, tool = M._generate_suppression(err)
    assert(text, "expected suppression text")
    assert_eq(tool, "valgrind")
    assert(text:find("Helgrind:Race"), "expected Helgrind:Race")
  end)

  it("fails for unsupported valgrind kind", function()
    M._reset_state()
    local err = M._new_error("SomeUnknownKind", "unknown", "valgrind", {
      { label = "stack", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local text, reason = M._generate_suppression(err)
    assert(not text, "expected nil text")
    assert(reason:find("not available"), "expected 'not available' in reason")
  end)

  it("fails when valgrind frames lack function names", function()
    M._reset_state()
    local err = M._new_error("InvalidRead", "Invalid read", "valgrind", {
      { label = "stack", frames = { { file = "a.c", line = 1 } } },
    }, {})
    local text, reason = M._generate_suppression(err)
    assert(not text, "expected nil text")
    assert(reason:find("No function name"), "expected 'No function name' in reason")
  end)

  it("fails when stacks are empty", function()
    M._reset_state()
    local err = M._new_error("InvalidRead", "Invalid read", "valgrind", {}, {})
    local text, reason = M._generate_suppression(err)
    assert(not text, "expected nil text")
    assert(reason:find("No stack frames"), "expected 'No stack frames' in reason")
  end)

  it("generates lsan suppression for sanitizer leak", function()
    M._reset_state()
    local err = M._new_error("detected memory leaks", "leak", "sanitizer", {
      { label = "stack", frames = { { func = "leaky", file = "a.c", line = 1 } } },
    }, { leak_type = "direct" })
    local text, tool = M._generate_suppression(err)
    assert(text, "expected suppression text")
    assert_eq(tool, "lsan")
    assert_eq(text, "leak:leaky")
  end)

  it("generates tsan suppression for data-race", function()
    M._reset_state()
    local err = M._new_error("data-race", "race", "sanitizer", {
      { label = "stack", frames = { { func = "racy", file = "a.c", line = 1 } } },
    }, {})
    local text, tool = M._generate_suppression(err)
    assert_eq(text, "race:racy")
    assert_eq(tool, "tsan")
  end)

  it("fails for unknown sanitizer kind", function()
    M._reset_state()
    local err = M._new_error("something-else", "unknown", "sanitizer", {
      { label = "stack", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local text, reason = M._generate_suppression(err)
    assert(not text, "expected nil text")
    assert(reason:find("not available"), "expected 'not available' in reason")
  end)

  it("fails for unknown error source", function()
    M._reset_state()
    local err = M._new_error("Race", "race", "mystery", {
      { label = "stack", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local text, reason = M._generate_suppression(err)
    assert(not text, "expected nil text")
    assert(reason:find("Unknown error source"), "expected 'Unknown error source' in reason")
  end)
end)

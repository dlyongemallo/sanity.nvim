vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

describe("expand_filter_args", function()
  it("expands preset names to kind lists", function()
    local result = T.expand_filter_args({ "leaks" })
    assert_eq(result, { "Leak_" })
  end)

  it("passes through unknown args verbatim", function()
    local result = T.expand_filter_args({ "SomeCustomKind" })
    assert_eq(result, { "SomeCustomKind" })
  end)

  it("deduplicates across presets and raw args", function()
    local result = T.expand_filter_args({ "races", "Race" })
    -- "races" expands to Race, data-race. "Race" is a duplicate.
    assert_eq(result, { "Race", "data-race" })
  end)

  it("handles multiple presets", function()
    local result = T.expand_filter_args({ "leaks", "races" })
    assert_eq(result, { "Leak_", "Race", "data-race" })
  end)
end)

describe("matches_filter", function()
  it("matches everything when filter is nil", function()
    T.set_filter(nil)
    assert_eq(T.matches_filter("Race"), true)
    assert_eq(T.matches_filter("anything"), true)
  end)

  it("matches exact kind", function()
    T.set_filter({ "Race", "InvalidWrite" })
    assert_eq(T.matches_filter("Race"), true)
    assert_eq(T.matches_filter("InvalidWrite"), true)
  end)

  it("matches by prefix", function()
    T.set_filter({ "Leak_" })
    assert_eq(T.matches_filter("Leak_DefinitelyLost"), true)
    assert_eq(T.matches_filter("Leak_PossiblyLost"), true)
  end)

  it("rejects non-matching kind", function()
    T.set_filter({ "Race" })
    assert_eq(T.matches_filter("InvalidWrite"), false)
  end)
end)

describe("get_available_kinds", function()
  it("returns sorted unique kinds from loaded errors", function()
    T.reset_state()
    T.new_error("Race", "race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})
    T.new_error("Race", "another race", "valgrind", {
      { label = "s", frames = { { func = "h", file = "c.c", line = 3 } } },
    }, {})

    local kinds = T.get_available_kinds()
    assert_eq(kinds, { "InvalidWrite", "Race" })
  end)

  it("returns empty list when no errors loaded", function()
    T.reset_state()
    assert_eq(T.get_available_kinds(), {})
  end)
end)

describe("get_qf_type", function()
  it("returns E for error-severity kinds", function()
    assert_eq(T.get_qf_type("InvalidRead"), "E")
    assert_eq(T.get_qf_type("InvalidWrite"), "E")
    assert_eq(T.get_qf_type("Leak_DefinitelyLost"), "E")
    assert_eq(T.get_qf_type("heap-use-after-free"), "E")
  end)

  it("returns W for warning-severity kinds", function()
    assert_eq(T.get_qf_type("Leak_PossiblyLost"), "W")
    assert_eq(T.get_qf_type("Leak_IndirectlyLost"), "W")
  end)

  it("returns I for info-severity kinds", function()
    assert_eq(T.get_qf_type("Leak_StillReachable"), "I")
  end)

  it("returns E for unknown kinds", function()
    assert_eq(T.get_qf_type("SomethingUnknown"), "E")
  end)
end)

describe("quickfix ordering", function()
  it("sorts entries by file and line number", function()
    T.reset_state()
    T.set_filter(nil)
    -- Insert out of line order so the test is meaningful.
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "writer", file = "demo.c", line = 30 } } },
    }, {})
    T.new_error("Leak_DefinitelyLost", "bytes lost", "valgrind", {
      { label = "s", frames = { { func = "alloc", file = "demo.c", line = 10 } } },
    }, {})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "worker", file = "demo.c", line = 20 } } },
    }, {})

    T.populate_quickfix()
    local qf = vim.fn.getqflist()
    assert_eq(#qf, 3)
    assert_eq(qf[1].lnum, 10)
    assert_eq(qf[2].lnum, 20)
    assert_eq(qf[3].lnum, 30)
    assert(qf[1].text:find("%[Leak_DefinitelyLost%]"), "expected Leak_DefinitelyLost at line 10: " .. qf[1].text)
    assert(qf[2].text:find("%[Race%]"), "expected Race at line 20: " .. qf[2].text)
    assert(qf[3].text:find("%[InvalidWrite%]"), "expected InvalidWrite at line 30: " .. qf[3].text)
  end)

  it("sorts by file then line across multiple files", function()
    T.reset_state()
    T.set_filter(nil)
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "w", file = "z.c", line = 1 } } },
    }, {})
    T.new_error("InvalidRead", "bad read", "valgrind", {
      { label = "s", frames = { { func = "r", file = "a.c", line = 99 } } },
    }, {})

    T.populate_quickfix()
    local qf = vim.fn.getqflist()
    assert_eq(#qf, 2)
    assert_eq(vim.fn.bufname(qf[1].bufnr), "a.c")
    assert_eq(qf[1].lnum, 99)
    assert_eq(vim.fn.bufname(qf[2].bufnr), "z.c")
    assert_eq(qf[2].lnum, 1)
  end)

  it("sets type field matching error severity", function()
    T.reset_state()
    T.set_filter(nil)
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "w", file = "t.c", line = 1 } } },
    }, {})
    T.new_error("Leak_PossiblyLost", "maybe lost", "valgrind", {
      { label = "s", frames = { { func = "a", file = "t.c", line = 2 } } },
    }, {})
    T.new_error("Leak_StillReachable", "reachable", "valgrind", {
      { label = "s", frames = { { func = "b", file = "t.c", line = 3 } } },
    }, {})

    T.populate_quickfix()
    local qf = vim.fn.getqflist()
    assert_eq(#qf, 3)
    assert_eq(qf[1].type, "E")
    assert_eq(qf[2].type, "W")
    assert_eq(qf[3].type, "I")
  end)
end)

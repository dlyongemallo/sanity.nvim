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

describe("get_priority", function()
  it("returns 1 for invalid access kinds", function()
    assert_eq(T.get_priority("InvalidRead"), 1)
    assert_eq(T.get_priority("InvalidWrite"), 1)
    assert_eq(T.get_priority("heap-use-after-free"), 1)
  end)

  it("returns 2 for uninit kinds", function()
    assert_eq(T.get_priority("UninitCondition"), 2)
    assert_eq(T.get_priority("UninitValue"), 2)
  end)

  it("returns 3 for race kinds", function()
    assert_eq(T.get_priority("Race"), 3)
    assert_eq(T.get_priority("data-race"), 3)
  end)

  it("returns 4 for definite leaks", function()
    assert_eq(T.get_priority("Leak_DefinitelyLost"), 4)
  end)

  it("returns 3 for unknown kinds", function()
    assert_eq(T.get_priority("SomethingNew"), 3)
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

describe("quickfix priority ordering", function()
  it("sorts entries by severity: invalid access before race before leak", function()
    T.reset_state()
    T.set_filter(nil)
    -- Insert in reverse priority order so the test is meaningful.
    T.new_error("Leak_DefinitelyLost", "bytes lost", "valgrind", {
      { label = "s", frames = { { func = "alloc", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "worker", file = "b.c", line = 2 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "writer", file = "c.c", line = 3 } } },
    }, {})

    T.populate_quickfix()
    local qf = vim.fn.getqflist()
    assert_eq(#qf, 3)
    assert(qf[1].text:find("%[InvalidWrite%]"), "expected InvalidWrite first: " .. qf[1].text)
    assert(qf[2].text:find("%[Race%]"), "expected Race second: " .. qf[2].text)
    assert(qf[3].text:find("%[Leak_DefinitelyLost%]"), "expected Leak last: " .. qf[3].text)
  end)

  it("uses lexicographic tiebreak within the same priority", function()
    T.reset_state()
    T.set_filter(nil)
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "w", file = "z.c", line = 9 } } },
    }, {})
    T.new_error("InvalidRead", "bad read", "valgrind", {
      { label = "s", frames = { { func = "r", file = "a.c", line = 1 } } },
    }, {})

    T.populate_quickfix()
    local qf = vim.fn.getqflist()
    assert_eq(#qf, 2)
    -- Both are priority 1; tiebreak is lexicographic on the group key (file:line:kind).
    assert(qf[1].text:find("%[InvalidRead%]"), "expected InvalidRead first: " .. qf[1].text)
    assert(qf[2].text:find("%[InvalidWrite%]"), "expected InvalidWrite second: " .. qf[2].text)
  end)
end)

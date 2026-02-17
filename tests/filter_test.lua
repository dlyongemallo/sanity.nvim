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

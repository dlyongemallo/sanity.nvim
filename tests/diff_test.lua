vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

describe("compute_diff_details", function()
  it("returns nil when no previous load exists", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local result = T.compute_diff_details()
    assert_eq(result, nil)
  end)

  it("classifies all errors as new when previous load was empty", function()
    T.reset_state()
    T.set_prev_fingerprints({})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})

    local result = T.compute_diff_details()
    assert_eq(#result.new, 2)
    assert_eq(#result.fixed, 0)
    assert_eq(#result.unchanged, 0)
    assert_eq(result.new[1].kind, "Race")
    assert_eq(result.new[2].kind, "InvalidWrite")
  end)

  it("classifies all errors as unchanged when fingerprints match", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.set_prev_fingerprints({ ["Race\0valgrind\0a.c:1"] = 1 })

    local result = T.compute_diff_details()
    assert_eq(#result.new, 0)
    assert_eq(#result.fixed, 0)
    assert_eq(#result.unchanged, 1)
    assert_eq(result.unchanged[1].kind, "Race")
  end)

  it("classifies all previous errors as fixed when current is empty", function()
    T.reset_state()
    T.set_prev_fingerprints({
      ["Race\0valgrind\0a.c:1"] = 1,
      ["InvalidWrite\0valgrind\0b.c:2"] = 1,
    })

    local result = T.compute_diff_details()
    assert_eq(#result.new, 0)
    assert_eq(#result.fixed, 2)
    assert_eq(#result.unchanged, 0)
  end)

  it("parses kind and location from fixed fingerprints", function()
    T.reset_state()
    T.set_prev_fingerprints({ ["Leak_DefinitelyLost\0valgrind\0src/alloc.c:42"] = 1 })

    local result = T.compute_diff_details()
    assert_eq(#result.fixed, 1)
    assert_eq(result.fixed[1].kind, "Leak_DefinitelyLost")
    assert_eq(result.fixed[1].source, "valgrind")
    assert_eq(result.fixed[1].location, "src/alloc.c:42")
  end)

  it("sets location to nil for fingerprints with no frame", function()
    T.reset_state()
    T.set_prev_fingerprints({ ["Race\0valgrind\0"] = 1 })

    local result = T.compute_diff_details()
    assert_eq(#result.fixed, 1)
    assert_eq(result.fixed[1].kind, "Race")
    assert_eq(result.fixed[1].location, nil)
  end)

  it("handles mixed new, fixed, and unchanged", function()
    T.reset_state()
    -- Current: Race at a.c:1, InvalidWrite at b.c:2.
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})
    -- Previous: Race at a.c:1 (unchanged), Leak at c.c:3 (fixed).
    T.set_prev_fingerprints({
      ["Race\0valgrind\0a.c:1"] = 1,
      ["Leak_DefinitelyLost\0valgrind\0c.c:3"] = 1,
    })

    local result = T.compute_diff_details()
    assert_eq(#result.unchanged, 1)
    assert_eq(result.unchanged[1].kind, "Race")
    assert_eq(#result.new, 1)
    assert_eq(result.new[1].kind, "InvalidWrite")
    assert_eq(#result.fixed, 1)
    assert_eq(result.fixed[1].kind, "Leak_DefinitelyLost")
  end)

  it("handles multiset: 3 previous to 1 current = 2 fixed + 1 unchanged", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.set_prev_fingerprints({ ["Race\0valgrind\0a.c:1"] = 3 })

    local result = T.compute_diff_details()
    assert_eq(#result.unchanged, 1)
    assert_eq(#result.fixed, 2)
    assert_eq(#result.new, 0)
    -- Both fixed entries should have the same kind and location.
    assert_eq(result.fixed[1].kind, "Race")
    assert_eq(result.fixed[2].kind, "Race")
  end)

  it("handles inverse multiset: 1 previous to 3 current = 2 new + 1 unchanged", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.set_prev_fingerprints({ ["Race\0valgrind\0a.c:1"] = 1 })

    local result = T.compute_diff_details()
    assert_eq(#result.unchanged, 1)
    assert_eq(#result.new, 2)
    assert_eq(#result.fixed, 0)
  end)
end)

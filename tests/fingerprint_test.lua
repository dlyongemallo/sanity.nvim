vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

describe("error fingerprint", function()
  it("produces a deterministic string from an error object", function()
    T.reset_state()
    local err = T.new_error("Race", "data race", "valgrind", {
      { label = "stack", frames = {
        { func = "worker", file = "src/w.c", line = 10 },
        { func = "main", file = "src/main.c", line = 99 },
      } },
    }, {})
    local fp = T.error_fingerprint(err)
    assert_eq(fp, "Race\0valgrind\0src/w.c:10")
  end)

  it("handles errors with no stacks gracefully", function()
    T.reset_state()
    local err = T.new_error("Race", "data race", "valgrind", {}, {})
    local fp = T.error_fingerprint(err)
    assert_eq(fp, "Race\0valgrind\0")
  end)

  it("handles errors with empty frames list", function()
    T.reset_state()
    local err = T.new_error("Race", "data race", "valgrind", {
      { label = "stack", frames = {} },
    }, {})
    local fp = T.error_fingerprint(err)
    assert_eq(fp, "Race\0valgrind\0")
  end)
end)

describe("snapshot fingerprints", function()
  it("returns a bag with correct counts for duplicates", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})

    local fps = T.snapshot_fingerprints()
    assert_eq(fps["Race\0valgrind\0a.c:1"], 2)
    assert_eq(fps["InvalidWrite\0valgrind\0b.c:2"], 1)
  end)

  it("returns empty table when no errors loaded", function()
    T.reset_state()
    local fps = T.snapshot_fingerprints()
    assert_eq(next(fps), nil)
  end)
end)

describe("compute diff summary", function()
  it("returns nil when no previous load exists", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local result = T.compute_diff_summary()
    assert_eq(result, nil)
  end)

  it("reports all new when previous load had 0 errors", function()
    T.reset_state()
    T.set_prev_fingerprints({})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local result = T.compute_diff_summary()
    assert_eq(result, " (1 new, 0 fixed, 0 unchanged)")
  end)

  it("reports all unchanged when sets are identical", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.set_prev_fingerprints({ ["Race\0valgrind\0a.c:1"] = 1 })
    local result = T.compute_diff_summary()
    assert_eq(result, " (0 new, 0 fixed, 1 unchanged)")
  end)

  it("reports all new when previous set was different", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.set_prev_fingerprints({ ["InvalidWrite\0valgrind\0b.c:2"] = 1 })
    local result = T.compute_diff_summary()
    assert_eq(result, " (1 new, 1 fixed, 0 unchanged)")
  end)

  it("handles multiset semantics: 3 prev to 1 current = 2 fixed + 1 unchanged", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.set_prev_fingerprints({ ["Race\0valgrind\0a.c:1"] = 3 })
    local result = T.compute_diff_summary()
    assert_eq(result, " (0 new, 2 fixed, 1 unchanged)")
  end)

  it("handles inverse multiset: 1 prev to 3 current = 2 new + 1 unchanged", function()
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
    local result = T.compute_diff_summary()
    assert_eq(result, " (2 new, 0 fixed, 1 unchanged)")
  end)

  it("handles mixed changes: some new, some fixed, some unchanged", function()
    T.reset_state()
    -- Current: 2x Race at a.c:1, 1x InvalidWrite at b.c:2.
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})
    -- Previous: 1x Race at a.c:1, 3x Leak at c.c:3.
    T.set_prev_fingerprints({
      ["Race\0valgrind\0a.c:1"] = 1,
      ["Leak_DefinitelyLost\0valgrind\0c.c:3"] = 3,
    })
    local result = T.compute_diff_summary()
    -- 1 Race unchanged, 1 Race new, 1 InvalidWrite new, 3 Leak fixed.
    assert_eq(result, " (2 new, 3 fixed, 1 unchanged)")
  end)
end)

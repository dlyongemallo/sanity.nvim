vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")

describe("find_related_targets", function()
  it("finds other stacks within the same error", function()
    M._reset_state()
    local err = M._new_error("Race", "data race on x", "test", {
      {
        label = "Write",
        frames = { { func = "writer", file = "src/a.c", line = 10 } },
      },
      {
        label = "Read",
        frames = { { func = "reader", file = "src/b.c", line = 20 } },
      },
    }, { addr = "0xBEEF" })

    local targets = M._find_related_targets(err, "src/a.c", 10, { err })
    assert_eq(#targets, 1)
    assert_eq(targets[1].file, "src/b.c")
    assert_eq(targets[1].line, 20)
    assert_eq(targets[1].label, "Read")
  end)

  it("finds errors sharing the same address", function()
    M._reset_state()
    local err1 = M._new_error("Race", "race on x", "test", {
      { label = "Write", frames = { { func = "w", file = "a.c", line = 1 } } },
    }, { addr = "0xDEAD" })
    local err2 = M._new_error("Race", "race on x", "test", {
      { label = "Read", frames = { { func = "r", file = "b.c", line = 2 } } },
    }, { addr = "0xDEAD" })

    local targets = M._find_related_targets(err1, "a.c", 1, { err1, err2 })
    assert_eq(#targets, 1)
    assert_eq(targets[1].file, "b.c")
    assert_eq(targets[1].line, 2)
    assert(targets[1].label:find("Race"), "expected label to contain error kind")
  end)

  it("deduplicates targets at the same file:line", function()
    M._reset_state()
    -- Two stacks in the same error both point to the same location.
    local err = M._new_error("Race", "race", "test", {
      { label = "S1", frames = { { func = "f", file = "a.c", line = 1 } } },
      { label = "S2", frames = { { func = "g", file = "b.c", line = 5 } } },
      { label = "S3", frames = { { func = "h", file = "b.c", line = 5 } } },
    }, { addr = "0xCAFE" })

    local targets = M._find_related_targets(err, "a.c", 1, { err })
    assert_eq(#targets, 1)
    assert_eq(targets[1].file, "b.c")
    assert_eq(targets[1].line, 5)
  end)

  it("combines intra-error and cross-error targets", function()
    M._reset_state()
    local err1 = M._new_error("Race", "race", "test", {
      { label = "Write", frames = { { func = "w", file = "a.c", line = 1 } } },
      { label = "Read", frames = { { func = "r", file = "b.c", line = 2 } } },
    }, { addr = "0xF00D" })
    local err2 = M._new_error("Race", "other race", "test", {
      { label = "Write", frames = { { func = "w2", file = "c.c", line = 3 } } },
    }, { addr = "0xF00D" })

    local targets = M._find_related_targets(err1, "a.c", 1, { err1, err2 })
    assert_eq(#targets, 2)
    -- Intra-error target first (other stack in same error).
    assert_eq(targets[1].file, "b.c")
    assert_eq(targets[1].line, 2)
    -- Cross-error target second.
    assert_eq(targets[2].file, "c.c")
    assert_eq(targets[2].line, 3)
  end)

  it("returns empty when no address metadata exists", function()
    M._reset_state()
    local err = M._new_error("Leak_DefinitelyLost", "leak", "test", {
      { label = "alloc", frames = { { func = "malloc", file = "a.c", line = 1 } } },
    }, {})

    local targets = M._find_related_targets(err, "a.c", 1, { err })
    assert_eq(#targets, 0)
  end)

  it("handles table-valued addr metadata", function()
    M._reset_state()
    local err1 = M._new_error("Race", "race", "test", {
      { label = "W", frames = { { func = "w", file = "a.c", line = 1 } } },
    }, { addr = { ["0xA"] = true, ["0xB"] = true } })
    local err2 = M._new_error("Race", "other", "test", {
      { label = "R", frames = { { func = "r", file = "b.c", line = 2 } } },
    }, { addr = "0xB" })

    local targets = M._find_related_targets(err1, "a.c", 1, { err1, err2 })
    assert_eq(#targets, 1)
    assert_eq(targets[1].file, "b.c")
  end)
end)

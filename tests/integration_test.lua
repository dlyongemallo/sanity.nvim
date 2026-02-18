vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test
local H = dofile("tests/helpers.lua")

-- Capture vim.notify messages during a callback.
local function capture_notify(fn)
  local messages = {}
  local orig = vim.notify
  vim.notify = function(msg) table.insert(messages, msg) end
  local ok, err = pcall(fn)
  vim.notify = orig
  if not ok then error(err) end
  return messages
end

describe("load_files integration", function()
  it("produces a summary message for sanitizer logs", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    local log = H.localize_log("examples/asan.log")
    local msgs = capture_notify(function()
      T.load_files({ log })
    end)
    -- Last message should be the summary.
    local summary = msgs[#msgs]
    assert(summary:find("^Loaded 1 errors into %d+ quickfix entr"), "unexpected summary: " .. summary)
    -- No previous load, so no diff suffix.
    assert(not summary:find("%("), "expected no diff suffix on first load")
  end)

  it("includes diff summary on second load", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    local log = H.localize_log("examples/asan.log")
    -- First load to populate state.
    capture_notify(function()
      T.load_files({ log })
    end)
    -- Second load of the same file.
    local msgs = capture_notify(function()
      T.load_files({ log })
    end)
    local summary = msgs[#msgs]
    assert(summary:find("%(%d+ new, %d+ fixed, %d+ unchanged%)"), "expected diff suffix: " .. summary)
    assert(summary:find("%(0 new, 0 fixed, 1 unchanged%)"), "expected all unchanged: " .. summary)
  end)

  it("shows diff after first load produced 0 errors", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    -- First load with no files produces 0 errors.
    capture_notify(function()
      T.load_files({})
    end)
    -- Second load with actual errors should show diff (all new).
    local log = H.localize_log("examples/asan.log")
    local msgs = capture_notify(function()
      T.load_files({ log })
    end)
    local summary = msgs[#msgs]
    assert(summary:find("%(1 new, 0 fixed, 0 unchanged%)"), "expected all-new diff: " .. summary)
  end)

  it("reflects changed errors in diff summary", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    local asan_log = H.localize_log("examples/asan.log")
    local tsan_log = H.localize_log("examples/tsan.log")
    -- Load ASAN log first.
    capture_notify(function()
      T.load_files({ asan_log })
    end)
    -- Now load TSAN log (different errors).
    local msgs = capture_notify(function()
      T.load_files({ tsan_log })
    end)
    local summary = msgs[#msgs]
    -- Both logs share a heap-use-after-free at demo.c:137 (same fingerprint),
    -- so that one is unchanged. The 2 other TSAN errors are new, 0 fixed.
    assert(summary:find("%(2 new, 0 fixed, 1 unchanged%)"), "expected partial turnover: " .. summary)
  end)
end)

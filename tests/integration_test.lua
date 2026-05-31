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
    T.set_config("snapshot_file", false)
    local log = H.localize_log("tests/asan.log")
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
    local log = H.localize_log("tests/asan.log")
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

  it("does not establish a diff baseline from an empty load", function()
    T.reset_state()
    -- set_prev_fingerprints(nil) also resets S.has_loaded to false.
    T.set_prev_fingerprints(nil)
    -- A call with no files must leave state untouched: it should not reset
    -- S.has_loaded or snapshot a bogus zero-error baseline that a later load
    -- would then diff against.
    local before_msgs = capture_notify(function()
      T.load_files({})
    end)
    -- An empty-filepaths call is allowed to be a silent no-op (the picker
    -- callback can produce {} when the user escapes), so no summary is
    -- required. But if any notification fires it must not claim a load.
    for _, m in ipairs(before_msgs) do
      assert(not m:find("^Loaded "), "empty load should not emit a Loaded summary: " .. m)
    end
    -- A real load afterwards is the first successful load, so no diff suffix.
    local log = H.localize_log("tests/asan.log")
    local msgs = capture_notify(function()
      T.load_files({ log })
    end)
    local summary = msgs[#msgs]
    assert(summary:find("^Loaded "), "expected summary from real load: " .. summary)
    assert(not summary:find("%("), "expected no diff suffix: " .. summary)
  end)

  it("reflects changed errors in diff summary", function()
    T.reset_state()
    T.set_prev_fingerprints(nil)
    local asan_log = H.localize_log("tests/asan.log")
    local tsan_log = H.localize_log("tests/tsan.log")
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

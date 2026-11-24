vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test
local N = require("sanity.navigate")
local SUP = require("sanity.suppressions")
local UI = require("sanity.ui")

-- Run `fn` with `tbl[key]` replaced by `replacement`; restore afterward.
-- Guards against the patched callee throwing by using pcall.
local function with_patched(tbl, key, replacement, fn)
    local original = tbl[key]
    tbl[key] = replacement
    local ok, err = pcall(fn)
    tbl[key] = original
    if not ok then error(err) end
end

-- Swallow vim.notify output during a call so the test log stays readable.
local function silently(fn)
    local orig = vim.notify
    vim.notify = function() end
    local ok, err = pcall(fn)
    vim.notify = orig
    if not ok then error(err) end
end

describe("command wiring", function()
  local fake_err = { kind = "InvalidWrite", stacks = {} }

  it(":SanitySuppress forwards (err, file, line) to generate_suppression", function()
    T.reset_state()
    local captured
    with_patched(N, "pick_error_at_cursor", function(cb) cb(fake_err, "a.c", 42) end, function()
      with_patched(SUP, "generate_suppression", function(err, file, line)
        captured = { err = err, file = file, line = line }
        return "stub-text", "valgrind"
      end, function()
        silently(M.suppress_error)
      end)
    end)
    assert_eq(captured.err, fake_err)
    assert_eq(captured.file, "a.c")
    assert_eq(captured.line, 42)
  end)

  it(":SanityDebug forwards (err, file, line) to UI.debug_error", function()
    local captured
    with_patched(N, "pick_error_at_cursor", function(cb) cb(fake_err, "b.c", 7) end, function()
      with_patched(UI, "debug_error", function(err, file, line, _nav)
        captured = { err = err, file = file, line = line }
      end, function()
        silently(M.debug_error)
      end)
    end)
    assert_eq(captured.err, fake_err)
    assert_eq(captured.file, "b.c")
    assert_eq(captured.line, 7)
  end)

  it(":SanityExplain forwards err to UI.explain_error", function()
    local captured
    with_patched(N, "pick_error_at_cursor", function(cb) cb(fake_err, "c.c", 11) end, function()
      with_patched(UI, "explain_error", function(err)
        captured = err
      end, function()
        silently(M.explain_error)
      end)
    end)
    assert_eq(captured, fake_err)
  end)
end)

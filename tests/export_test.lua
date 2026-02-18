vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

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

describe("export_errors", function()
  it("writes valid JSON containing all errors", function()
    T.reset_state()
    T.set_filter(nil)
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})

    local tmp = vim.fn.tempname() .. ".json"
    capture_notify(function()
      M.export_errors({ args = tmp })
    end)

    local fh = io.open(tmp, "r")
    assert(fh, "expected output file to exist")
    local content = fh:read("*a")
    fh:close()
    vim.fn.delete(tmp)

    local decoded = vim.fn.json_decode(content)
    assert_eq(#decoded, 2)
    assert_eq(decoded[1].kind, "Race")
    assert_eq(decoded[2].kind, "InvalidWrite")
    assert_eq(decoded[1].source, "valgrind")
  end)

  it("respects active filter", function()
    T.reset_state()
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      { label = "s", frames = { { func = "g", file = "b.c", line = 2 } } },
    }, {})
    T.set_filter({ "Race" })

    local tmp = vim.fn.tempname() .. ".json"
    capture_notify(function()
      M.export_errors({ args = tmp })
    end)

    local fh = io.open(tmp, "r")
    assert(fh, "expected output file to exist")
    local content = fh:read("*a")
    fh:close()
    vim.fn.delete(tmp)

    local decoded = vim.fn.json_decode(content)
    assert_eq(#decoded, 1)
    assert_eq(decoded[1].kind, "Race")
  end)

  it("notifies when no errors are loaded", function()
    T.reset_state()
    T.set_filter(nil)
    local msgs = capture_notify(function()
      M.export_errors({ args = vim.fn.tempname() })
    end)
    assert(#msgs > 0, "expected a notification")
    assert(msgs[1]:find("No errors to export"), "expected 'No errors' message: " .. msgs[1])
  end)

  it("uses default filename when no argument given", function()
    T.reset_state()
    T.set_filter(nil)
    T.new_error("Race", "data race", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})

    local msgs = capture_notify(function()
      M.export_errors({ args = "" })
    end)

    local summary = msgs[#msgs]
    assert(summary:find("sanity%-export%.json"), "expected default filename: " .. summary)
    vim.fn.delete("sanity-export.json")
  end)
end)

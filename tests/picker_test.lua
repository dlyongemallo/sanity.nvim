vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

local function reset_editor()
  vim.cmd("silent! cclose")
  vim.cmd("silent! only")
  vim.cmd("enew")
end

-- Open a buffer for `filename` with enough lines to place the cursor.
local function open_file(filename, num_lines)
  vim.cmd("edit " .. filename)
  local lines = {}
  for i = 1, (num_lines or 5) do lines[i] = "line " .. i end
  vim.api.nvim_buf_set_lines(0, 0, -1, false, lines)
end

describe("pick_error_at_cursor", function()
  it("deduplicates repeated error IDs at the same location", function()
    reset_editor()
    T.reset_state()
    local file = vim.fn.fnamemodify("dedup.c", ":p")
    -- Two stacks with frames at the same file:line produce duplicate IDs
    -- in the location index.
    T.new_error("Race", "race on x", "test", {
      { label = "Write", frames = { { func = "w", file = file, line = 1 } } },
      { label = "Read",  frames = { { func = "r", file = file, line = 1 } } },
    }, { addr = "0xBEEF" })
    open_file("dedup.c")
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    local called = 0
    local got_err
    T.pick_error_at_cursor(function(err)
      called = called + 1
      got_err = err
    end)

    -- Should call back directly (single unique error, no picker).
    assert_eq(called, 1)
    assert_eq(got_err.kind, "Race")
  end)

  it("calls callback directly for a single error", function()
    reset_editor()
    T.reset_state()
    local file = vim.fn.fnamemodify("single.c", ":p")
    local err = T.new_error("Leak_DefinitelyLost", "100 bytes lost", "test", {
      { label = "alloc", frames = { { func = "malloc", file = file, line = 3 } } },
    }, {})
    open_file("single.c")
    vim.api.nvim_win_set_cursor(0, { 3, 0 })

    local got_err, got_file, got_line
    T.pick_error_at_cursor(function(e, f, l)
      got_err = e
      got_file = f
      got_line = l
    end)

    assert_eq(got_err.id, err.id)
    assert_eq(got_file, file)
    assert_eq(got_line, 3)
  end)

  it("prompts via vim.ui.select for multiple errors", function()
    reset_editor()
    T.reset_state()
    local file = vim.fn.fnamemodify("multi.c", ":p")
    T.new_error("Race", "race #1", "test", {
      { label = "W1", frames = { { func = "w1", file = file, line = 2 } } },
    }, { addr = "0xA" })
    local err2 = T.new_error("heap-use-after-free", "uaf", "test", {
      { label = "W2", frames = { { func = "w2", file = file, line = 2 } } },
    }, {})
    open_file("multi.c")
    vim.api.nvim_win_set_cursor(0, { 2, 0 })

    -- Stub vim.ui.select to choose the second item.
    local orig_select = vim.ui.select
    local select_items
    vim.ui.select = function(items, opts, on_choice)
      select_items = items
      on_choice(items[2])
    end

    local got_err, got_file, got_line
    T.pick_error_at_cursor(function(e, f, l)
      got_err = e
      got_file = f
      got_line = l
    end)
    vim.ui.select = orig_select

    assert_eq(#select_items, 2)
    assert_eq(got_err.id, err2.id)
    assert_eq(got_file, file)
    assert_eq(got_line, 2)
  end)

  it("does not call back when vim.ui.select is cancelled", function()
    reset_editor()
    T.reset_state()
    local file = vim.fn.fnamemodify("cancel.c", ":p")
    T.new_error("Race", "r1", "test", {
      { label = "W", frames = { { func = "w", file = file, line = 1 } } },
    }, {})
    T.new_error("Race", "r2", "test", {
      { label = "W", frames = { { func = "w", file = file, line = 1 } } },
    }, {})
    open_file("cancel.c")
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    local orig_select = vim.ui.select
    vim.ui.select = function(_, _, on_choice) on_choice(nil) end

    local called = false
    T.pick_error_at_cursor(function() called = true end)
    vim.ui.select = orig_select

    assert_eq(called, false)
  end)

  it("notifies when no error exists at cursor", function()
    reset_editor()
    T.reset_state()
    open_file("empty.c")
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    local notified = false
    local orig_notify = vim.notify
    vim.notify = function(msg, level)
      if msg:find("No error") then notified = true end
    end

    T.pick_error_at_cursor(function() error("should not be called") end)
    vim.notify = orig_notify

    assert_eq(notified, true)
  end)
end)

vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

local function fresh_scratch(filetype, buftype)
  vim.cmd("silent! only")
  vim.cmd("enew")
  local buf = vim.api.nvim_get_current_buf()
  if filetype then vim.bo[buf].filetype = filetype end
  if buftype then vim.bo[buf].buftype = buftype end
  return vim.api.nvim_get_current_win(), buf
end

describe("window classifiers", function()
  it("tags a filetype=trouble buffer as trouble-like", function()
    local win = fresh_scratch("trouble", "nofile")
    assert_eq(T.is_trouble_like_window(win), true)
    assert_eq(T.is_qflist_window(win), false)
    assert_eq(T.is_loclist_window(win), false)
    assert_eq(T.is_source_window(win), false)
  end)

  it("does not tag a plain source buffer as trouble-like", function()
    local win = fresh_scratch(nil, nil)
    assert_eq(T.is_trouble_like_window(win), false)
  end)

  it("does not confuse a location-list window with a trouble window", function()
    vim.cmd("silent! only")
    vim.cmd("enew")
    vim.fn.setloclist(0, { { filename = "a.c", lnum = 1, text = "t" } })
    vim.cmd("lopen")
    local win = vim.api.nvim_get_current_win()
    -- `:lopen` lands in the location-list window.
    assert_eq(T.is_loclist_window(win), true)
    assert_eq(T.is_trouble_like_window(win), false)
    assert_eq(T.is_qflist_window(win), false)
    vim.cmd("lclose")
  end)

  it("tags a real quickfix window as qflist, not trouble or loclist", function()
    vim.cmd("silent! only")
    vim.cmd("enew")
    vim.fn.setqflist({ { filename = "a.c", lnum = 1, text = "t" } })
    vim.cmd("copen")
    local win = vim.api.nvim_get_current_win()
    assert_eq(T.is_qflist_window(win), true)
    assert_eq(T.is_trouble_like_window(win), false)
    assert_eq(T.is_loclist_window(win), false)
    vim.cmd("cclose")
  end)

  it("resolves a cursor position in the native :copen window without needing Trouble", function()
    -- Guard: the trouble module must NOT be loaded for this test to prove
    -- the native path is self-sufficient. Removing a loaded module from
    -- package.loaded only affects require resolution; is_trouble_like_window
    -- checks the buffer's filetype, which :copen does not set to "trouble".
    package.loaded["trouble"] = nil
    T.reset_state()
    local file = vim.fn.fnamemodify("qf_entry.c", ":p")
    T.new_error("Race", "r", "test", {
      { label = "s", frames = { { func = "f", file = file, line = 42 } } },
    }, {})
    T.populate_quickfix()
    vim.cmd("silent! only")
    vim.cmd("copen")
    local win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_cursor(win, { 1, 0 })
    local require_navigate = require("sanity.navigate")
    local got_file, got_line, got_ids = require_navigate.get_current_position()
    assert_eq(got_file, file)
    assert_eq(got_line, 42)
    assert(got_ids and #got_ids == 1, "expected one error id at cursor")
    vim.cmd("cclose")
  end)
end)

describe("get_qf_entry_position cache invalidation", function()
  it("reads error IDs from user_data so same-size reorders don't return stale IDs", function()
    T.reset_state()
    local file = vim.fn.fnamemodify("qf_dup.c", ":p")
    local race = T.new_error("Race", "race msg", "test", {
      { label = "W", frames = { { func = "w", file = file, line = 7 } } },
    }, {})
    local leak = T.new_error("Leak_DefinitelyLost", "leak msg", "test", {
      { label = "L", frames = { { func = "l", file = file, line = 7 } } },
    }, {})
    T.populate_quickfix()

    -- Two groups share (file, 7) but differ in kind, so populate produces
    -- two entries (sorted by kind: Leak before Race).
    local items = vim.fn.getqflist()
    assert_eq(#items, 2)
    assert_eq(items[1].text, "Leak_DefinitelyLost")
    assert_eq(items[2].text, "Race")

    -- Replace the list with a same-size reorder: swap the two entries. A
    -- length-only guard would still trust the stale index-keyed cache and
    -- hand back the original index-1 entry's error IDs for idx=1. With
    -- user_data as the source of truth, idx=1 now returns the Race's id.
    vim.fn.setqflist({ items[2], items[1] }, "r")

    local nav = require("sanity.navigate")
    local got_file, got_line, got_ids = nav.get_qf_entry_position(1)
    assert_eq(got_file, file)
    assert_eq(got_line, 7)
    assert(got_ids and #got_ids == 1, "expected one id on the surviving entry")
    assert_eq(got_ids[1], race.id)
    assert(got_ids[1] ~= leak.id, "must not return the old index-1 entry's id")
    vim.cmd("silent! only")
  end)
end)

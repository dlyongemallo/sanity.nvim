vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

local function reset_editor()
  vim.cmd("silent! cclose")
  vim.cmd("silent! only")
  vim.cmd("enew")
end

local function seed_related_qflist()
  T.reset_state()
  local a_file = vim.fn.fnamemodify("a.c", ":p")
  local b_file = vim.fn.fnamemodify("b.c", ":p")
  T.new_error("Race", "race on shared value", "test", {
    {
      label = "Write",
      frames = { { func = "writer", file = a_file, line = 1 } },
    },
    {
      label = "Read",
      frames = { { func = "reader", file = b_file, line = 1 } },
    },
  }, { addr = "0xBEEF" })
  T.populate_quickfix()
  vim.fn.setqflist({}, "a", { idx = 1 })
end

local function open_trouble_window(opts)
  opts = opts or {}
  vim.cmd("silent! only")
  vim.cmd("edit a.c")
  local source_win = vim.api.nvim_get_current_win()

  vim.cmd("vsplit")
  local trouble_win = vim.api.nvim_get_current_win()
  local trouble_buf = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_buf_set_lines(trouble_buf, 0, -1, false, { "entry 1", "entry 2" })
  vim.api.nvim_win_set_buf(trouble_win, trouble_buf)
  vim.bo[trouble_buf].filetype = "trouble"
  if opts.buftype ~= nil then
    vim.bo[trouble_buf].buftype = opts.buftype
  end
  vim.api.nvim_win_set_cursor(trouble_win, { 1, 0 })
  return source_win, trouble_win, trouble_buf
end

local function assert_source_jumped(source_win, suffix, line)
  local src_buf = vim.api.nvim_win_get_buf(source_win)
  local src_name = vim.api.nvim_buf_get_name(src_buf)
  assert(src_name:sub(-#suffix) == suffix, "expected source window to open " .. suffix .. ", got: " .. src_name)
  assert_eq(vim.api.nvim_win_get_cursor(source_win)[1], line)
end

describe("show_related window handling", function()
  it("jumps from trouble qflist windows with empty buftype", function()
    reset_editor()
    seed_related_qflist()
    local source_win, trouble_win, trouble_buf = open_trouble_window({ buftype = "" })

    vim.api.nvim_set_current_win(trouble_win)
    M.show_related()

    assert_eq(vim.api.nvim_get_current_win(), trouble_win)
    assert_eq(vim.api.nvim_win_get_buf(trouble_win), trouble_buf)
    assert_source_jumped(source_win, "b.c", 1)
  end)

  it("does not replace trouble qflist buffers even if buftype is quickfix", function()
    reset_editor()
    seed_related_qflist()
    local source_win, trouble_win, trouble_buf = open_trouble_window({ buftype = "quickfix" })

    vim.api.nvim_set_current_win(trouble_win)
    M.show_related()

    assert_eq(vim.api.nvim_get_current_win(), trouble_win)
    assert_eq(vim.api.nvim_win_get_buf(trouble_win), trouble_buf)
    assert_source_jumped(source_win, "b.c", 1)
  end)

  it("keeps focus in native quickfix windows", function()
    reset_editor()
    seed_related_qflist()
    vim.cmd("silent! only")
    vim.cmd("edit a.c")
    local source_win = vim.api.nvim_get_current_win()
    vim.cmd("copen")
    local qf_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_cursor(qf_win, { 1, 0 })

    M.show_related()

    assert_eq(vim.api.nvim_get_current_win(), qf_win)
    assert_source_jumped(source_win, "b.c", 1)
  end)

  it("works from the SanityStack window", function()
    reset_editor()
    seed_related_qflist()
    vim.cmd("silent! only")
    vim.cmd("edit a.c")
    local source_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_cursor(source_win, { 1, 0 })

    M.sanity_stack()
    local stack_win = vim.api.nvim_get_current_win()
    local stack_buf = vim.api.nvim_win_get_buf(stack_win)
    assert_eq(vim.bo[stack_buf].filetype, "sanity_stack")

    M.show_related()

    assert_eq(vim.api.nvim_get_current_win(), stack_win)
    assert_source_jumped(source_win, "b.c", 1)
    M.sanity_stack()
  end)

  it("updates stack cursor after a related jump", function()
    reset_editor()
    seed_related_qflist()
    vim.cmd("silent! only")
    vim.cmd("edit a.c")
    local source_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_cursor(source_win, { 1, 0 })

    M.sanity_stack()
    local stack_win = vim.api.nvim_get_current_win()
    assert_eq(vim.bo[vim.api.nvim_win_get_buf(stack_win)].filetype, "sanity_stack")

    -- First call jumps from a.c to b.c.
    M.show_related()
    assert_eq(vim.api.nvim_get_current_win(), stack_win)
    assert_source_jumped(source_win, "b.c", 1)

    -- If stack cursor moved to b.c, second call should jump back to a.c.
    M.show_related()
    assert_eq(vim.api.nvim_get_current_win(), stack_win)
    assert_source_jumped(source_win, "a.c", 1)
    M.sanity_stack()
  end)

  it("works from non-frame lines in the SanityStack window", function()
    reset_editor()
    seed_related_qflist()
    vim.cmd("silent! only")
    vim.cmd("edit a.c")
    local source_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_cursor(source_win, { 1, 0 })

    M.sanity_stack()
    local stack_win = vim.api.nvim_get_current_win()
    local stack_buf = vim.api.nvim_win_get_buf(stack_win)
    assert_eq(vim.bo[stack_buf].filetype, "sanity_stack")

    -- Header line does not map directly to a frame.
    vim.api.nvim_win_set_cursor(stack_win, { 1, 0 })
    M.show_related()

    assert_eq(vim.api.nvim_get_current_win(), stack_win)
    assert_source_jumped(source_win, "b.c", 1)
    M.sanity_stack()
  end)
end)

describe("show_related stack cursor tracking", function()
  it("keeps stack selection within the active error group when locations overlap", function()
    reset_editor()
    T.reset_state()
    local a_file = vim.fn.fnamemodify("a.c", ":p")
    local b_file = vim.fn.fnamemodify("b.c", ":p")
    T.new_error("Race", "race #1", "test", {
      { label = "Write", frames = { { func = "w1", file = a_file, line = 1 } } },
      { label = "Read", frames = { { func = "r1", file = b_file, line = 1 } } },
    }, { addr = "0xAAA" })
    T.new_error("data-race", "race #2", "test", {
      { label = "Write", frames = { { func = "w2", file = a_file, line = 1 } } },
      { label = "Read", frames = { { func = "r2", file = b_file, line = 1 } } },
    }, { addr = "0xBBB" })
    T.populate_quickfix()
    vim.fn.setqflist({}, "a", { idx = 1 })

    vim.cmd("silent! only")
    vim.cmd("edit a.c")
    local source_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_cursor(source_win, { 1, 0 })

    M.sanity_stack()
    local stack_win = vim.api.nvim_get_current_win()
    local stack_buf = vim.api.nvim_win_get_buf(stack_win)
    local lines = vim.api.nvim_buf_get_lines(stack_buf, 0, -1, false)

    local second_header = nil
    local second_write_line = nil
    for i, line in ipairs(lines) do
      if not second_header and line:find("^%[data%-race%]") then
        second_header = i
      elseif second_header and not second_write_line and line:find("a%.c:1$") then
        second_write_line = i
        break
      end
    end
    assert(second_header and second_write_line, "expected second group lines in stack buffer")
    vim.api.nvim_win_set_cursor(stack_win, { second_write_line, 0 })

    M.show_related()
    assert_source_jumped(source_win, "b.c", 1)
    local cur1 = vim.api.nvim_win_get_cursor(stack_win)[1]
    assert(cur1 > second_header, "expected cursor to remain in second group after first jump")

    M.show_related()
    assert_source_jumped(source_win, "a.c", 1)
    local cur2 = vim.api.nvim_win_get_cursor(stack_win)[1]
    assert(cur2 > second_header, "expected cursor to remain in second group after second jump")
    M.sanity_stack()
  end)
end)

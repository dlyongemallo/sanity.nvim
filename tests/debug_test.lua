vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

-- Run fn while capturing vim.notify messages and setreg calls.
local function capture_debug(fn)
  local messages = {}
  local registers = {}
  local orig_notify = vim.notify
  local orig_setreg = vim.fn.setreg
  vim.notify = function(msg) table.insert(messages, msg) end
  vim.fn.setreg = function(reg, val) registers[reg] = val end
  local ok, err = pcall(fn)
  vim.notify = orig_notify
  vim.fn.setreg = orig_setreg
  if not ok then error(err) end
  return messages, registers
end

describe("debug_error", function()
  it("warns when no error is at the cursor", function()
    T.reset_state()
    -- Open a scratch buffer with no errors registered.
    vim.cmd("enew!")
    vim.api.nvim_buf_set_name(0, "no_errors_here.c")
    vim.api.nvim_buf_set_lines(0, 0, -1, false, { "int main() {}" })
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    local msgs = capture_debug(function() M.debug_error() end)
    assert_eq(msgs[1], "No error at cursor.")
  end)

  it("copies GDB command with correct file and line when dap is absent", function()
    T.reset_state()
    local test_file = vim.fn.getcwd() .. "/src/demo.c"

    T.new_error("InvalidWrite", "bad write", "valgrind", {
      {
        label = "stack",
        frames = { { func = "main", file = test_file, line = 42 } },
      },
    }, {})

    -- Open a buffer matching the error's location so get_current_position
    -- returns the right file/line via the normal-buffer fallback path.
    vim.cmd("enew!")
    vim.api.nvim_buf_set_name(0, test_file)
    vim.api.nvim_buf_set_lines(0, 0, -1, false, vim.fn["repeat"]({ "" }, 50))
    vim.api.nvim_win_set_cursor(0, { 42, 0 })

    local msgs, regs = capture_debug(function() M.debug_error() end)

    local expected_cmd = 'break "' .. test_file .. '":42'
    assert_eq(regs["+"], expected_cmd, "GDB command should use quoted file path")
    assert(msgs[1]:find("GDB command copied"), "expected clipboard notification: " .. msgs[1])
  end)

  it("quotes file paths containing spaces", function()
    T.reset_state()
    local test_file = vim.fn.getcwd() .. "/my project/src/demo.c"

    T.new_error("InvalidRead", "bad read", "valgrind", {
      {
        label = "stack",
        frames = { { func = "foo", file = test_file, line = 7 } },
      },
    }, {})

    vim.cmd("enew!")
    vim.api.nvim_buf_set_name(0, test_file)
    vim.api.nvim_buf_set_lines(0, 0, -1, false, vim.fn["repeat"]({ "" }, 10))
    vim.api.nvim_win_set_cursor(0, { 7, 0 })

    local msgs, regs = capture_debug(function() M.debug_error() end)

    local expected_cmd = 'break "' .. test_file .. '":7'
    assert_eq(regs["+"], expected_cmd, "GDB command should quote path with spaces")
  end)

  it("does not replace the SanityStack buffer", function()
    T.reset_state()
    vim.cmd("silent! only")
    local src_file = vim.fn.fnamemodify("debug_src.c", ":p")
    T.new_error("InvalidWrite", "bad write", "valgrind", {
      {
        label = "stack",
        frames = { { func = "main", file = src_file, line = 1 } },
      },
    }, {})
    T.populate_quickfix()

    vim.cmd("edit " .. vim.fn.fnameescape(src_file))
    vim.api.nvim_buf_set_lines(0, 0, -1, false, { "int main() {}" })
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    M.sanity_stack()
    local stack_win = vim.api.nvim_get_current_win()
    local stack_buf = vim.api.nvim_win_get_buf(stack_win)
    assert_eq(vim.bo[stack_buf].filetype, "sanity_stack")

    capture_debug(function() M.debug_error() end)

    -- The stack window must still show the stack buffer, not the source file.
    assert_eq(vim.api.nvim_win_get_buf(stack_win), stack_buf)
    assert_eq(vim.bo[stack_buf].filetype, "sanity_stack")
    M.sanity_stack()
  end)
end)

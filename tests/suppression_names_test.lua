vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

local tmpdir = vim.fn.tempname()
vim.fn.mkdir(tmpdir, "p")

local function write_tmp(name, content)
  local path = tmpdir .. "/" .. name
  local f = io.open(path, "w")
  f:write(content)
  f:close()
  return path
end

describe("parse_suppression_names", function()
  it("extracts name from a normal suppression block", function()
    local path = write_tmp("normal.supp", [[
{
   my_suppression
   Memcheck:Leak
   fun:malloc
}
]])
    local result = T.parse_suppression_names(path)
    assert(result, "expected result")
    assert_eq(#result, 1)
    assert_eq(result[1].name, "my_suppression")
    assert_eq(result[1].file, path)
  end)

  it("skips comment lines before the name", function()
    local path = write_tmp("comments.supp", [[
{
   # This is a comment.
   # Another comment.
   actual_name
   Memcheck:Addr4
   fun:bad_fn
}
]])
    local result = T.parse_suppression_names(path)
    assert(result, "expected result")
    assert_eq(#result, 1)
    assert_eq(result[1].name, "actual_name")
  end)

  it("skips blank lines between brace and name", function()
    local path = write_tmp("blanks.supp", [[
{

   spaced_name
   Memcheck:Leak
   fun:alloc
}
]])
    local result = T.parse_suppression_names(path)
    assert(result, "expected result")
    assert_eq(#result, 1)
    assert_eq(result[1].name, "spaced_name")
  end)

  it("collects names from multiple blocks", function()
    local path = write_tmp("multi.supp", [[
{
   first_supp
   Memcheck:Leak
   fun:a
}
{
   second_supp
   Helgrind:Race
   fun:b
}
{
   third_supp
   Memcheck:Addr4
   fun:c
}
]])
    local result = T.parse_suppression_names(path)
    assert(result, "expected result")
    assert_eq(#result, 3)
    assert_eq(result[1].name, "first_supp")
    assert_eq(result[2].name, "second_supp")
    assert_eq(result[3].name, "third_supp")
  end)

  it("returns nil for missing file", function()
    local result = T.parse_suppression_names("/nonexistent/path.supp")
    assert_eq(result, nil)
  end)
end)

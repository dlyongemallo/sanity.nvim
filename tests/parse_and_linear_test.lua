vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test
local H = dofile("tests/helpers.lua")

local function basename(path)
  return (path:match("[^/]+$") or path)
end

describe("stack capture and linear rendering", function()
  it("captures caller chain from memcheck.xml", function()
    if not pcall(require, "xml2lua") then
      return
    end
    T.reset_state()
    local xml = H.localize_log("examples/memcheck.xml")
    local count = M.parse_valgrind_xml(xml)
    assert(count and count > 0, "expected parsed errors")

    local target = nil
    for _, err in ipairs(T.errors()) do
      if err.kind == "InvalidWrite" and err.message == "Invalid write of size 1" then
        target = err
        break
      end
    end
    assert(target, "expected InvalidWrite error")

    local s1 = target.stacks[1].frames
    assert_eq(s1[1].func, "write_to_buffer")
    assert_eq(s1[2].func, "process_data")
    assert_eq(s1[3].func, "demonstrate_buffer_overflow")
    assert_eq(s1[4].func, "main")
    assert_eq(basename(s1[4].file), "demo.c")
    assert_eq(s1[4].line, 328)

    -- Second stack (alloc site). The malloc frame from valgrind internals is
    -- filtered by the cwd check, so only project-local frames remain.
    local s2 = target.stacks[2].frames
    assert_eq(s2[1].func, "process_data")
    assert_eq(s2[2].func, "demonstrate_buffer_overflow")
    assert_eq(s2[3].func, "main")
    assert_eq(basename(s2[3].file), "demo.c")
    assert_eq(s2[3].line, 328)
  end)

  it("draws a single stack as a simple linear list", function()
    T.reset_state()
    local err = T.new_error("Race", "data race", "test", {
      {
        label = "data race",
        frames = {
          { func = "worker", file = "src/w.c", line = 10 },
          { func = "main", file = "src/main.c", line = 99 },
        },
      },
    }, {})

    local lines = T.build_stack_content("src/w.c", 10, { err.id })
    assert_eq(lines[1], "[Race] data race")
    assert_eq(lines[2], "┌  worker                       w.c:10")
    assert_eq(lines[3], "└  main                         main.c:99")
  end)

  it("draws middle frames in a linear stack with branch glyph", function()
    T.reset_state()
    local err = T.new_error("Leak_DefinitelyLost", "bytes lost", "test", {
      {
        label = "bytes lost",
        frames = {
          { func = "create_node", file = "demo.c", line = 220 },
          { func = "demonstrate_nested_leak", file = "demo.c", line = 233 },
          { func = "main", file = "demo.c", line = 346 },
        },
      },
    }, {})

    local lines = T.build_stack_content("demo.c", 220, { err.id })
    assert_eq(lines[1], "[Leak_DefinitelyLost] bytes lost")
    assert_eq(lines[2], "┌  create_node                  demo.c:220")
    assert_eq(lines[3], "├  demonstrate_nested_leak      demo.c:233")
    assert_eq(lines[4], "└  main                         demo.c:346")
  end)
end)

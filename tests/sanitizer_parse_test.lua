vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test
local H = dofile("tests/helpers.lua")

describe("detect_log_format", function()
  it("identifies valgrind XML", function()
    assert_eq(T.detect_log_format("examples/memcheck.xml"), "valgrind_xml")
  end)

  it("identifies ASAN sanitizer log", function()
    assert_eq(T.detect_log_format("examples/asan.log"), "sanitizer_log")
  end)

  it("identifies TSAN sanitizer log", function()
    assert_eq(T.detect_log_format("examples/tsan.log"), "sanitizer_log")
  end)

  it("returns nil for unrecognised format", function()
    assert_eq(T.detect_log_format("Makefile"), nil)
  end)
end)

describe("parse ASAN log", function()
  it("parses heap-use-after-free from asan.log", function()
    T.reset_state()
    local log = H.localize_log("examples/asan.log")
    local count = M.parse_sanitizer_log(log)
    assert(count and count > 0, "expected processed lines")

    local errs = T.errors()
    assert_eq(#errs, 1)
    assert_eq(errs[1].kind, "heap-use-after-free")
    assert_eq(errs[1].source, "sanitizer")

    -- First stack should contain the access frame.
    local s1 = errs[1].stacks[1].frames
    assert(#s1 >= 1, "expected at least one frame in first stack")
    assert_eq(s1[1].func, "demonstrate_use_after_free")
    assert_eq(s1[1].line, 137)

    -- Should have multiple stacks (read, freed by, previously allocated).
    assert(#errs[1].stacks >= 3, "expected at least 3 stacks")
  end)
end)

describe("parse TSAN log", function()
  it("parses three errors from tsan.log", function()
    T.reset_state()
    local log = H.localize_log("examples/tsan.log")
    local count = M.parse_sanitizer_log(log)
    assert(count and count > 0, "expected processed lines")

    local errs = T.errors()
    assert_eq(#errs, 3)
  end)

  it("identifies data-race kind and metadata", function()
    T.reset_state()
    M.parse_sanitizer_log(H.localize_log("examples/tsan.log"))

    local errs = T.errors()
    local race = nil
    for _, e in ipairs(errs) do
      if e.kind == "data-race" then race = e; break end
    end
    assert(race, "expected data-race error")

    -- Should have rw_op metadata accumulated as sets.
    assert(race.meta.rw_op, "expected rw_op metadata")
    assert(race.meta.addr, "expected addr metadata")
    assert(race.meta.thr, "expected thr metadata")

    -- First stack should contain the read frame.
    assert_eq(race.stacks[1].frames[1].func, "read_counter")
  end)

  it("identifies lock-order-inversion kind", function()
    T.reset_state()
    M.parse_sanitizer_log(H.localize_log("examples/tsan.log"))

    local errs = T.errors()
    local lock = nil
    for _, e in ipairs(errs) do
      if e.kind == "lock-order-inversion" then lock = e; break end
    end
    assert(lock, "expected lock-order-inversion error")
    assert(#lock.stacks >= 2, "expected multiple stacks for lock-order-inversion")
  end)

  it("identifies heap-use-after-free kind", function()
    T.reset_state()
    M.parse_sanitizer_log(H.localize_log("examples/tsan.log"))

    local errs = T.errors()
    local uaf = nil
    for _, e in ipairs(errs) do
      if e.kind == "heap-use-after-free" then uaf = e; break end
    end
    assert(uaf, "expected heap-use-after-free error")
    assert_eq(uaf.stacks[1].frames[1].func, "demonstrate_use_after_free")
    assert_eq(uaf.stacks[1].frames[1].line, 137)
  end)
end)

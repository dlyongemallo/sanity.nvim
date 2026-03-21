vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test
local H = dofile("tests/helpers.lua")

describe("detect_log_format", function()
  it("identifies valgrind XML", function()
    assert_eq(T.detect_log_format("tests/memcheck.xml"), "valgrind_xml")
  end)

  it("identifies ASAN sanitizer log", function()
    assert_eq(T.detect_log_format("tests/asan.log"), "sanitizer_log")
  end)

  it("identifies TSAN sanitizer log", function()
    assert_eq(T.detect_log_format("tests/tsan.log"), "sanitizer_log")
  end)

  it("returns nil for unrecognised format", function()
    assert_eq(T.detect_log_format("Makefile"), nil)
  end)
end)

describe("parse ASAN log", function()
  it("parses heap-use-after-free from asan.log", function()
    T.reset_state()
    local log = H.localize_log("tests/asan.log")
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
    local log = H.localize_log("tests/tsan.log")
    local count = M.parse_sanitizer_log(log)
    assert(count and count > 0, "expected processed lines")

    local errs = T.errors()
    assert_eq(#errs, 3)
  end)

  it("identifies data-race kind and metadata", function()
    T.reset_state()
    M.parse_sanitizer_log(H.localize_log("tests/tsan.log"))

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
    M.parse_sanitizer_log(H.localize_log("tests/tsan.log"))

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
    M.parse_sanitizer_log(H.localize_log("tests/tsan.log"))

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

describe("detect_log_format for UBSAN", function()
  it("identifies UBSAN log", function()
    assert_eq(T.detect_log_format("tests/ubsan.log"), "ubsan_log")
  end)
end)

describe("parse UBSAN log", function()
  it("parses signed-integer-overflow with stack frames", function()
    T.reset_state()
    local log = H.localize_log("tests/ubsan.log")
    local count = M.parse_ubsan_log(log)
    assert(count and count > 0, "expected parsed errors")

    local errs = T.errors()
    assert(#errs >= 1, "expected at least 1 error")

    local overflow = nil
    for _, e in ipairs(errs) do
      if e.kind == "signed-integer-overflow" then overflow = e; break end
    end
    assert(overflow, "expected signed-integer-overflow error")
    assert_eq(overflow.source, "sanitizer")

    -- Should have parsed stack frames.
    local s1 = overflow.stacks[1].frames
    assert(#s1 >= 1, "expected at least one frame")
    assert_eq(s1[1].func, "overflow_add")
    assert_eq(s1[1].line, 55)
  end)

  it("parses null-pointer error without stack frames", function()
    T.reset_state()
    local log = H.localize_log("tests/ubsan.log")
    M.parse_ubsan_log(log)

    local errs = T.errors()
    local null_err = nil
    for _, e in ipairs(errs) do
      if e.kind == "null-pointer-passed-as-argument" then null_err = e; break end
    end
    assert(null_err, "expected null-pointer-passed-as-argument error")
    -- Should have a single-frame stack from the header location.
    assert_eq(#null_err.stacks, 1)
    assert_eq(null_err.stacks[1].frames[1].line, 72)
  end)
end)

describe("detect_log_format for MSAN", function()
  it("identifies MSAN sanitizer log", function()
    assert_eq(T.detect_log_format("tests/msan.log"), "sanitizer_log")
  end)
end)

describe("parse MSAN log", function()
  it("parses use-of-uninitialized-value from msan.log", function()
    T.reset_state()
    local log = H.localize_log("tests/msan.log")
    local count = M.parse_sanitizer_log(log)
    assert(count and count > 0, "expected processed lines")

    local errs = T.errors()
    assert_eq(#errs, 1)
    assert_eq(errs[1].kind, "use-of-uninitialized-value")
    assert_eq(errs[1].source, "sanitizer")

    local s1 = errs[1].stacks[1].frames
    assert(#s1 >= 1, "expected at least one frame in first stack")
    assert_eq(s1[1].func, "process_data")
    assert_eq(s1[1].line, 42)
  end)

  it("strips column numbers from file:line:col frames", function()
    T.reset_state()
    local log = H.localize_log("tests/msan.log")
    M.parse_sanitizer_log(log)

    local errs = T.errors()
    assert_eq(#errs, 1)

    -- The filename must not include a trailing line/column suffix (e.g. "demo.c:42").
    local s1 = errs[1].stacks[1].frames
    assert(not s1[1].file:match(":%d+$"), "line/column number leaked into filename: " .. s1[1].file)
    assert(s1[1].file:match("demo%.c$"), "expected filename ending in demo.c, got: " .. s1[1].file)
  end)
end)

describe("normalize_path in location_index", function()
  it("matches errors despite redundant slashes in frame paths", function()
    T.reset_state()
    local cwd = vim.fn.getcwd()
    local file_with_slashes = cwd .. "//src//main.c"
    local normalised = T.normalize_path(file_with_slashes)
    T.new_error("InvalidRead", "bad read", "test", {
      { label = "stack", frames = { { func = "f", file = file_with_slashes, line = 42 } } },
    }, {})
    -- The location_index key should use the normalised path.
    local errs = T.errors()
    assert_eq(#errs, 1)
    local key = normalised .. ":42"
    local li = T.location_index()
    assert(li[key] and #li[key] > 0, "expected non-empty location_index entry at normalised key: " .. key)
    assert_eq(li[key][1], errs[1].id)
  end)
end)

vim.opt.rtp:prepend(vim.fn.fnamemodify(debug.getinfo(1, "S").source:match("@?(.*/)"), ":p") .. "/..")
local M = require("sanity")
local T = M._test

describe("starts_with", function()
  it("returns true for matching prefix", function()
    assert_eq(T.starts_with("Leak_DefinitelyLost", "Leak_"), true)
  end)

  it("returns false for non-matching prefix", function()
    assert_eq(T.starts_with("Race", "Leak_"), false)
  end)

  it("returns true for empty prefix", function()
    assert_eq(T.starts_with("anything", ""), true)
  end)
end)

describe("ipairs_safe", function()
  it("iterates numeric keys in order", function()
    local result = {}
    for k, v in T.ipairs_safe({ [1] = "a", [2] = "b", [3] = "c" }) do
      table.insert(result, k .. "=" .. v)
    end
    assert_eq(result, { "1=a", "2=b", "3=c" })
  end)

  it("iterates string-numeric keys in order", function()
    local result = {}
    for k, v in T.ipairs_safe({ ["2"] = "b", ["1"] = "a", ["3"] = "c" }) do
      table.insert(result, k .. "=" .. v)
    end
    assert_eq(result, { "1=a", "2=b", "3=c" })
  end)

  it("returns empty iterator for non-table input", function()
    local count = 0
    for _ in T.ipairs_safe("not a table") do
      count = count + 1
    end
    assert_eq(count, 0)
  end)

  it("returns empty iterator for nil input", function()
    local count = 0
    for _ in T.ipairs_safe(nil) do
      count = count + 1
    end
    assert_eq(count, 0)
  end)
end)

describe("summarize_rw", function()
  it("returns read for read-only set", function()
    assert_eq(T.summarize_rw({ read = true }), "read")
  end)

  it("returns write for write-only set", function()
    assert_eq(T.summarize_rw({ write = true }), "write")
  end)

  it("returns read/write for both", function()
    assert_eq(T.summarize_rw({ read = true, write = true }), "read/write")
  end)

  it("returns unknown operation for empty set", function()
    assert_eq(T.summarize_rw({}), "unknown operation")
  end)
end)

describe("summarize_table_keys", function()
  it("returns single key directly", function()
    assert_eq(T.summarize_table_keys({ hello = true }), "hello")
  end)

  it("returns multiple keys sorted and joined with slash", function()
    assert_eq(T.summarize_table_keys({ b = true, a = true, c = true }), "a/b/c")
  end)

  it("returns first-only with /... suffix", function()
    assert_eq(T.summarize_table_keys({ b = true, a = true }, true), "a/...")
  end)

  it("sorts numerically when requested", function()
    assert_eq(T.summarize_table_keys({ ["10"] = true, ["2"] = true }, false, true), "2/10")
  end)
end)

describe("merge_meta_sets", function()
  it("merges set fields from multiple errors", function()
    local errs = {
      { meta = { addr = { ["0xA"] = true } } },
      { meta = { addr = { ["0xB"] = true } } },
    }
    local merged = T.merge_meta_sets(errs, "addr")
    assert_eq(merged["0xA"], true)
    assert_eq(merged["0xB"], true)
  end)

  it("returns empty table when field is absent", function()
    local errs = { { meta = {} }, { meta = {} } }
    local merged = T.merge_meta_sets(errs, "addr")
    assert_eq(next(merged), nil)
  end)
end)

describe("format_link_set", function()
  it("formats a single link", function()
    local result = T.format_link_set({ ["->main.c:000099"] = true })
    assert_eq(result, "main.c:99")
  end)

  it("comma-separates multiple lines in the same file", function()
    local result = T.format_link_set({
      ["->main.c:000010"] = true,
      ["->main.c:000020"] = true,
    })
    assert_eq(result, "main.c:10,20")
  end)

  it("slash-separates different files", function()
    local result = T.format_link_set({
      ["->a.c:000001"] = true,
      ["->b.c:000002"] = true,
    })
    assert_eq(result, "a.c:1/b.c:2")
  end)

  it("appends END at the end", function()
    local result = T.format_link_set({
      ["->main.c:000099"] = true,
      ["END"] = true,
    })
    assert_eq(result, "main.c:99/END")
  end)

  it("handles END-only link set", function()
    local result = T.format_link_set({ ["END"] = true })
    assert_eq(result, "END")
  end)

  it("handles empty link set", function()
    local result = T.format_link_set({})
    assert_eq(result, "")
  end)
end)

describe("format_valgrind_group", function()
  it("formats a race message", function()
    T.reset_state()
    local err = T.new_error("Race",
      "Possible data race during read of size 4 at 0xDEAD by thread #1",
      "valgrind", {
        { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
      }, { rw = "read", size = "4", addr = "0xDEAD", thr = "#1" })
    local result = T.format_valgrind_group("Race", { err }, "a.c:1")
    assert_eq(result, "[Race] Possible data race during read of size 4 at 0xDEAD by thread #1 (a.c:1)")
  end)

  it("formats a leak message", function()
    T.reset_state()
    local err = T.new_error("Leak_DefinitelyLost",
      "100 bytes in 1 blocks are lost in loss record 3 of 10",
      "valgrind", {
        { label = "s", frames = { { func = "alloc", file = "a.c", line = 1 } } },
      }, { leak_type = "DefinitelyLost", size = "100", blocks = "1", loss_record = "3", total_records = "10" })
    local result = T.format_valgrind_group("Leak_DefinitelyLost", { err }, "a.c:1")
    assert_eq(result, "[Leak_DefinitelyLost] 100 bytes in 1 blocks in loss record 3 of 10 (a.c:1)")
  end)

  it("formats a general message and strips kind prefix", function()
    T.reset_state()
    local err = T.new_error("InvalidWrite", "InvalidWrite of size 4", "valgrind", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local result = T.format_valgrind_group("InvalidWrite", { err }, "a.c:1")
    assert_eq(result, "[InvalidWrite] of size 4 (a.c:1)")
  end)
end)

describe("format_sanitizer_group", function()
  it("formats rw_op errors", function()
    T.reset_state()
    local err = T.new_error("data-race", "data race", "sanitizer", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, { rw_op = { Read = true }, size = { ["4"] = true }, addr = { ["0xBEEF"] = true }, thr = { T1 = true } })
    local result = T.format_sanitizer_group("data-race", { err }, "a.c:1")
    assert_eq(result, "[data-race] Read of size 4 at 0xBEEF by thread T1 (a.c:1)")
  end)

  it("formats mutex creation", function()
    T.reset_state()
    local err = T.new_error("lock-order-inversion", "deadlock", "sanitizer", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, { mutex = { M0 = true } })
    local result = T.format_sanitizer_group("lock-order-inversion", { err }, "a.c:1")
    assert_eq(result, "[lock-order-inversion] Mutex M0 created (a.c:1)")
  end)

  it("formats heap block", function()
    T.reset_state()
    local err = T.new_error("heap-use-after-free", "uaf", "sanitizer", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, { heap_block = true, size = { ["32"] = true }, addr = { ["0xCAFE"] = true }, thr = { T0 = true } })
    local result = T.format_sanitizer_group("heap-use-after-free", { err }, "a.c:1")
    assert_eq(result, "[heap-use-after-free] Location is heap block of size 32 at 0xCAFE allocated by T0 (a.c:1)")
  end)

  it("formats leak errors", function()
    T.reset_state()
    local err = T.new_error("detected-memory-leaks", "leak", "sanitizer", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, { leak_type = { direct = true }, size = { ["64"] = true }, num_objs = { ["1"] = true } })
    local result = T.format_sanitizer_group("detected-memory-leaks", { err }, "a.c:1")
    assert_eq(result, "[detected-memory-leaks] direct leak of 64 byte(s) in 1 object(s) allocated from (a.c:1)")
  end)

  it("formats general message and strips kind prefix", function()
    T.reset_state()
    local err = T.new_error("signal-unsafe-call", "signal-unsafe-call inside signal handler", "sanitizer", {
      { label = "s", frames = { { func = "f", file = "a.c", line = 1 } } },
    }, {})
    local result = T.format_sanitizer_group("signal-unsafe-call", { err }, "a.c:1")
    assert_eq(result, "[signal-unsafe-call] inside signal handler (a.c:1)")
  end)
end)

-- Minimal test harness for nvim --headless -l.
local tests = {}
local current_describe = ""

function describe(name, fn)
  current_describe = name
  fn()
  current_describe = ""
end

function it(name, fn)
  table.insert(tests, { name = current_describe .. " > " .. name, fn = fn })
end

function assert_eq(actual, expected, msg)
  if type(actual) == "table" and type(expected) == "table" then
    local max = math.max(#actual, #expected)
    for i = 1, max do
      if actual[i] ~= expected[i] then
        local lines = { (msg or "assert_eq") .. ": mismatch at index " .. i }
        table.insert(lines, "  expected: " .. vim.inspect(expected[i]))
        table.insert(lines, "  actual:   " .. vim.inspect(actual[i]))
        for j = math.max(1, i - 2), math.min(max, i + 2) do
          local marker = j == i and " >> " or "    "
          table.insert(lines, marker .. j .. " exp: " .. vim.inspect(expected[j]))
          table.insert(lines, marker .. j .. " act: " .. vim.inspect(actual[j]))
        end
        error(table.concat(lines, "\n"))
      end
    end
    return
  end
  if actual ~= expected then
    error((msg or "assert_eq") .. "\n  expected: " .. vim.inspect(expected) .. "\n  actual:   " .. vim.inspect(actual))
  end
end

local passed, failed = 0, 0
local test_dir = debug.getinfo(1, "S").source:match("@?(.*/)")
for _, file in ipairs(vim.fn.glob(test_dir .. "*_test.lua", false, true)) do
  dofile(file)
end

for _, t in ipairs(tests) do
  local ok, err = pcall(t.fn)
  if ok then
    passed = passed + 1
    io.write("  \27[32m✓\27[0m " .. t.name .. "\n")
  else
    failed = failed + 1
    io.write("  \27[31m✗\27[0m " .. t.name .. "\n")
    io.write("    " .. tostring(err):gsub("\n", "\n    ") .. "\n")
  end
end

io.write(string.format("\n%d passed, %d failed\n", passed, failed))
vim.cmd("cquit " .. (failed > 0 and "1" or "0"))

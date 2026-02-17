-- Shared test helpers.
local H = {}

local LOG_PREFIX = "/home/user/project/"

-- Copy a log file to a temp path with absolute paths rewritten to match cwd.
-- Sanitizer log parsers filter frames by starts_with(target, cwd), so the
-- embedded paths must match wherever the tests are running.
function H.localize_log(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local content = f:read("*a")
  f:close()
  local cwd = vim.fn.getcwd() .. "/"
  content = content:gsub(LOG_PREFIX, cwd)
  local tmp = vim.fn.tempname()
  local out = io.open(tmp, "w")
  out:write(content)
  out:close()
  return tmp
end

return H

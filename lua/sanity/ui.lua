-- Floating windows and display commands.
local S = require("sanity.state")
local F = require("sanity.format")
local D = require("sanity.diff")
local Q = require("sanity.quickfix")

local UI = {}

-- Open a floating window with the given title and lines.
function UI.show_floating_window(title, lines)
    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.bo[buf].modifiable = false
    vim.bo[buf].bufhidden = "wipe"

    local width = 0
    for _, line in ipairs(lines) do
        width = math.max(width, vim.fn.strdisplaywidth(line))
    end
    width = math.min(width + 2, vim.o.columns - 4)
    local height = math.min(#lines, vim.o.lines - 4)

    local win = vim.api.nvim_open_win(buf, true, {
        relative = "cursor",
        row = 1,
        col = 0,
        width = width,
        height = height,
        style = "minimal",
        border = "rounded",
        title = " " .. title .. " ",
        title_pos = "center",
    })

    vim.keymap.set("n", "q", function() vim.api.nvim_win_close(win, true) end, { buffer = buf })
    vim.keymap.set("n", "<Esc>", function() vim.api.nvim_win_close(win, true) end, { buffer = buf })
end

-- Serialize the current error set to a JSON file.
function UI.export_errors(args)
    if #S.errors == 0 then
        vim.notify("No errors to export.", vim.log.levels.INFO)
        return
    end

    local filename = args and args.args and args.args ~= "" and args.args or "sanity-export.json"

    -- Build a serializable representation of the error set.
    local export = {}
    for _, err in ipairs(S.errors) do
        if not Q.matches_filter(err.kind) then goto export_continue end
        table.insert(export, {
            id = err.id,
            kind = err.kind,
            message = err.message,
            source = err.source,
            meta = err.meta,
            stacks = err.stacks,
        })
        ::export_continue::
    end

    local json = vim.fn.json_encode(export)
    local fh, open_err = io.open(filename, "w")
    if not fh then
        vim.notify(("Failed to open %s for writing: %s"):format(filename, open_err or "unknown error"),
            vim.log.levels.ERROR)
        return
    end
    local ok, write_err = fh:write(json .. "\n")
    fh:close()
    if not ok then
        vim.notify(("Failed to write to %s: %s"):format(filename, write_err or "unknown error"),
            vim.log.levels.ERROR)
        return
    end
    vim.notify("Exported " .. #export .. " error(s) to " .. filename .. ".")
end

-- Show a floating window with the detailed run-to-run diff.
function UI.show_diff()
    local details = D.compute_diff_details()
    if not details then
        vim.notify("No previous run to compare against. Load or run twice to see a diff.",
            vim.log.levels.INFO)
        return
    end

    -- Group entries by kind + location, returning { {kind, location, count}, ... }.
    local function group_entries(entries, get_kind_loc)
        local groups = {}
        local seen = {}
        for _, entry in ipairs(entries) do
            local kind, location = get_kind_loc(entry)
            local key = kind .. "\0" .. (location or "")
            if seen[key] then
                groups[seen[key]].count = groups[seen[key]].count + 1
            else
                table.insert(groups, { kind = kind, location = location, count = 1 })
                seen[key] = #groups
            end
        end
        table.sort(groups, function(a, b)
            if a.kind ~= b.kind then return a.kind < b.kind end
            return (a.location or "") < (b.location or "")
        end)
        return groups
    end

    local function error_kind_loc(err)
        local loc
        if err.stacks and err.stacks[1] and err.stacks[1].frames and err.stacks[1].frames[1] then
            local f = err.stacks[1].frames[1]
            loc = f.file .. ":" .. f.line
        end
        return err.kind, loc
    end

    local function fixed_kind_loc(entry)
        return entry.kind, entry.location
    end

    local new_groups = group_entries(details.new, error_kind_loc)
    local fixed_groups = group_entries(details.fixed, fixed_kind_loc)
    local unchanged_groups = group_entries(details.unchanged, error_kind_loc)

    local lines = {}
    local header = string.format("%d new, %d fixed, %d unchanged",
        #details.new, #details.fixed, #details.unchanged)
    table.insert(lines, header)
    table.insert(lines, string.rep("\xe2\x94\x80", vim.fn.strdisplaywidth(header)))

    local function render_groups(groups, prefix)
        for _, g in ipairs(groups) do
            local loc = g.location or "unknown location"
            local suffix = g.count > 1 and string.format(" (x%d)", g.count) or ""
            table.insert(lines, string.format("  %s [%s] %s%s", prefix, g.kind, loc, suffix))
        end
    end

    if #new_groups > 0 then
        table.insert(lines, "")
        table.insert(lines, "New:")
        render_groups(new_groups, "+")
    end

    if #fixed_groups > 0 then
        table.insert(lines, "")
        table.insert(lines, "Fixed:")
        render_groups(fixed_groups, "-")
    end

    if #unchanged_groups > 0 then
        table.insert(lines, "")
        table.insert(lines, "Unchanged:")
        render_groups(unchanged_groups, "=")
    end

    UI.show_floating_window("Run-to-Run Diff", lines)
end

-- Show a floating window explaining the error type.
-- get_error_at_cursor is passed in because navigate.lua may not be extracted yet.
function UI.explain_error(get_error_at_cursor)
    local explanations = require("sanity.explanations")
    local err = get_error_at_cursor()
    if not err then
        vim.notify("No error at cursor.", vim.log.levels.WARN)
        return
    end

    -- Try exact match first, then prefix match.
    local explanation = explanations[err.kind]
    if not explanation then
        for key, expl in pairs(explanations) do
            if F.starts_with(err.kind, key) then
                explanation = expl
                break
            end
        end
    end

    if not explanation then
        vim.notify("No explanation available for error type: " .. err.kind, vim.log.levels.INFO)
        return
    end

    local lines = {
        explanation.title,
        string.rep("\xe2\x94\x80", vim.fn.strdisplaywidth(explanation.title)),
        "",
    }

    -- Word-wrap description at 70 columns.
    local current_line = ""
    for word in explanation.description:gmatch("%S+") do
        if current_line == "" then
            current_line = word
        elseif #current_line + #word + 1 > 70 then
            table.insert(lines, current_line)
            current_line = word
        else
            current_line = current_line .. " " .. word
        end
    end
    if current_line ~= "" then
        table.insert(lines, current_line)
    end

    if explanation.common_fixes and #explanation.common_fixes > 0 then
        table.insert(lines, "")
        table.insert(lines, "Common fixes:")
        for _, fix in ipairs(explanation.common_fixes) do
            table.insert(lines, "  - " .. fix)
        end
    end

    UI.show_floating_window("Error: " .. err.kind, lines)
end

-- Set a breakpoint at the error's location via nvim-dap or GDB clipboard.
-- Navigate functions are passed as a table: { get_error_at_cursor, get_current_position,
-- is_source_window, find_source_win }.
function UI.debug_error(nav)
    local err = nav.get_error_at_cursor()
    if not err then
        vim.notify("No error at cursor.", vim.log.levels.WARN)
        return
    end
    -- Use the cursor's actual position, not the first stack frame.
    local file, line = nav.get_current_position()
    if not file or not line then
        vim.notify("No position to debug.", vim.log.levels.WARN)
        return
    end
    local ok, dap = pcall(require, "dap")
    if ok then
        local target_win = vim.api.nvim_get_current_win()
        if not nav.is_source_window(target_win) then
            target_win = nav.find_source_win()
            if not target_win then
                vim.notify("No source window available.", vim.log.levels.WARN)
                return
            end
        end
        vim.api.nvim_set_current_win(target_win)
        vim.cmd("edit " .. vim.fn.fnameescape(file))
        vim.api.nvim_win_set_cursor(target_win, { line, 0 })
        dap.toggle_breakpoint()
        vim.notify("Breakpoint set at " .. file .. ":" .. line)
    else
        -- Quote the file path so GDB handles spaces and special characters.
        local gdb_file = file:gsub('"', '\\"')
        local gdb_cmd = string.format('break "%s":%s', gdb_file, line)
        vim.fn.setreg("+", gdb_cmd)
        vim.notify("GDB command copied to clipboard: " .. gdb_cmd)
    end
end

return UI

-- Suppression generation, saving, and file parsing.
local S = require("sanity.state")
local F = require("sanity.format")

local SUP = {}

-- Generate a suppression entry for an error.
-- Returns (text, tool) on success or (nil, reason) on failure.
function SUP.generate_suppression(err)
    if not err.stacks or #err.stacks == 0 or not err.stacks[1].frames or #err.stacks[1].frames == 0 then
        return nil, "No stack frames available for suppression."
    end

    if err.source == "valgrind" then
        -- Map kind to suppression tool:type.
        local supp_type
        local extra_line
        local kind = err.kind
        if kind == "Race" then
            supp_type = "Helgrind:Race"
        elseif kind == "UnlockUnlocked" or kind == "LockOrder" then
            supp_type = "Helgrind:Misc"
        elseif kind == "InvalidRead" or kind == "InvalidWrite" then
            supp_type = "Memcheck:Addr"
        elseif kind == "InvalidFree" then
            supp_type = "Memcheck:Free"
        elseif kind == "UninitCondition" then
            supp_type = "Memcheck:Cond"
        elseif kind == "UninitValue" then
            supp_type = "Memcheck:Value"
        elseif kind == "Overlap" then
            supp_type = "Memcheck:Overlap"
        elseif F.starts_with(kind, "Leak_") then
            supp_type = "Memcheck:Leak"
            local leak_map = {
                Leak_DefinitelyLost = "definite",
                Leak_PossiblyLost = "possible",
                Leak_IndirectlyLost = "indirect",
                Leak_StillReachable = "reachable",
            }
            local leak_kind = leak_map[kind]
            if leak_kind then
                extra_line = "   match-leak-kinds: " .. leak_kind
            end
        end

        if not supp_type then
            return nil, "Suppression not available for " .. kind .. " errors."
        end

        local lines = { "{", "   <sanity_generated>", "   " .. supp_type }
        if extra_line then
            table.insert(lines, extra_line)
        end
        local has_func = false
        for _, frame in ipairs(err.stacks[1].frames) do
            if frame.func then
                table.insert(lines, "   fun:" .. frame.func)
                has_func = true
            end
        end
        if not has_func then
            return nil, "No function name available for suppression."
        end
        table.insert(lines, "}")
        return table.concat(lines, "\n"), "valgrind"
    end

    if err.source == "sanitizer" then
        -- Find deepest in-project frame with a function name.
        local func
        for _, frame in ipairs(err.stacks[1].frames) do
            if frame.func then
                func = frame.func
                break
            end
        end
        if not func then
            return nil, "No function name available for suppression."
        end

        local kind = err.kind
        if err.meta and err.meta.leak_type then
            return "leak:" .. func, "lsan"
        elseif kind == "data-race" then
            return "race:" .. func, "tsan"
        elseif kind:match("^signal%-unsafe") then
            return "signal:" .. func, "tsan"
        elseif kind == "lock-order-inversion" then
            return "deadlock:" .. func, "tsan"
        else
            -- Only mention ignorelist files for known ASan memory-error kinds.
            local message = "Suppression not available for " .. kind .. " errors."
            if kind:match("use%-after")
                or kind:match("out%-of%-bounds")
                or kind:match("overflow")
                or kind:match("^heap%-")
                or kind:match("^stack%-") then
                message = message .. " ASAN uses ignorelist files (-fsanitize-ignorelist=) instead of runtime suppressions."
            end
            return nil, message
        end
    end

    return nil, "Unknown error source: " .. tostring(err.source) .. "."
end

-- Write queued suppressions to file(s).
function SUP.save_suppressions(args)
    if #S.suppressions == 0 then
        vim.notify("No suppressions to save.", vim.log.levels.INFO)
        return
    end

    local filename = args and args.args and args.args ~= "" and args.args or nil

    if filename then
        -- Write all suppressions to a single file.
        local fh, open_err = io.open(filename, "a")
        if not fh then
            vim.notify("Failed to open " .. filename .. ": " .. (open_err or "unknown error"), vim.log.levels.ERROR)
            return
        end
        local ok, write_err
        for _, s in ipairs(S.suppressions) do
            ok, write_err = fh:write(s.text .. "\n")
            if not ok then break end
        end
        fh:close()
        if not ok then
            vim.notify("Write failed for " .. filename .. ": " .. (write_err or "unknown error"), vim.log.levels.ERROR)
            return
        end
        vim.notify("Wrote " .. #S.suppressions .. " suppression(s) to " .. filename .. ".")
        S.suppressions = {}
    else
        -- Partition by tool and write to default files.
        local by_tool = {}
        for _, s in ipairs(S.suppressions) do
            if not by_tool[s.tool] then
                by_tool[s.tool] = {}
            end
            table.insert(by_tool[s.tool], s.text)
        end
        local saved_tools = {}
        for tool, entries in pairs(by_tool) do
            local path = S.config.suppression_files[tool]
            if not path then
                vim.notify("No default file configured for tool: " .. tool, vim.log.levels.WARN)
                goto save_continue
            end
            local fh, open_err = io.open(path, "a")
            if not fh then
                vim.notify("Failed to open " .. path .. ": " .. (open_err or "unknown error"), vim.log.levels.ERROR)
                goto save_continue
            end
            local ok, write_err
            for _, text in ipairs(entries) do
                ok, write_err = fh:write(text .. "\n")
                if not ok then break end
            end
            fh:close()
            if not ok then
                vim.notify("Write failed for " .. path .. ": " .. (write_err or "unknown error"), vim.log.levels.ERROR)
                goto save_continue
            end
            vim.notify("Wrote " .. #entries .. " suppression(s) to " .. path .. ".")
            saved_tools[tool] = true
            ::save_continue::
        end
        -- Only remove suppressions that were successfully written.
        local remaining = {}
        for _, s in ipairs(S.suppressions) do
            if not saved_tools[s.tool] then
                table.insert(remaining, s)
            end
        end
        S.suppressions = remaining
    end
end

-- Parse suppression names from a valgrind .supp file.
-- Returns an array of { name = string, line = number, file = string }.
function SUP.parse_suppression_names(filepath)
    local fh = io.open(filepath, "r")
    if not fh then return nil end
    local result = {}
    local in_block = false
    local line_num = 0
    for line in fh:lines() do
        line_num = line_num + 1
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed == "{" then
            in_block = true
        elseif in_block then
            -- Skip blank lines and comments; first real line is the name.
            if trimmed ~= "" and not trimmed:match("^#") then
                table.insert(result, { name = trimmed, line = line_num, file = filepath })
                in_block = false
            end
        end
    end
    fh:close()
    return result
end

-- Parse suppression entries from a sanitizer .supp file (TSan/LSan format).
-- Each non-empty, non-comment line is a suppression entry of the form type:function.
-- Returns an array of { name = string, line = number, file = string }.
function SUP.parse_sanitizer_suppression_names(filepath)
    local fh = io.open(filepath, "r")
    if not fh then return nil end
    local result = {}
    local line_num = 0
    for line in fh:lines() do
        line_num = line_num + 1
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and not trimmed:match("^#") then
            table.insert(result, { name = trimmed, line = line_num, file = filepath })
        end
    end
    fh:close()
    return result
end

-- Report which suppressions were used/unused in the last run.
-- Requires show_floating_window as a parameter since ui.lua may not be extracted yet.
function SUP.audit_suppressions(show_floating_window)
    -- Collect valgrind suppression files to audit.
    local vg_files = {}
    for _, path in ipairs(S.config.valgrind_suppressions) do
        table.insert(vg_files, path)
    end
    local default_vg = S.config.suppression_files.valgrind
    if default_vg and vim.fn.filereadable(default_vg) == 1 then
        local already = false
        for _, f in ipairs(vg_files) do
            if f == default_vg then already = true; break end
        end
        if not already then
            table.insert(vg_files, default_vg)
        end
    end

    -- Collect sanitizer suppression files (TSan, LSan).
    local san_files = {}
    for _, key in ipairs({ "lsan", "tsan" }) do
        local path = S.config.suppression_files[key]
        if path and vim.fn.filereadable(path) == 1 then
            table.insert(san_files, path)
        end
    end

    local has_vg_data = not vim.tbl_isempty(S.suppression_counts)
    if #vg_files == 0 and #san_files == 0 then
        vim.notify("No suppression files configured or found.", vim.log.levels.INFO)
        return
    end

    local lines = {}
    local total_used = 0
    local total_unused = 0

    -- Audit valgrind suppression files.
    if #vg_files > 0 then
        if not has_vg_data then
            table.insert(lines, "Valgrind: no suppression count data available.")
            table.insert(lines, "  Run :SanityRunValgrind or load a valgrind XML log first.")
            table.insert(lines, "")
        else
            for _, filepath in ipairs(vg_files) do
                local entries = SUP.parse_suppression_names(filepath)
                if not entries then
                    table.insert(lines, "Could not read: " .. filepath)
                    goto audit_vg_continue
                end
                table.insert(lines, filepath .. ":")
                for _, entry in ipairs(entries) do
                    local count = S.suppression_counts[entry.name]
                    if count and count > 0 then
                        table.insert(lines, string.format("  %s  (used %d time%s)",
                            entry.name, count, count == 1 and "" or "s"))
                        total_used = total_used + 1
                    else
                        table.insert(lines, string.format("  %s  (unused)", entry.name))
                        total_unused = total_unused + 1
                    end
                end
                ::audit_vg_continue::
            end
        end
    end

    -- Audit sanitizer suppression files (TSan/LSan).
    for _, filepath in ipairs(san_files) do
        local entries = SUP.parse_sanitizer_suppression_names(filepath)
        if not entries then
            table.insert(lines, "Could not read: " .. filepath)
            goto audit_san_continue
        end
        if #lines > 0 and lines[#lines] ~= "" then
            table.insert(lines, "")
        end
        table.insert(lines, filepath .. ":")
        for _, entry in ipairs(entries) do
            table.insert(lines, string.format("  %s  (usage data not available)", entry.name))
        end
        ::audit_san_continue::
    end

    if has_vg_data then
        table.insert(lines, "")
        table.insert(lines, string.format("Valgrind: %d used, %d unused", total_used, total_unused))
    end

    show_floating_window("Suppression Audit", lines)
end

return SUP

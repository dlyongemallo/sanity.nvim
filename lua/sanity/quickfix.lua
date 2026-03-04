-- Quickfix population, diagnostics, and filtering.
local S = require("sanity.state")
local F = require("sanity.format")

local Q = {}

-- Create an error object, register it, and update S.location_index.
function Q.new_error(kind, message, source, stacks, meta)
    S.error_id_counter = S.error_id_counter + 1
    local err = {
        id = S.error_id_counter,
        kind = kind,
        message = message,
        source = source,
        stacks = stacks,
        meta = meta or {},
    }
    table.insert(S.errors, err)
    S.errors_by_id[err.id] = err
    for _, stack in ipairs(stacks) do
        for _, frame in ipairs(stack.frames) do
            -- Normalise the stored frame path so all consumers and indexes agree.
            frame.file = F.normalize_path(frame.file)
            local key = frame.file .. ":" .. frame.line
            if not S.location_index[key] then
                S.location_index[key] = {}
            end
            table.insert(S.location_index[key], err.id)
        end
    end
    return err
end

-- Collect unique error kinds from all loaded errors.
function Q.get_available_kinds()
    local seen = {}
    local kinds = {}
    for _, err in ipairs(S.errors) do
        if not seen[err.kind] then
            seen[err.kind] = true
            table.insert(kinds, err.kind)
        end
    end
    table.sort(kinds)
    return kinds
end

-- Preset filter groups that expand to sets of kind prefixes/names.
Q.filter_presets = {
    errors = {
        "InvalidRead", "InvalidWrite", "InvalidFree",
        "UninitCondition", "UninitValue", "Overlap",
        "heap-use-after-free", "heap-buffer-overflow", "stack-buffer-overflow",
        "use-of-uninitialized-value",
        "signed-integer-overflow", "division-by-zero", "shift-exponent",
        "null-pointer-passed-as-argument",
    },
    leaks = {
        "Leak_",
    },
    races = {
        "Race", "data-race",
    },
    threading = {
        "Race", "data-race", "UnlockUnlocked", "LockOrder",
        "lock-order-inversion", "signal-unsafe-call",
    },
}

-- Expand a list of filter arguments, resolving any preset names.
function Q.expand_filter_args(args_list)
    local result = {}
    local seen = {}
    for _, arg in ipairs(args_list) do
        local preset = Q.filter_presets[arg]
        local items = preset or { arg }
        for _, kind in ipairs(items) do
            if not seen[kind] then
                seen[kind] = true
                table.insert(result, kind)
            end
        end
    end
    return result
end

-- Check whether an error's kind matches any entry in the active filter.
function Q.matches_filter(kind)
    if not S.current_filter then return true end
    for _, fk in ipairs(S.current_filter) do
        if kind == fk or F.starts_with(kind, fk) then
            return true
        end
    end
    return false
end

-- Group error frames by (file, line, kind), collecting link sets.
-- Each group tracks its errors, file/line, kind, and a link set showing where
-- each frame points in the stack (END for the deepest, ->basename:line otherwise).
-- Returns (groups, group_order) where group_order is sorted by file:line:kind.
function Q.group_error_frames()
    local group_order = {}
    local groups = {}

    for _, err in ipairs(S.errors) do
        if not Q.matches_filter(err.kind) then goto filter_skip end
        for _, stack in ipairs(err.stacks) do
            for fi, frame in ipairs(stack.frames) do
                local padded = string.format("%06d", frame.line)
                local group_key = frame.file .. ":" .. padded .. ":" .. err.kind

                if not groups[group_key] then
                    groups[group_key] = {
                        errors = {},
                        error_id_set = {},
                        file = frame.file,
                        line = frame.line,
                        kind = err.kind,
                        link_set = {},
                    }
                    table.insert(group_order, group_key)
                end

                local group = groups[group_key]

                if not group.error_id_set[err.id] then
                    group.error_id_set[err.id] = true
                    table.insert(group.errors, err)
                end

                -- Deepest frame (first in array) links to END.
                -- Each subsequent frame links to the previous frame (one level deeper).
                if fi == 1 then
                    group.link_set["END"] = true
                else
                    local prev = stack.frames[fi - 1]
                    local basename = prev.file:match("[^/]+$") or prev.file
                    local link_key = basename .. ":" .. string.format("%06d", prev.line)
                    group.link_set["->" .. link_key] = true
                end
            end
        end
        ::filter_skip::
    end

    table.sort(group_order)
    return groups, group_order
end

-- Map error kind to diagnostic severity.
function Q.get_severity(kind)
    if kind:match("^Leak_StillReachable") then
        return vim.diagnostic.severity.INFO
    elseif kind:match("^Leak_Possibly") or kind:match("^Leak_Indirect") then
        return vim.diagnostic.severity.WARN
    else
        return vim.diagnostic.severity.ERROR
    end
end

-- Map error kind to quickfix type character (E/W/I).
function Q.get_qf_type(kind)
    local sev = Q.get_severity(kind)
    if sev == vim.diagnostic.severity.WARN then
        return "W"
    elseif sev == vim.diagnostic.severity.INFO then
        return "I"
    end
    return "E"
end

-- Populate the quickfix list from the errors array.
function Q.populate_quickfix_from_errors()
    local groups, group_order = Q.group_error_frames()

    local qf_entries = {}
    S.qf_error_ids = {}
    S.qf_file_lines = {}

    for _, group_key in ipairs(group_order) do
        local group = groups[group_key]
        local errs = group.errors
        local kind = group.kind
        local source = errs[1].source
        local links = F.format_link_set(group.link_set)

        local msg
        if source == "valgrind" then
            msg = F.format_valgrind_group(kind, errs, links)
        elseif source == "sanitizer" then
            msg = F.format_sanitizer_group(kind, errs, links)
        else
            msg = kind
        end

        table.insert(qf_entries, {
            filename = group.file,
            lnum = group.line,
            text = msg,
            type = Q.get_qf_type(kind),
        })

        local ids = {}
        for _, err in ipairs(errs) do
            table.insert(ids, err.id)
        end
        table.insert(S.qf_error_ids, ids)
        table.insert(S.qf_file_lines, { file = group.file, line = group.line })
    end

    vim.fn.setqflist(qf_entries, "r")

    -- Deduplicate quickfix entries (for multi-file loads).
    local qflist = vim.fn.getqflist()
    local seen = {}
    local deduped = {}
    local deduped_ids = {}
    local deduped_fl = {}
    for i, entry in ipairs(qflist) do
        local key = entry.bufnr .. ":" .. entry.lnum .. ":" .. (entry.text or "")
        if not seen[key] then
            seen[key] = true
            table.insert(deduped, entry)
            if S.qf_error_ids[i] then
                table.insert(deduped_ids, S.qf_error_ids[i])
            end
            if S.qf_file_lines[i] then
                table.insert(deduped_fl, S.qf_file_lines[i])
            end
        end
    end
    if #deduped < #qflist then
        vim.fn.setqflist(deduped, "r")
        S.qf_error_ids = deduped_ids
        S.qf_file_lines = deduped_fl
    end

    -- Set the quickfix title so the active filter is visible in the statusline.
    local title = "sanity"
    if S.current_filter then
        title = title .. " (filter: " .. table.concat(S.current_filter, ", ") .. ")"
    end
    vim.fn.setqflist({}, "a", { title = title })

    -- Notify plugins (e.g. trouble.nvim) that the quickfix list changed.
    vim.api.nvim_exec_autocmds("QuickFixCmdPost", { pattern = "*" })
end

-- Set diagnostics on buffers for all error frames.
-- When only_bufnr is given, only refresh diagnostics for that buffer.
function Q.set_diagnostics(only_bufnr)
    if not S.config.diagnostics_enabled then return end

    if only_bufnr then
        vim.diagnostic.reset(S.ns, only_bufnr)
    else
        vim.diagnostic.reset(S.ns)
    end

    local groups, group_order = Q.group_error_frames()

    local buf_diags = {}
    for _, group_key in ipairs(group_order) do
        local group = groups[group_key]
        local bufnr = vim.fn.bufnr(group.file, false)
        if bufnr == -1 then goto diag_continue end
        if only_bufnr and bufnr ~= only_bufnr then goto diag_continue end
        if not buf_diags[bufnr] then
            buf_diags[bufnr] = {}
        end
        -- Use first non-blank column so lsp_lines.nvim arrows align with code.
        local lnum = group.line - 1  -- Diagnostics use 0-based lines.
        local col = 0
        if vim.api.nvim_buf_is_loaded(bufnr) then
            local lines = vim.api.nvim_buf_get_lines(bufnr, lnum, lnum + 1, false)
            if lines[1] then
                col = #(lines[1]:match("^(%s*)") or "")
            end
        end
        local links = F.format_link_set(group.link_set)
        local msg = string.format("[%s] %s (%s)", group.kind, group.errors[1].message, links)
        table.insert(buf_diags[bufnr], {
            lnum = lnum,
            col = col,
            message = msg,
            severity = Q.get_severity(group.kind),
            source = "sanity",
        })
        ::diag_continue::
    end

    for bufnr, diags in pairs(buf_diags) do
        vim.diagnostic.set(S.ns, bufnr, diags)
    end
end

return Q

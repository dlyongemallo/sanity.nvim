-- Cursor-based position resolution and navigation.
local S = require("sanity.state")
local F = require("sanity.format")

local N = {}

function N.get_error_by_id(id)
    return S.errors_by_id[id]
end

-- Return (file, line, error_ids) for a quickfix entry index.
function N.get_qf_entry_position(idx)
    if not idx or idx < 1 then return nil, nil, nil end
    local ids = S.qf_error_ids[idx]
    local fl = S.qf_file_lines[idx]
    if fl then return fl.file, fl.line, ids end
    local qflist = vim.fn.getqflist()
    local entry = qflist[idx]
    if not entry or entry.bufnr == 0 then return nil, nil, nil end
    return vim.api.nvim_buf_get_name(entry.bufnr), entry.lnum, ids
end

-- True only for the built-in quickfix *window* (not loclist, not wrappers).
function N.is_qflist_window(win)
    win = win or vim.api.nvim_get_current_win()
    local info = vim.fn.getwininfo(win)
    if not info or not info[1] then return false end
    return info[1].quickfix == 1 and info[1].loclist ~= 1
end

-- Trouble qflist windows are not native quickfix windows.
function N.is_trouble_like_window(win)
    win = win or vim.api.nvim_get_current_win()
    local buf = vim.api.nvim_win_get_buf(win)
    if vim.bo[buf].filetype == "trouble" then return true end
    if vim.bo[buf].buftype == "quickfix" and not N.is_qflist_window(win) then
        return true
    end
    return false
end

-- A source window is a normal non-floating window showing a source buffer.
function N.is_source_window(win)
    if not win or not vim.api.nvim_win_is_valid(win) then return false end
    if vim.api.nvim_win_get_config(win).relative ~= "" then return false end
    local buf = vim.api.nvim_win_get_buf(win)
    if not buf or not vim.api.nvim_buf_is_valid(buf) then return false end
    if vim.bo[buf].buftype ~= "" then return false end
    if vim.fn.buflisted(buf) ~= 1 then return false end
    local ft = vim.bo[buf].filetype
    if ft == "qf" or ft == "trouble" then return false end
    if S.stack_bufnr and buf == S.stack_bufnr then return false end
    return true
end

-- Resolve a line in the stack buffer to the nearest frame entry.
function N.get_stack_frame_position(line)
    if not S.stack_frame_map then return nil, nil, nil end
    local info = S.stack_frame_map[line]
    if info and info.file then return info.file, info.line, info.error_ids end
    local max_line = vim.api.nvim_buf_line_count(S.stack_bufnr)
    for offset = 1, max_line do
        local down = line + offset
        if down <= max_line then
            local d = S.stack_frame_map[down]
            if d and d.file then return d.file, d.line, d.error_ids end
        end
        local up = line - offset
        if up >= 1 then
            local u = S.stack_frame_map[up]
            if u and u.file then return u.file, u.line, u.error_ids end
        end
    end
    return nil, nil, nil
end

-- Get the current file and line from cursor position or quickfix entry.
-- Returns (file, line, error_ids). The third value is non-nil only when
-- called from a quickfix-like UI, so callers can bypass location_index
-- and use the pre-resolved error IDs directly.
function N.get_current_position()
    local win = vim.api.nvim_get_current_win()
    local buf = vim.api.nvim_win_get_buf(win)

    if S.stack_bufnr and buf == S.stack_bufnr then
        local line = vim.api.nvim_win_get_cursor(win)[1]
        local file, resolved_line, ids = N.get_stack_frame_position(line)
        if file and resolved_line then return file, resolved_line, ids end
        return nil, nil, nil
    end

    if N.is_qflist_window(win) then
        -- In the real quickfix window, cursor line maps 1:1 to entry index.
        return N.get_qf_entry_position(vim.fn.line("."))
    end

    if N.is_trouble_like_window(win) then
        -- trouble.nvim keeps qflist idx in sync with the selected item.
        local info = vim.fn.getqflist({ idx = 0 })
        local file, line, ids = N.get_qf_entry_position(info and info.idx)
        if file and line then return file, line, ids end
        return nil, nil, nil
    end

    -- Fallback for quickfix-like custom buffers that don't expose wininfo.
    if vim.bo[buf].buftype == "quickfix" then
        return N.get_qf_entry_position(vim.fn.line("."))
    end

    return F.normalize_path(vim.api.nvim_buf_get_name(buf)), vim.api.nvim_win_get_cursor(win)[1], nil
end

-- Return the first error at the cursor position, or nil.
function N.get_error_at_cursor()
    local file, line, error_ids = N.get_current_position()
    if not file or not line then return nil end
    local ids = error_ids
    if not ids or #ids == 0 then
        ids = S.location_index[file .. ":" .. line]
    end
    if not ids or #ids == 0 then return nil end
    return S.errors_by_id[ids[1]]
end

-- Extract addresses from an error's meta.addr field.
-- Valgrind stores addr as a scalar string; sanitizers store it as a set.
function N.extract_addrs(err)
    local addr = err.meta and err.meta.addr
    if not addr then return {} end
    if type(addr) == "table" then
        local result = {}
        for k, _ in pairs(addr) do
            table.insert(result, k)
        end
        return result
    end
    return { addr }
end

-- Find adjacent frames in the given direction from file:line.
-- direction = -1 for deeper (toward inner frames), +1 for shallower (toward main).
-- Returns array of { file, line, label }.
function N.find_adjacent_frames(file, line, direction)
    local key = file .. ":" .. line
    local ids = S.location_index[key]
    if not ids then return {} end

    local targets = {}
    local seen = {}
    local seen_ids = {}
    for _, id in ipairs(ids) do
        if not seen_ids[id] then
            seen_ids[id] = true
            local err = N.get_error_by_id(id)
            if err then
                for _, stack in ipairs(err.stacks) do
                    for fi, frame in ipairs(stack.frames) do
                        if frame.file == file and frame.line == line then
                            local adj_idx = fi + direction
                            if adj_idx >= 1 and adj_idx <= #stack.frames then
                                local adj = stack.frames[adj_idx]
                                local tkey = adj.file .. ":" .. adj.line
                                if not seen[tkey] then
                                    seen[tkey] = true
                                    local basename = adj.file:match("[^/]+$") or adj.file
                                    table.insert(targets, {
                                        file = adj.file,
                                        line = adj.line,
                                        label = string.format("%s:%d [%s]", basename, adj.line, err.kind),
                                    })
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    return targets
end

-- Find a normal (non-special) window suitable for editing source files.
-- Returns the window handle, or nil if none exists.
function N.find_source_win()
    for _, win in ipairs(vim.api.nvim_tabpage_list_wins(0)) do
        if N.is_source_window(win) then return win end
    end
    return nil
end

-- Jump to a target frame. When in a non-source window (quickfix,
-- trouble.nvim, etc.), open the file in a source window and return
-- focus. In the real quickfix window, use :cc to keep ]q/[q in sync.
-- refresh_stack_fn is an optional callback for updating the stack view.
function N.jump_to_frame(target, refresh_stack_fn)
    local cur_win = vim.api.nvim_get_current_win()
    local cur_buf = vim.api.nvim_win_get_buf(cur_win)
    local from_stack_window = S.stack_bufnr and cur_buf == S.stack_bufnr

    if not N.is_source_window(cur_win) then
        local src_win = N.find_source_win()
        if not src_win then return end

        -- In the real quickfix window, try :cc to keep qf idx in sync.
        if N.is_qflist_window(cur_win) then
            local qflist = vim.fn.getqflist()
            for i, entry in ipairs(qflist) do
                if entry.bufnr ~= 0 and entry.lnum == target.line
                    and vim.api.nvim_buf_get_name(entry.bufnr) == target.file then
                    vim.cmd("silent " .. i .. "cc")
                    vim.api.nvim_set_current_win(cur_win)
                    return
                end
            end
        end

        -- In trouble/special windows, edit in a source window so the list
        -- buffer is not replaced.
        vim.api.nvim_set_current_win(src_win)
        vim.cmd("edit " .. vim.fn.fnameescape(target.file))
        vim.api.nvim_win_set_cursor(src_win, { target.line, 0 })
        if from_stack_window and refresh_stack_fn then
            refresh_stack_fn(target.file, target.line, target.error_ids)
        end
        vim.api.nvim_set_current_win(cur_win)
        return
    end

    vim.cmd("edit " .. vim.fn.fnameescape(target.file))
    vim.api.nvim_win_set_cursor(0, { target.line, 0 })
end

-- Navigate to adjacent stack frames in the given direction.
-- direction = -1 for deeper, +1 for shallower.
function N.navigate_stack(direction, refresh_stack_fn)
    -- Keep the quickfix internal index in sync with the cursor so that
    -- ]q/[q continue from the right position after ]s/[s navigation.
    if N.is_qflist_window(vim.api.nvim_get_current_win()) then
        vim.fn.setqflist({}, "a", { idx = vim.fn.line(".") })
    end

    local file, line = N.get_current_position()
    if not file or not line then
        vim.notify("No position to navigate from.", vim.log.levels.WARN)
        return
    end

    local targets = N.find_adjacent_frames(file, line, direction)
    if #targets == 0 then
        local msg = direction < 0 and "At end of stack." or "At top of stack."
        vim.notify(msg, vim.log.levels.INFO)
        return
    end

    if #targets == 1 then
        N.jump_to_frame(targets[1], refresh_stack_fn)
        vim.notify(targets[1].label, vim.log.levels.INFO)
        return
    end

    vim.ui.select(targets, {
        prompt = "Select stack frame:",
        format_item = function(item) return item.label end,
    }, function(choice)
        if choice then
            N.jump_to_frame(choice, refresh_stack_fn)
            vim.notify(choice.label, vim.log.levels.INFO)
        end
    end)
end

-- Find related targets sharing the same address as err.
-- Includes other stacks within the same error (e.g. both sides of a
-- data race) and other errors referencing the same memory address.
-- file/line is the current position used to exclude the caller's location.
-- all_errors is the full error list to search for cross-error matches.
function N.find_related_targets(err, file, line, all_errors)
    local targets = {}
    local seen_locs = {}

    local function add_target(f, l, label, ids)
        local key = f .. ":" .. l
        if seen_locs[key] then return end
        seen_locs[key] = true
        table.insert(targets, { file = f, line = l, label = label, error_ids = ids })
    end

    -- Other stacks within the same error at different locations.
    if file and line then
        for _, stack in ipairs(err.stacks) do
            local frame = stack.frames[1]
            if frame and (frame.file ~= file or frame.line ~= line) then
                add_target(frame.file, frame.line, stack.label or err.message, { err.id })
            end
        end
    end

    -- Other errors sharing any address.
    local addrs = N.extract_addrs(err)
    if #addrs > 0 then
        local seen_ids = { [err.id] = true }
        for _, other in ipairs(all_errors) do
            if not seen_ids[other.id] then
                local other_addrs = N.extract_addrs(other)
                for _, a in ipairs(addrs) do
                    for _, oa in ipairs(other_addrs) do
                        if a == oa then
                            seen_ids[other.id] = true
                            local frame = other.stacks[1] and other.stacks[1].frames[1]
                            if frame then
                                add_target(frame.file, frame.line,
                                    string.format("[%s] %s", other.kind, other.message), { other.id })
                            end
                            goto next_error
                        end
                    end
                end
            end
            ::next_error::
        end
    end

    return targets
end

-- Jump to a related location sharing the same address.
function N.show_related(refresh_stack_fn)
    local err = N.get_error_at_cursor()
    if not err then
        vim.notify("No error at cursor.", vim.log.levels.WARN)
        return
    end

    local file, line = N.get_current_position()
    local targets = N.find_related_targets(err, file, line, S.errors)

    if #targets == 0 then
        vim.notify("No related errors.", vim.log.levels.INFO)
        return
    end

    if #targets == 1 then
        N.jump_to_frame(targets[1], refresh_stack_fn)
        vim.notify(targets[1].label, vim.log.levels.INFO)
        return
    end

    vim.ui.select(targets, {
        prompt = "Select related error:",
        format_item = function(item) return item.label end,
    }, function(choice)
        if choice then
            N.jump_to_frame(choice, refresh_stack_fn)
            vim.notify(choice.label, vim.log.levels.INFO)
        end
    end)
end

return N

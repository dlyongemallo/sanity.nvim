local M = {}
local pickers = require("sanity.pickers")

local config = {}

-- Structured error storage.
local errors = {}
local error_id_counter = 0
local location_index = {}  -- "file:line" -> { error_id, ... }
local qf_error_ids = {}    -- qf index -> { error_id, ... }

local function reset_state()
    errors = {}
    error_id_counter = 0
    location_index = {}
    qf_error_ids = {}
end

-- Create an error object, register it, and update location_index.
local function new_error(kind, message, source, stacks, meta)
    error_id_counter = error_id_counter + 1
    local err = {
        id = error_id_counter,
        kind = kind,
        message = message,
        source = source,
        stacks = stacks,
        meta = meta or {},
    }
    table.insert(errors, err)
    for _, stack in ipairs(stacks) do
        for _, frame in ipairs(stack.frames) do
            local key = frame.file .. ":" .. frame.line
            if not location_index[key] then
                location_index[key] = {}
            end
            table.insert(location_index[key], err.id)
        end
    end
    return err
end

function M.setup(opts)
    opts = opts or {}
    config.picker = opts.picker
    config.keymaps = opts.keymaps or {}

    vim.api.nvim_create_user_command("Valgrind", M.run_valgrind, { nargs = 1 })
    vim.api.nvim_create_user_command("SanityLoadLog", M.sanity_load_log, { nargs = "*", complete = "file" })
    vim.api.nvim_create_user_command("SanityStacks", M.sanity_stacks, { nargs = 0 })

    vim.keymap.set("n", config.keymaps.stack_next or "]s", M.stack_next,
        { desc = "Next stack frame" })
    vim.keymap.set("n", config.keymaps.stack_prev or "[s", M.stack_prev,
        { desc = "Previous stack frame" })
end

local function starts_with(str, start)
    return str:sub(1, #start) == start
end

-- Iterate over a table in numeric key order.
-- xml2lua creates tables with numeric keys, but pairs() doesn't preserve order.
-- Handles both numeric keys (1, 2, 3) and string keys ("1", "2", "3").
local function ipairs_safe(t)
    if type(t) ~= "table" then
        return function() end
    end
    local numeric_keys = {}
    local other_keys = {}
    for k in pairs(t) do
        local num = tonumber(k)
        if num then
            table.insert(numeric_keys, { key = k, num = num })
        else
            table.insert(other_keys, k)
        end
    end
    -- Sort numeric keys by their numeric value.
    table.sort(numeric_keys, function(a, b) return a.num < b.num end)
    -- Build final key list: numeric keys first (in order), then other keys.
    local keys = {}
    for _, entry in ipairs(numeric_keys) do
        table.insert(keys, entry.key)
    end
    for _, k in ipairs(other_keys) do
        table.insert(keys, k)
    end
    local i = 0
    return function()
        i = i + 1
        local k = keys[i]
        if k then
            return k, t[k]
        end
    end
end

local summarize_rw = function(rw)
    local has_read = false
    local has_write = false
    for k, _ in pairs(rw) do
        if k == "read" then
            has_read = true
        elseif k == "write" then
            has_write = true
        end
        if has_read and has_write then
            return "read/write"
        end
    end
    if has_read then
        return "read"
    elseif has_write then
        return "write"
    else
        return "unknown operation"
    end
end

local summarize_table_keys = function(t, show_only_first_entry, sort_by_numeric_value)
    show_only_first_entry = show_only_first_entry or false
    sort_by_numeric_value = sort_by_numeric_value or false

    local sorted_t = {}
    local n = 0
    for k, _ in pairs(t) do
        if sort_by_numeric_value then
            k = tonumber(k)
        end
        table.insert(sorted_t, k)
        n = n + 1
    end
    table.sort(sorted_t)
    if n == 1 then
        return sorted_t[1]
    elseif show_only_first_entry then
        return sorted_t[1] .. "/..."
    else
        return table.concat(sorted_t, '/')
    end
end

-- Detect the format of a log file by reading the first few lines.
local function detect_log_format(filepath)
    local f = io.open(filepath, "r")
    if not f then
        vim.notify("Failed to open file: " .. filepath, vim.log.levels.ERROR)
        return nil
    end
    for _ = 1, 10 do
        local line = f:read("*l")
        if not line then break end
        if line:find("<%?xml") or line:find("<valgrindoutput") then
            f:close()
            return "valgrind_xml"
        end
        if line:match("WARNING: .*Sanitizer:") or line:match("ERROR: .*Sanitizer:") then
            f:close()
            return "sanitizer_log"
        end
    end
    f:close()
    vim.notify("Unrecognised log format: " .. filepath, vim.log.levels.ERROR)
    return nil
end

-- Format a link set into a summary string.
-- Link sets contain entries like "->basename:000042" and "END".
local function format_link_set(link_set)
    local sorted_links = {}
    for k, _ in pairs(link_set) do
        table.insert(sorted_links, k)
    end
    table.sort(sorted_links)
    local summary = ""
    local prev_filename = ""
    local has_end = false
    for _, full_link in ipairs(sorted_links) do
        if full_link == "END" then
            has_end = true
        else
            local filename, line_number = string.match(full_link, "^%->(.*):(%d+)$")
            line_number = line_number:match("^0*(%d+)$")
            if filename == prev_filename then
                summary = summary .. "," .. line_number
            else
                if prev_filename ~= "" then
                    summary = summary .. "/"
                end
                summary = summary .. filename .. ":" .. line_number
                prev_filename = filename
            end
        end
    end
    if has_end then
        if summary ~= "" then
            summary = summary .. "/"
        end
        summary = summary .. "END"
    end
    return summary
end

-- Format a quickfix message for a group of valgrind errors with the same kind.
local function format_valgrind_group(kind, errs, links)
    -- Data race errors.
    local rw, size, addr, thr = string.match(errs[1].message,
        "^Possible data race during (.*) of size (%d+) at (0x%x+) by thread (#%d+)")
    if rw then
        local rw_set = {}
        local size_set = {}
        local addr_set = {}
        local thr_set = {}
        for _, err in ipairs(errs) do
            local m = err.meta
            if m.rw then rw_set[m.rw] = true end
            if m.size then size_set[m.size] = true end
            if m.addr then addr_set[m.addr] = true end
            if m.thr then thr_set[m.thr] = true end
        end
        return string.format("[Race] Possible data race during %s of size %s at %s by thread %s (%s)",
            summarize_rw(rw_set),
            summarize_table_keys(size_set, false, true),
            summarize_table_keys(addr_set, true),
            summarize_table_keys(thr_set),
            links)
    end

    -- Leak errors.
    local leak_type = kind:match("^Leak_(.*)")
    if leak_type and errs[1].meta.size then
        local leak_type_set = {}
        local size_set2 = {}
        local blocks_set = {}
        local loss_set = {}
        local total_set = {}
        for _, err in ipairs(errs) do
            local m = err.meta
            if m.leak_type then leak_type_set[m.leak_type] = true end
            if m.size then size_set2[m.size] = true end
            if m.blocks then blocks_set[m.blocks] = true end
            if m.loss_record then loss_set[m.loss_record] = true end
            if m.total_records then total_set[m.total_records] = true end
        end
        return string.format("[Leak_%s] %s bytes in %s blocks in loss record %s of %s (%s)",
            summarize_table_keys(leak_type_set, false),
            summarize_table_keys(size_set2, true, true),
            summarize_table_keys(blocks_set, true, true),
            summarize_table_keys(loss_set, true, true),
            summarize_table_keys(total_set, false, true),
            links)
    end

    -- General errors.
    return string.format("[%s] %s (%s)", kind, errs[1].message, links)
end

-- Merge a set-valued meta field from multiple errors into one set.
local function merge_meta_sets(errs, field)
    local merged = {}
    for _, err in ipairs(errs) do
        if type(err.meta[field]) == "table" then
            for k, _ in pairs(err.meta[field]) do
                merged[k] = true
            end
        end
    end
    return merged
end

-- Format a quickfix message for a group of sanitizer errors with the same kind.
local function format_sanitizer_group(kind, errs, links)
    -- rw_op errors (data race read/write).
    if errs[1].meta.rw_op then
        local rw_op_set = merge_meta_sets(errs, "rw_op")
        local size_set = merge_meta_sets(errs, "size")
        local addr_set = merge_meta_sets(errs, "addr")
        local thr_set = merge_meta_sets(errs, "thr")
        return string.format("%s of size %s at %s by thread %s: (%s)",
            summarize_table_keys(rw_op_set),
            summarize_table_keys(size_set, false, true),
            summarize_table_keys(addr_set, true),
            summarize_table_keys(thr_set),
            links)
    end

    -- Mutex creation.
    if errs[1].meta.mutex then
        local mutex_set = merge_meta_sets(errs, "mutex")
        return string.format("Mutex %s created: (%s)",
            summarize_table_keys(mutex_set),
            links)
    end

    -- Heap allocation.
    if errs[1].meta.heap_block then
        local size_set = merge_meta_sets(errs, "size")
        local addr_set = merge_meta_sets(errs, "addr")
        local thr_set = merge_meta_sets(errs, "thr")
        return string.format("Location is heap block of size %s at %s allocated by %s: (%s)",
            summarize_table_keys(size_set, false, true),
            summarize_table_keys(addr_set, true),
            summarize_table_keys(thr_set),
            links)
    end

    -- Leak errors.
    if errs[1].meta.leak_type then
        local leak_type_set = merge_meta_sets(errs, "leak_type")
        local size_set = merge_meta_sets(errs, "size")
        local num_objs_set = merge_meta_sets(errs, "num_objs")
        return string.format("%s leak of %s byte(s) in %s object(s) allocated from: (%s)",
            summarize_table_keys(leak_type_set),
            summarize_table_keys(size_set, false, true),
            summarize_table_keys(num_objs_set, false, true),
            links)
    end

    -- General errors.
    return string.format("%s (%s)", errs[1].message, links)
end

-- Populate the quickfix list from the errors array.
-- Creates an entry for every frame in every stack, matching the old per-frame behaviour.
-- Groups entries by (file, line, kind), with links pointing from each frame to the
-- previous (deeper) frame in the same stack (END for the deepest frame).
local function populate_quickfix_from_errors()
    local group_order = {}
    local groups = {}

    for _, err in ipairs(errors) do
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

                -- Add error to group if not already present.
                if not group.error_id_set[err.id] then
                    group.error_id_set[err.id] = true
                    table.insert(group.errors, err)
                end

                -- Compute link for this frame position.
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
    end

    table.sort(group_order)

    local qf_entries = {}
    qf_error_ids = {}

    for _, group_key in ipairs(group_order) do
        local group = groups[group_key]
        local errs = group.errors
        local kind = group.kind
        local source = errs[1].source
        local links = format_link_set(group.link_set)

        local msg
        if source == "valgrind" then
            msg = format_valgrind_group(kind, errs, links)
        elseif source == "sanitizer" then
            msg = format_sanitizer_group(kind, errs, links)
        else
            msg = kind
        end

        table.insert(qf_entries, {
            filename = group.file,
            lnum = group.line,
            text = msg,
        })

        local ids = {}
        for _, err in ipairs(errs) do
            table.insert(ids, err.id)
        end
        table.insert(qf_error_ids, ids)
    end

    vim.fn.setqflist(qf_entries, " ")

    -- Deduplicate quickfix entries (for multi-file loads).
    local qflist = vim.fn.getqflist()
    local seen = {}
    local deduped = {}
    local deduped_ids = {}
    for i, entry in ipairs(qflist) do
        local key = entry.bufnr .. ":" .. entry.lnum .. ":" .. (entry.text or "")
        if not seen[key] then
            seen[key] = true
            table.insert(deduped, entry)
            if qf_error_ids[i] then
                table.insert(deduped_ids, qf_error_ids[i])
            end
        end
    end
    if #deduped < #qflist then
        vim.fn.setqflist(deduped, "r")
        qf_error_ids = deduped_ids
    end
end

-- Parse a valgrind XML file into structured error objects.
M.parse_valgrind_xml = function(xml_file)
    local xml2lua = require("xml2lua")
    -- Create a fresh handler each call to avoid xml2lua's repeated-parse bug.
    local handler = require("xmlhandler.tree"):new()

    local parser = xml2lua.parser(handler)
    parser:parse(xml2lua.loadFile(xml_file))

    local output = handler.root.valgrindoutput
    local error_list = output.error
    if error_list and #error_list <= 1 then
        -- xml2lua doesn't wrap single-element lists in an array.
        error_list = { error_list }
    end
    if not error_list then return 0 end

    local cwd = vim.fn.getcwd()
    local num_errors = 0

    for _, e in pairs(error_list) do
        if not e.kind then goto not_error_continue end
        if not e.stack then goto not_error_continue end

        local message = ""
        if e.what then
            message = e.what
        elseif e.xwhat then
            message = e.xwhat.text
        end

        -- Extract metadata from message.
        local meta = {}
        local rw, size, addr, thr = string.match(message,
            "^Possible data race during (.*) of size (%d+) at (0x%x+) by thread (#%d+)")
        if rw then
            meta.rw = rw
            meta.size = size
            meta.addr = addr
            meta.thr = thr
        end

        local lsize, blocks, loss_record, total_records = string.match(message,
            "(.+) bytes in (%d+) blocks .* in loss record (%d+) of (%d+)")
        if lsize then
            meta.leak_type = e.kind:match("^Leak_(.*)") or "unknown"
            meta.size = lsize
            meta.blocks = blocks
            meta.loss_record = loss_record
            meta.total_records = total_records
        end

        -- Build stacks.
        local stacks_list = e.stack
        if stacks_list and #stacks_list <= 1 then
            stacks_list = { stacks_list }
        end

        local err_stacks = {}
        for _, s in ipairs_safe(stacks_list) do
            if not s.frame then goto not_stack_continue end
            local frame_list = s.frame
            if frame_list and #frame_list <= 1 then
                frame_list = { frame_list }
            end

            local frames = {}
            for _, f in ipairs_safe(frame_list) do
                if not f.dir or not f.file then goto not_frame_continue end
                if not starts_with(f.dir, cwd) then goto not_frame_continue end
                table.insert(frames, {
                    file = f.dir .. "/" .. f.file,
                    line = tonumber(f.line) or 1,
                })
                ::not_frame_continue::
            end

            if #frames > 0 then
                table.insert(err_stacks, {
                    label = "[" .. e.kind .. "] " .. message,
                    frames = frames,
                })
            end
            ::not_stack_continue::
        end

        if #err_stacks > 0 then
            new_error(e.kind, message, "valgrind", err_stacks, meta)
        end
        num_errors = num_errors + 1
        ::not_error_continue::
    end

    return num_errors
end

-- Parse a sanitizer log file into structured error objects.
M.parse_sanitizer_log = function(log_file)
    local log_file_handle = io.open(log_file, "r")
    if not log_file_handle then
        print("Failed to read sanitizer log file: " .. log_file)
        return 0
    end

    local cwd = vim.fn.getcwd()
    local current_message = "NO MESSAGE"
    local current_kind = "unknown"
    local current_meta = {}
    local current_stacks = {}  -- Array of { label, frames }.
    local current_label = ""
    local current_frames = {}
    local last_addr = "NO ADDRESS"
    local num_processed_lines = 0
    local in_error = false

    -- Finalize the current stack section (if it has frames).
    local function finalize_stack()
        if #current_frames > 0 then
            table.insert(current_stacks, {
                label = current_label,
                frames = current_frames,
            })
            current_frames = {}
        end
    end

    -- Finalize the current error (if it has stacks).
    local function finalize_error()
        finalize_stack()
        if #current_stacks > 0 then
            new_error(current_kind, current_message, "sanitizer", current_stacks, current_meta)
        end
        current_stacks = {}
        current_meta = {}
        current_label = ""
        current_frames = {}
        in_error = false
    end

    for line in log_file_handle:lines() do
        if starts_with(line, "allocated by") then
            -- "allocated by" continues the current error as a new stack section.
            finalize_stack()
            current_label = last_addr .. " " .. line
            current_meta.heap_block = true
            local size, addr, thr = string.match(current_label,
                "^%s*Location is heap block of size (%d+) at (0x%x+) allocated by (.*):$")
            if size then
                current_meta.size = size
                current_meta.addr = addr
                current_meta.thr = thr
            end
        elseif not starts_with(line, "    #") then
            -- Non-frame line: could be a new error or a section header within an error.
            -- Match ASAN format (==PID==ERROR:) and TSAN format (bare WARNING:).
            local maybe_error_message = string.match(line, "==%d+==ERROR: .*Sanitizer: (.*)")
            local maybe_warning_message = string.match(line, "==%d+==WARNING: .*Sanitizer: (.*)")
                or string.match(line, "^WARNING: .*Sanitizer: (.*)")

            if maybe_error_message or maybe_warning_message then
                -- New error starts.
                finalize_error()
                current_message = maybe_error_message or maybe_warning_message
                current_kind = current_message:match("^(%S+)") or "unknown"
                current_label = current_message
                in_error = true
            elseif in_error then
                -- Section header within current error.
                finalize_stack()
                current_label = line

                -- Extract metadata from section headers, accumulating into sets.
                local rw_op, size, addr, thr = string.match(line, "^%s*(.*) of size (%d+) at (0x%x+) by (.*):$")
                if rw_op then
                    current_meta.rw_op = current_meta.rw_op or {}
                    current_meta.rw_op[rw_op] = true
                    current_meta.size = current_meta.size or {}
                    current_meta.size[size] = true
                    current_meta.addr = current_meta.addr or {}
                    current_meta.addr[addr] = true
                    current_meta.thr = current_meta.thr or {}
                    current_meta.thr[thr] = true
                end

                local mutex = string.match(line, "^%s*Mutex (.*) created at:$")
                if mutex then
                    current_meta.mutex = current_meta.mutex or {}
                    current_meta.mutex[mutex] = true
                end

                local hsize, haddr, hthr = string.match(line, "^%s*Location is heap block of size (%d+) at (0x%x+) allocated by (.*):$")
                if hsize then
                    current_meta.heap_block = true
                    current_meta.size = current_meta.size or {}
                    current_meta.size[hsize] = true
                    current_meta.addr = current_meta.addr or {}
                    current_meta.addr[haddr] = true
                    current_meta.thr = current_meta.thr or {}
                    current_meta.thr[hthr] = true
                end

                local leak_type, lsize, num_objs = string.match(line, "^%s*(.*) leak of (%d+) byte%(s%) in (%d+) object%(s%) allocated from:$")
                if leak_type then
                    current_meta.leak_type = current_meta.leak_type or {}
                    current_meta.leak_type[leak_type] = true
                    current_meta.size = current_meta.size or {}
                    current_meta.size[lsize] = true
                    current_meta.num_objs = current_meta.num_objs or {}
                    current_meta.num_objs[num_objs] = true
                end
            end

            local addr = string.match(line, "(0x%x+)")
            if addr then
                last_addr = addr
            end
        else
            -- Frame line.
            local target = string.match(line, "#%d+ 0x%x+ .* (.+)")  -- ASAN format.
            if not target then
                target = string.match(line, "#%d+ %S+ ([^%(]+)%s+%(")  -- TSAN format.
            end
            if not target then
                goto not_source_file_continue
            end
            if not starts_with(target, cwd) then
                goto not_source_file_continue
            end
            local filename, line_number = string.match(target, "(%S+):(%d+)")
            if not filename or not line_number then
                goto not_source_file_continue
            end

            table.insert(current_frames, {
                file = filename,
                line = tonumber(line_number),
            })
            num_processed_lines = num_processed_lines + 1
        end
        ::not_source_file_continue::
    end
    log_file_handle:close()

    -- Finalize the last error.
    finalize_error()

    return num_processed_lines
end

M.run_valgrind = function(args)
    local xml_file = vim.fn.tempname()

    local valgrind_cmd_line = "!valgrind --num-callers=500 --xml=yes --xml-file="
        .. vim.fn.shellescape(xml_file) .. " " .. args.args

    vim.cmd(valgrind_cmd_line)
    M.valgrind_load_xml({args = xml_file})

    vim.fn.delete(xml_file)
end

M.valgrind_load_xml = function(args)
    local xml_file = args.args
    reset_state()
    local num_errors = M.parse_valgrind_xml(xml_file)
    populate_quickfix_from_errors()
    vim.notify("Processed " .. num_errors .. " errors from '" .. xml_file .. "' into " .. #qf_error_ids .. " locations.")
end

local function load_files(filepaths)
    reset_state()
    for _, filepath in ipairs(filepaths) do
        local format = detect_log_format(filepath)
        if format == "valgrind_xml" then
            M.parse_valgrind_xml(filepath)
            vim.notify("Parsed valgrind XML: " .. filepath)
        elseif format == "sanitizer_log" then
            M.parse_sanitizer_log(filepath)
            vim.notify("Parsed sanitizer log: " .. filepath)
        end
    end
    populate_quickfix_from_errors()
    vim.notify("Loaded " .. #errors .. " errors into " .. #qf_error_ids .. " quickfix entries.")
end

-- Stack frame navigation.

local function get_error_by_id(id)
    for _, err in ipairs(errors) do
        if err.id == id then return err end
    end
    return nil
end

-- Get the current file and line from cursor position or quickfix entry.
local function get_current_position()
    if vim.bo.buftype == "quickfix" then
        local qflist = vim.fn.getqflist()
        local entry = qflist[vim.fn.line(".")]
        if not entry or entry.bufnr == 0 then return nil, nil end
        return vim.api.nvim_buf_get_name(entry.bufnr), entry.lnum
    end
    return vim.api.nvim_buf_get_name(0), vim.api.nvim_win_get_cursor(0)[1]
end

-- Find adjacent frames in the given direction from file:line.
-- direction = -1 for deeper (toward inner frames), +1 for shallower (toward main).
-- Returns array of { file, line, label }.
local function find_adjacent_frames(file, line, direction)
    local key = file .. ":" .. line
    local ids = location_index[key]
    if not ids then return {} end

    local targets = {}
    local seen = {}
    local seen_ids = {}
    for _, id in ipairs(ids) do
        if not seen_ids[id] then
            seen_ids[id] = true
            local err = get_error_by_id(id)
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

-- Jump to a target frame. When in the quickfix window, use :cc to update
-- both the visual cursor and the internal quickfix index (keeping ]q/[q
-- in sync), then return focus to the quickfix window.
local function jump_to_frame(target)
    if vim.bo.buftype == "quickfix" then
        local qflist = vim.fn.getqflist()
        for i, entry in ipairs(qflist) do
            if entry.lnum == target.line
                and vim.api.nvim_buf_get_name(entry.bufnr) == target.file then
                vim.cmd("silent " .. i .. "cc")
                vim.cmd("wincmd p")
                return
            end
        end
        -- No matching qf entry; update the source window manually.
        vim.cmd("wincmd p")
        vim.cmd("edit " .. vim.fn.fnameescape(target.file))
        vim.api.nvim_win_set_cursor(0, { target.line, 0 })
        vim.cmd("wincmd p")
        return
    end
    vim.cmd("edit " .. vim.fn.fnameescape(target.file))
    vim.api.nvim_win_set_cursor(0, { target.line, 0 })
end

-- Navigate to adjacent stack frames in the given direction.
-- direction = -1 for deeper, +1 for shallower.
local function navigate_stack(direction)
    -- Keep the quickfix internal index in sync with the cursor so that
    -- ]q/[q continue from the right position after ]s/[s navigation.
    if vim.bo.buftype == "quickfix" then
        vim.fn.setqflist({}, "a", { idx = vim.fn.line(".") })
    end

    local file, line = get_current_position()
    if not file or not line then
        vim.notify("No position to navigate from.", vim.log.levels.WARN)
        return
    end

    local targets = find_adjacent_frames(file, line, direction)
    if #targets == 0 then
        local msg = direction < 0 and "At end of stack." or "At top of stack."
        vim.notify(msg, vim.log.levels.INFO)
        return
    end

    if #targets == 1 then
        jump_to_frame(targets[1])
        vim.notify(targets[1].label, vim.log.levels.INFO)
        return
    end

    vim.ui.select(targets, {
        prompt = "Select stack frame:",
        format_item = function(item) return item.label end,
    }, function(choice)
        if choice then
            jump_to_frame(choice)
            vim.notify(choice.label, vim.log.levels.INFO)
        end
    end)
end

M.stack_next = function()
    navigate_stack(-1)
end

M.stack_prev = function()
    navigate_stack(1)
end

-- SanityStacks: show all stacks at the current cursor line.

local function pick_stacks_fzf_lua(items, on_select)
    require("fzf-lua").fzf_exec(
        vim.tbl_map(function(item) return item.display end, items),
        {
            prompt = "SanityStacks> ",
            actions = {
                ["default"] = function(selected)
                    if #selected > 0 then
                        -- Find the matching item.
                        for _, item in ipairs(items) do
                            if item.display == selected[1] then
                                on_select(item)
                                return
                            end
                        end
                    end
                end,
            },
        }
    )
end

local function pick_stacks_telescope(items, on_select)
    local pickers = require("telescope.pickers")
    local finders = require("telescope.finders")
    local conf = require("telescope.config").values
    local actions = require("telescope.actions")
    local action_state = require("telescope.actions.state")

    pickers.new({}, {
        prompt_title = "SanityStacks",
        finder = finders.new_table({
            results = items,
            entry_maker = function(item)
                return {
                    value = item,
                    display = item.display,
                    ordinal = item.display,
                }
            end,
        }),
        sorter = conf.generic_sorter({}),
        attach_mappings = function(prompt_bufnr, _)
            actions.select_default:replace(function()
                local entry = action_state.get_selected_entry()
                actions.close(prompt_bufnr)
                if entry then
                    on_select(entry.value)
                end
            end)
            return true
        end,
    }):find()
end

local function pick_stacks_mini_pick(items, on_select)
    MiniPick.start({
        source = {
            name = "SanityStacks",
            items = vim.tbl_map(function(item) return item.display end, items),
            choose = function(chosen)
                for _, item in ipairs(items) do
                    if item.display == chosen then
                        on_select(item)
                        return
                    end
                end
            end,
        },
    })
end

local function pick_stacks_snacks(items, on_select)
    require("snacks").picker({
        title = "SanityStacks",
        items = vim.tbl_map(function(item)
            return { text = item.display, item = item }
        end, items),
        confirm = function(picker)
            picker:close()
            local sel = picker:selected({ fallback = true })
            if #sel > 0 and sel[1].item then
                on_select(sel[1].item)
            end
        end,
    })
end

local function pick_stacks(items, on_select)
    local pickers_map = {
        ["fzf-lua"]   = { mod = "fzf-lua",   fn = pick_stacks_fzf_lua },
        ["telescope"] = { mod = "telescope",  fn = pick_stacks_telescope },
        ["mini.pick"] = { mod = "mini.pick",  fn = pick_stacks_mini_pick },
        ["snacks"]    = { mod = "snacks",     fn = pick_stacks_snacks },
    }
    if config.picker then
        local p = pickers_map[config.picker]
        if p then
            p.fn(items, on_select)
            return
        end
        vim.notify("SanityStacks: unknown picker '" .. config.picker .. "'", vim.log.levels.ERROR)
        return
    end
    for _, name in ipairs({ "fzf-lua", "telescope", "mini.pick", "snacks" }) do
        local ok = pcall(require, pickers_map[name].mod)
        if ok then
            pickers_map[name].fn(items, on_select)
            return
        end
    end
    vim.notify("SanityStacks: no picker available (install fzf-lua, telescope.nvim, mini.pick, or snacks.nvim)",
        vim.log.levels.ERROR)
end

M.sanity_stacks = function()
    local file, line = get_current_position()
    if not file or not line then
        vim.notify("No position to show stacks for.", vim.log.levels.WARN)
        return
    end
    local key = file .. ":" .. line
    local ids = location_index[key]
    if not ids or #ids == 0 then
        vim.notify("No errors at this line.", vim.log.levels.INFO)
        return
    end

    local items = {}
    local seen_ids = {}
    for _, id in ipairs(ids) do
        if not seen_ids[id] then
            seen_ids[id] = true
            local err = get_error_by_id(id)
            if err then
                for _, stack in ipairs(err.stacks) do
                    for fi, frame in ipairs(stack.frames) do
                        if frame.file == file and frame.line == line then
                            table.insert(items, {
                                display = string.format("[%s] %s — frame %d of %d (%s:%d)",
                                    err.kind, stack.label, fi, #stack.frames,
                                    frame.file:match("[^/]+$"), frame.line),
                                file = frame.file,
                                line = frame.line,
                            })
                        end
                    end
                end
            end
        end
    end

    if #items == 0 then
        vim.notify("No stacks at this line.", vim.log.levels.INFO)
        return
    end

    pick_stacks(items, function(item)
        jump_to_frame(item)
    end)
end

M.sanity_load_log = function(args)
    local filepaths = args.fargs
    if #filepaths == 0 then
        pickers.pick_files(config.picker, load_files)
        return
    end
    load_files(filepaths)
end

-- Expose internals for testing.
M._errors = function() return errors end
M._location_index = function() return location_index end
M._qf_error_ids = function() return qf_error_ids end
return M

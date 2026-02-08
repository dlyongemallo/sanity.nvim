local M = {}
local pickers = require("sanity.pickers")

local config = {}

-- Structured error storage.
local errors = {}
local errors_by_id = {}
local error_id_counter = 0
local location_index = {}  -- "file:line" -> { error_id, ... }
local qf_error_ids = {}    -- qf index -> { error_id, ... }
local qf_file_lines = {}   -- qf index -> { file, line } using original frame paths

local ns = vim.api.nvim_create_namespace("sanity")

local set_diagnostics  -- Forward declaration; defined after populate_quickfix_from_errors.

local function reset_state()
    errors = {}
    errors_by_id = {}
    error_id_counter = 0
    location_index = {}
    qf_error_ids = {}
    qf_file_lines = {}
    vim.diagnostic.reset(ns)
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
    errors_by_id[err.id] = err
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
    config.diagnostics_enabled = true

    vim.api.nvim_create_user_command("Valgrind", M.run_valgrind, { nargs = 1 })
    vim.api.nvim_create_user_command("SanityLoadLog", M.sanity_load_log, { nargs = "*", complete = "file" })
    vim.api.nvim_create_user_command("SanityStack", M.sanity_stack, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityStackNext", function() M.stack_next() end, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityStackPrev", function() M.stack_prev() end, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityDiagnostics", M.toggle_diagnostics, { nargs = "?" })

    -- Refresh diagnostic columns when a source file is opened.
    vim.api.nvim_create_autocmd("BufReadPost", {
        group = vim.api.nvim_create_augroup("sanity", { clear = true }),
        callback = function(ev)
            if #errors > 0 and config.diagnostics_enabled then
                set_diagnostics(ev.buf)
            end
        end,
    })

    -- Set keymaps unless explicitly disabled with false.
    local keymaps = opts.keymaps or {}
    local next_key = keymaps.stack_next
    if next_key == nil then next_key = "]s" end
    if next_key then
        vim.keymap.set("n", next_key, M.stack_next, { desc = "Next stack frame" })
    end
    local prev_key = keymaps.stack_prev
    if prev_key == nil then prev_key = "[s" end
    if prev_key then
        vim.keymap.set("n", prev_key, M.stack_prev, { desc = "Previous stack frame" })
    end
    local show_key = keymaps.show_stack
    if show_key then
        vim.keymap.set("n", show_key, M.sanity_stack, { desc = "Show stack explorer" })
    end
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

-- Group error frames by (file, line, kind), collecting link sets.
-- Each group tracks its errors, file/line, kind, and a link set showing where
-- each frame points in the stack (END for the deepest, ->basename:line otherwise).
-- Returns (groups, group_order) where group_order is sorted by file:line:kind.
local function group_error_frames()
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
    end

    table.sort(group_order)
    return groups, group_order
end

-- Populate the quickfix list from the errors array.
local function populate_quickfix_from_errors()
    local groups, group_order = group_error_frames()

    local qf_entries = {}
    qf_error_ids = {}
    qf_file_lines = {}

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
        table.insert(qf_file_lines, { file = group.file, line = group.line })
    end

    vim.fn.setqflist(qf_entries, " ")

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
            if qf_error_ids[i] then
                table.insert(deduped_ids, qf_error_ids[i])
            end
            if qf_file_lines[i] then
                table.insert(deduped_fl, qf_file_lines[i])
            end
        end
    end
    if #deduped < #qflist then
        vim.fn.setqflist(deduped, "r")
        qf_error_ids = deduped_ids
        qf_file_lines = deduped_fl
    end
end

-- Map error kind to diagnostic severity.
local function get_severity(kind)
    if kind:match("^Leak_StillReachable") then
        return vim.diagnostic.severity.INFO
    elseif kind:match("^Leak_Possibly") or kind:match("^Leak_Indirect") then
        return vim.diagnostic.severity.WARN
    else
        return vim.diagnostic.severity.ERROR
    end
end

-- Set diagnostics on buffers for all error frames.
-- When only_bufnr is given, only refresh diagnostics for that buffer.
set_diagnostics = function(only_bufnr)
    if not config.diagnostics_enabled then return end

    local groups, group_order = group_error_frames()

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
        local links = format_link_set(group.link_set)
        local msg = string.format("[%s] %s (%s)", group.kind, group.errors[1].message, links)
        table.insert(buf_diags[bufnr], {
            lnum = lnum,
            col = col,
            message = msg,
            severity = get_severity(group.kind),
            source = "sanity",
        })
        ::diag_continue::
    end

    for bufnr, diags in pairs(buf_diags) do
        vim.diagnostic.set(ns, bufnr, diags)
    end
end

M.toggle_diagnostics = function(args)
    local arg = args.args
    if arg == "on" then
        config.diagnostics_enabled = true
        set_diagnostics()
    elseif arg == "off" then
        config.diagnostics_enabled = false
        vim.diagnostic.reset(ns)
    else
        config.diagnostics_enabled = not config.diagnostics_enabled
        if config.diagnostics_enabled then
            set_diagnostics()
        else
            vim.diagnostic.reset(ns)
        end
    end
end

-- Parse a valgrind XML file into structured error objects.
M.parse_valgrind_xml = function(xml_file)
    local xml2lua = require("xml2lua")
    -- Create a fresh handler each call to avoid xml2lua's repeated-parse bug.
    local handler = require("xmlhandler.tree"):new()

    local parser = xml2lua.parser(handler)
    local ok, parse_err = pcall(function()
        parser:parse(xml2lua.loadFile(xml_file))
    end)
    if not ok then
        vim.notify("Failed to parse XML: " .. tostring(parse_err), vim.log.levels.ERROR)
        return 0
    end

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

        -- Extract auxwhat labels for secondary stacks.
        local auxwhat_list = e.auxwhat
        if type(auxwhat_list) == "string" then
            auxwhat_list = { auxwhat_list }
        end

        local err_stacks = {}
        local stack_idx = 0
        for _, s in ipairs_safe(stacks_list) do
            if not s.frame then goto not_stack_continue end
            stack_idx = stack_idx + 1
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
                    func = f.fn,
                })
                ::not_frame_continue::
            end

            if #frames > 0 then
                -- First stack uses the error message; subsequent stacks use auxwhat.
                local label
                if stack_idx == 1 then
                    label = message
                elseif auxwhat_list and auxwhat_list[stack_idx - 1] then
                    label = auxwhat_list[stack_idx - 1]
                else
                    label = message
                end
                table.insert(err_stacks, {
                    label = label,
                    frames = frames,
                })
            end
            ::not_stack_continue::
        end

        if #err_stacks > 0 then
            new_error(e.kind, message, "valgrind", err_stacks, meta)
            num_errors = num_errors + 1
        end
        ::not_error_continue::
    end

    return num_errors
end

-- Parse a sanitizer log file into structured error objects.
M.parse_sanitizer_log = function(log_file)
    local log_file_handle = io.open(log_file, "r")
    if not log_file_handle then
        vim.notify("Failed to read sanitizer log file: " .. log_file, vim.log.levels.ERROR)
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

    local ok, parse_err = pcall(function()
    for line in log_file_handle:lines() do
        if starts_with(line, "allocated by") then
            -- "allocated by" continues the current error as a new stack section.
            finalize_stack()
            current_label = last_addr .. " " .. line
            current_meta.heap_block = true
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
                -- Handle multi-word kinds like "data race (pid=...)" → "data-race".
                current_kind = current_message:match("^(%S+%s%S+)%s+%(")
                    or current_message:match("^(%S+)") or "unknown"
                current_kind = current_kind:gsub("%s+", "-")
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
            -- Extract function name (nil when unavailable).
            local func_name = line:match("#%d+ 0x%x+ in (%S+)")       -- ASAN format.
            if not func_name then
                func_name = line:match("#%d+ (%S+) /")                 -- TSAN format.
            end

            local target = string.match(line, "#%d+ 0x%x+ .* (.+)")   -- ASAN format.
            if not target then
                target = string.match(line, "#%d+ %S+ ([^%(]+)%s+%(") -- TSAN format.
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
                func = func_name,
            })
            num_processed_lines = num_processed_lines + 1
        end
        ::not_source_file_continue::
    end
    end)
    log_file_handle:close()
    if not ok then
        vim.notify("Error parsing log: " .. tostring(parse_err), vim.log.levels.ERROR)
        return 0
    end

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
    set_diagnostics()
    if #qf_error_ids > 0 then vim.cmd("cfirst") end
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
    set_diagnostics()
    if #qf_error_ids > 0 then vim.cmd("cfirst") end
    vim.notify("Loaded " .. #errors .. " errors into " .. #qf_error_ids .. " quickfix entries.")
end

-- Stack frame navigation.

local function get_error_by_id(id)
    return errors_by_id[id]
end

-- Get the current file and line from cursor position or quickfix entry.
-- Returns (file, line, error_ids). The third value is non-nil only when
-- called from the quickfix window — it carries the error IDs directly so
-- callers can bypass location_index (whose keys may not match Vim's
-- normalised buffer paths).
local function get_current_position()
    if vim.bo.buftype == "quickfix" then
        local idx = vim.fn.line(".")
        local ids = qf_error_ids[idx]
        local fl = qf_file_lines[idx]
        if fl then return fl.file, fl.line, ids end
        local qflist = vim.fn.getqflist()
        local entry = qflist[idx]
        if not entry or entry.bufnr == 0 then return nil, nil end
        return vim.api.nvim_buf_get_name(entry.bufnr), entry.lnum, ids
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
            if entry.bufnr ~= 0 and entry.lnum == target.line
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

-- SanityStack: interactive split showing all stacks at the cursor line.

local stack_bufnr = nil       -- Track the stack split buffer for toggling.
local stack_frame_map = nil   -- buf line number (1-based) -> { file, line }
local stack_win = nil         -- The stack split window.
local stack_preview_win = nil -- The source/preview window.
local stack_last_key = nil    -- "file:line" key to avoid redundant refreshes.
local stack_augroup = nil     -- Augroup for source-tracking autocmd.
local stack_last_preview = "" -- Preview dedup key.
local stack_preview_ns = vim.api.nvim_create_namespace("sanity_stack_preview")

local function close_stack_split()
    if stack_augroup then
        vim.api.nvim_del_augroup_by_id(stack_augroup)
        stack_augroup = nil
    end
    if stack_bufnr and vim.api.nvim_buf_is_valid(stack_bufnr) then
        local wins = vim.fn.win_findbuf(stack_bufnr)
        for _, win in ipairs(wins) do
            vim.api.nvim_win_close(win, true)
        end
    end
    -- Clear preview highlights from all buffers.
    for _, b in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_is_valid(b) then
            vim.api.nvim_buf_clear_namespace(b, stack_preview_ns, 0, -1)
        end
    end
    stack_bufnr = nil
    stack_frame_map = nil
    stack_win = nil
    stack_preview_win = nil
    stack_last_key = nil
    stack_last_preview = ""
end

-- Find a suitable preview window, avoiding quickfix and stack buffer windows.
local function find_preview_win()
    local alt = vim.fn.win_getid(vim.fn.winnr("#"))
    if alt ~= 0 and vim.api.nvim_win_is_valid(alt) then
        local bt = vim.bo[vim.api.nvim_win_get_buf(alt)].buftype
        local bn = vim.api.nvim_win_get_buf(alt)
        if bt == "" and bn ~= stack_bufnr then
            return alt
        end
    end
    for _, win in ipairs(vim.api.nvim_tabpage_list_wins(0)) do
        local buf = vim.api.nvim_win_get_buf(win)
        if vim.bo[buf].buftype == "" and buf ~= stack_bufnr then
            return win
        end
    end
    return vim.api.nvim_get_current_win()
end

-- Build the stack content lines and frame map for a given file:line.
-- When error_ids is provided (from quickfix), uses those directly instead of
-- looking up location_index, which avoids path-normalisation mismatches.
-- Returns buf_lines, frame_map, cursor_line or nil if no errors.
local function build_stack_content(file, line, error_ids)
    local ids = error_ids
    if not ids or #ids == 0 then
        ids = location_index[file .. ":" .. line]
    end
    if not ids or #ids == 0 then return nil end

    -- Expand to all related errors: any error sharing a frame with the initial
    -- set is included, transitively.  This ensures the full tree is shown
    -- regardless of which frame the user triggered the stack from.
    local seen_ids = {}
    local queue = {}
    for _, id in ipairs(ids) do
        if not seen_ids[id] then
            seen_ids[id] = true
            table.insert(queue, id)
        end
    end
    local qi = 1
    while qi <= #queue do
        local err = get_error_by_id(queue[qi])
        qi = qi + 1
        if err then
            for _, stack in ipairs(err.stacks) do
                for _, frame in ipairs(stack.frames) do
                    local neighbours = location_index[frame.file .. ":" .. frame.line]
                    if neighbours then
                        for _, nid in ipairs(neighbours) do
                            if not seen_ids[nid] then
                                seen_ids[nid] = true
                                table.insert(queue, nid)
                            end
                        end
                    end
                end
            end
        end
    end

    -- Collect the expanded error set.
    local err_list = {}
    for _, id in ipairs(queue) do
        local err = get_error_by_id(id)
        if err then table.insert(err_list, err) end
    end
    if #err_list == 0 then return nil end

    local buf_lines = {}
    local frame_map = {}
    local cursor_line = nil

    local function format_frame(prefix, frame)
        local func_col = frame.func or "???"
        local basename = frame.file:match("[^/]+$") or frame.file
        return string.format("%s%-28s %s:%d", prefix, func_col, basename, frame.line)
    end

    local function emit_frame(prefix, frame)
        table.insert(buf_lines, format_frame(prefix, frame))
        frame_map[#buf_lines] = { file = frame.file, line = frame.line }
        if not cursor_line and frame.file == file and frame.line == line then
            cursor_line = #buf_lines
        end
    end

    local function find_common_prefix(stacks)
        if #stacks < 2 then return 0 end
        local min_len = math.huge
        for _, s in ipairs(stacks) do min_len = math.min(min_len, #s.frames) end
        local common = 0
        for i = 1, min_len do
            local ref = stacks[1].frames[i]
            local all_match = true
            for si = 2, #stacks do
                local f = stacks[si].frames[i]
                if f.file ~= ref.file or f.line ~= ref.line then
                    all_match = false
                    break
                end
            end
            if not all_match then break end
            common = common + 1
        end
        return common
    end

    local function find_common_suffix(stacks)
        if #stacks < 2 then return 0 end
        local min_len = math.huge
        for _, s in ipairs(stacks) do min_len = math.min(min_len, #s.frames) end
        local common = 0
        for offset = 1, min_len do
            local ref = stacks[1].frames[#stacks[1].frames - offset + 1]
            local all_match = true
            for si = 2, #stacks do
                local f = stacks[si].frames[#stacks[si].frames - offset + 1]
                if f.file ~= ref.file or f.line ~= ref.line then
                    all_match = false
                    break
                end
            end
            if not all_match then break end
            common = common + 1
        end
        return common
    end

    -- Group errors by kind so same-kind errors are merged into one tree.
    local kind_groups = {}
    local kind_order = {}
    for _, err in ipairs(err_list) do
        if not kind_groups[err.kind] then
            kind_groups[err.kind] = {}
            table.insert(kind_order, err.kind)
        end
        table.insert(kind_groups[err.kind], err)
    end

    for ki, kind in ipairs(kind_order) do
        local group_errs = kind_groups[kind]
        if ki > 1 then table.insert(buf_lines, "") end

        local header = string.format("[%s] %s", kind, group_errs[1].message)
        if #group_errs > 1 then
            header = header .. string.format(" (+%d more)", #group_errs - 1)
        end
        table.insert(buf_lines, header)

        -- Pool all stacks, deduplicating by frame sequence.
        local all_stacks = {}
        local stack_seen = {}
        for _, err in ipairs(group_errs) do
            for _, stack in ipairs(err.stacks) do
                local parts = {}
                for _, frame in ipairs(stack.frames) do
                    table.insert(parts, frame.file .. ":" .. frame.line)
                end
                local fp = table.concat(parts, "\0")
                if not stack_seen[fp] then
                    stack_seen[fp] = true
                    table.insert(all_stacks, stack)
                end
            end
        end

        if #all_stacks == 1 then
            -- Single unique stack: flat display.
            for _, frame in ipairs(all_stacks[1].frames) do
                emit_frame("    ", frame)
            end
        else
            -- Multiple stacks: find common prefix/suffix, build tree.
            local prefix_count = find_common_prefix(all_stacks)
            local suffix_count = find_common_suffix(all_stacks)
            local min_len = math.huge
            for _, s in ipairs(all_stacks) do
                min_len = math.min(min_len, #s.frames)
            end
            -- Clamp so prefix and suffix don't overlap.
            if prefix_count + suffix_count > min_len then
                suffix_count = min_len - prefix_count
            end

            -- Check whether any stack has divergent (non-common) frames.
            local has_divergent = false
            for _, stack in ipairs(all_stacks) do
                if #stack.frames > prefix_count + suffix_count then
                    has_divergent = true
                    break
                end
            end

            if not has_divergent then
                -- All stacks identical after dedup: flat display.
                for _, frame in ipairs(all_stacks[1].frames) do
                    emit_frame("    ", frame)
                end
            else
                local ref = all_stacks[1]

                -- Collect divergent frames tagged with their stack label,
                -- then sort by (file, line) so navigation is sequential.
                local div_frames = {}
                for _, stack in ipairs(all_stacks) do
                    for i = prefix_count + 1, #stack.frames - suffix_count do
                        table.insert(div_frames, {
                            frame = stack.frames[i],
                            label = stack.label,
                        })
                    end
                end
                table.sort(div_frames, function(a, b)
                    if a.frame.file ~= b.frame.file then
                        return a.frame.file < b.frame.file
                    end
                    return a.frame.line < b.frame.line
                end)

                -- Indentation: each fork adds 1 character of depth.
                local has_prefix = prefix_count > 0
                local prefix_indent = "  "
                local div_indent = has_prefix and "   " or "  "
                local suffix_indent = div_indent .. " "

                -- When suffix has 2+ frames, pop the first as a merge line
                -- rendered at divergent indent with └┬. When suffix has
                -- exactly 1 frame, the last divergent frame gets └┬ and the
                -- sole suffix frame goes to suffix indent.
                local merge_frame = nil
                local suffix_start = #ref.frames - suffix_count + 1
                if suffix_count > 1 then
                    merge_frame = ref.frames[suffix_start]
                    suffix_start = suffix_start + 1
                end

                -- UTF-8 tree-drawing characters.
                local TOP    = "\xe2\x94\x8c" -- ┌
                local MID    = "\xe2\x94\x82" -- │
                local BRANCH = "\xe2\x94\x9c" -- ├
                local BOT    = "\xe2\x94\x94" -- └
                local MERGE  = "\xe2\x94\x94\xe2\x94\xac" -- └┬

                -- Prefix zone: common deep callees.
                for i = 1, prefix_count do
                    local ch = (i == 1) and TOP or MID
                    emit_frame(prefix_indent .. ch .. " ", ref.frames[i])
                end
                -- Transition label: └┬ closes the prefix rail and opens
                -- the divergent rail. The label is non-navigable.
                if has_prefix then
                    table.insert(buf_lines, prefix_indent
                        .. MERGE .. " " .. div_frames[1].label .. ":")
                end

                -- Divergent zone.
                local labels_shown = {}
                local last_label = nil
                for di, df in ipairs(div_frames) do
                    local is_last = di == #div_frames

                    -- Emit a label line when a new label first appears.
                    -- Skip the first label if already emitted as the
                    -- prefix transition label above.
                    local emitted_label = false
                    if df.label ~= last_label then
                        if not labels_shown[df.label] then
                            if has_prefix and di == 1 then
                                -- Already emitted as the prefix transition label.
                            elseif di == 1 then
                                -- No prefix: standalone label, no tree char.
                                table.insert(buf_lines,
                                    div_indent .. df.label .. ":")
                                emitted_label = true
                            else
                                table.insert(buf_lines,
                                    div_indent .. BRANCH .. " " .. df.label .. ":")
                                emitted_label = true
                            end
                            labels_shown[df.label] = true
                        end
                        last_label = df.label
                    end

                    -- Tree character for this frame line.
                    local ch
                    if is_last and not merge_frame then
                        ch = suffix_count > 0 and MERGE or BOT
                    elseif di == 1 and not has_prefix then
                        ch = TOP
                    elseif emitted_label or (di == 1 and has_prefix) then
                        -- Frame right after a label line or prefix transition.
                        ch = MID
                    else
                        local prev_label = div_frames[di - 1].label
                        if df.label ~= prev_label then
                            -- Label changed but already shown (no label line
                            -- emitted): branch on the frame itself.
                            ch = BRANCH
                        else
                            ch = MID
                        end
                    end
                    emit_frame(div_indent .. ch .. " ", df.frame)
                end

                -- Merge line: first suffix frame at divergent indent
                -- when suffix has 2+ frames.
                if merge_frame then
                    emit_frame(div_indent .. MERGE .. " ", merge_frame)
                end

                -- Remaining suffix frames at suffix indent.
                for i = suffix_start, #ref.frames do
                    local ch = (i == #ref.frames) and BOT or MID
                    emit_frame(suffix_indent .. ch .. " ", ref.frames[i])
                end
            end
        end
    end

    return buf_lines, frame_map, cursor_line or 1
end

-- Refresh the stack buffer content for a new file:line position.
-- When there are no errors at the new position, keeps the last stack visible.
local function refresh_stack(file, line, error_ids)
    if not stack_bufnr or not vim.api.nvim_buf_is_valid(stack_bufnr) then return end

    local new_key = file .. ":" .. line
    if new_key == stack_last_key then return end

    local buf_lines, frame_map, cursor_line = build_stack_content(file, line, error_ids)
    if not buf_lines then
        stack_last_key = new_key
        return
    end

    stack_last_key = new_key
    stack_frame_map = frame_map

    vim.bo[stack_bufnr].modifiable = true
    vim.api.nvim_buf_set_lines(stack_bufnr, 0, -1, false, buf_lines)
    vim.bo[stack_bufnr].modifiable = false

    if stack_win and vim.api.nvim_win_is_valid(stack_win) then
        vim.api.nvim_win_set_height(stack_win, math.min(15, #buf_lines))
        vim.api.nvim_win_set_cursor(stack_win, { cursor_line, 0 })
    end

    -- Reset preview so the next CursorMoved triggers a fresh preview.
    stack_last_preview = ""
end

M.sanity_stack = function()
    -- Toggle off if already open.
    if stack_bufnr and vim.api.nvim_buf_is_valid(stack_bufnr) then
        local wins = vim.fn.win_findbuf(stack_bufnr)
        if #wins > 0 then
            close_stack_split()
            return
        end
    end

    local file, line, error_ids = get_current_position()
    if not file or not line then
        vim.notify("No position to show stacks for.", vim.log.levels.WARN)
        return
    end

    local buf_lines, frame_map, cursor_line = build_stack_content(file, line, error_ids)
    if not buf_lines then
        vim.notify("No errors at this line.", vim.log.levels.INFO)
        return
    end

    -- Find the preview window before creating the split.
    stack_preview_win = find_preview_win()

    -- Create the stack buffer.
    local buf = vim.api.nvim_create_buf(false, true)
    stack_bufnr = buf
    vim.bo[buf].buftype = "nofile"
    vim.bo[buf].bufhidden = "wipe"
    vim.bo[buf].swapfile = false
    vim.bo[buf].filetype = "sanity_stack"

    -- Open a horizontal split at the bottom.
    local height = math.min(15, #buf_lines)
    vim.cmd("botright " .. height .. "split")
    stack_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_buf(stack_win, buf)
    vim.wo[stack_win].cursorline = true
    vim.wo[stack_win].number = false
    vim.wo[stack_win].relativenumber = false
    vim.wo[stack_win].signcolumn = "no"
    vim.wo[stack_win].winfixheight = true

    -- Set initial content.
    stack_frame_map = frame_map
    stack_last_key = file .. ":" .. line
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, buf_lines)
    vim.bo[buf].modifiable = false
    vim.api.nvim_win_set_cursor(stack_win, { cursor_line, 0 })

    -- Preview a frame in the source window.
    local function preview_frame(frame_info)
        local preview_key = frame_info.file .. ":" .. frame_info.line
        if preview_key == stack_last_preview then return end
        stack_last_preview = preview_key

        if not stack_preview_win or not vim.api.nvim_win_is_valid(stack_preview_win) then
            return
        end

        -- Open the file in the preview window.
        local cur_buf = vim.api.nvim_win_get_buf(stack_preview_win)
        local cur_name = vim.api.nvim_buf_get_name(cur_buf)
        if cur_name ~= frame_info.file then
            vim.api.nvim_win_call(stack_preview_win, function()
                vim.cmd("edit " .. vim.fn.fnameescape(frame_info.file))
            end)
        end

        -- Scroll to the line and centre it.
        local target_buf = vim.api.nvim_win_get_buf(stack_preview_win)
        local lc = vim.api.nvim_buf_line_count(target_buf)
        local target_line = math.min(frame_info.line, lc)
        vim.api.nvim_win_set_cursor(stack_preview_win, { target_line, 0 })
        vim.api.nvim_win_call(stack_preview_win, function()
            vim.cmd("normal! zz")
        end)

        -- Highlight the previewed line.
        vim.api.nvim_buf_clear_namespace(target_buf, stack_preview_ns, 0, -1)
        vim.api.nvim_buf_add_highlight(target_buf, stack_preview_ns, "CursorLine",
            target_line - 1, 0, -1)
    end

    -- Preview the initial frame.
    if stack_frame_map[cursor_line] then
        preview_frame(stack_frame_map[cursor_line])
    end

    -- CursorMoved autocmd on the stack buffer for live preview.
    vim.api.nvim_create_autocmd("CursorMoved", {
        buffer = buf,
        callback = function()
            if not stack_win or not vim.api.nvim_win_is_valid(stack_win) then return end
            local cur = vim.api.nvim_win_get_cursor(stack_win)[1]
            local info = stack_frame_map and stack_frame_map[cur]
            if info then
                preview_frame(info)
            end
        end,
    })

    -- Source-tracking autocmd: refresh stack when cursor moves in other windows.
    -- Deferred via vim.schedule so buffer modifications happen outside the
    -- CursorMoved handler (avoids silent failures in special buffers like quickfix).
    stack_augroup = vim.api.nvim_create_augroup("sanity_stack_track", { clear = true })
    vim.api.nvim_create_autocmd("CursorMoved", {
        group = stack_augroup,
        callback = function()
            if vim.api.nvim_get_current_buf() == stack_bufnr then return end
            vim.schedule(function()
                local f, l, ids = get_current_position()
                if f and l then refresh_stack(f, l, ids) end
            end)
        end,
    })

    -- Clean up when the stack buffer is wiped.
    vim.api.nvim_create_autocmd("BufWipeout", {
        buffer = buf,
        callback = function()
            close_stack_split()
        end,
    })

    -- Helper: find next/previous frame line.
    local function jump_to_frame_line(direction)
        if not stack_win or not vim.api.nvim_win_is_valid(stack_win) then return end
        local cur = vim.api.nvim_win_get_cursor(stack_win)[1]
        local line_count = vim.api.nvim_buf_line_count(stack_bufnr)
        local target = cur + direction
        while target >= 1 and target <= line_count do
            if stack_frame_map and stack_frame_map[target] then
                vim.api.nvim_win_set_cursor(stack_win, { target, 0 })
                return
            end
            target = target + direction
        end
    end

    -- Keymaps.
    local kopts = { buffer = buf, nowait = true, silent = true }

    -- Close the split.
    local function close()
        -- Capture preview win before close clears it.
        local pw = stack_preview_win
        close_stack_split()
        if pw and vim.api.nvim_win_is_valid(pw) then
            vim.api.nvim_set_current_win(pw)
        end
    end
    vim.keymap.set("n", "q", close, kopts)
    vim.keymap.set("n", "<Esc>", close, kopts)

    -- Jump to frame under cursor.
    vim.keymap.set("n", "<CR>", function()
        if not stack_win or not vim.api.nvim_win_is_valid(stack_win) then return end
        local cur = vim.api.nvim_win_get_cursor(stack_win)[1]
        local info = stack_frame_map and stack_frame_map[cur]
        if not info then return end
        local pw = stack_preview_win
        close_stack_split()
        if pw and vim.api.nvim_win_is_valid(pw) then
            vim.api.nvim_set_current_win(pw)
            vim.cmd("edit " .. vim.fn.fnameescape(info.file))
            vim.api.nvim_win_set_cursor(pw, { info.line, 0 })
        end
    end, kopts)

    -- Navigate between frame lines.
    vim.keymap.set("n", "]s", function() jump_to_frame_line(1) end, kopts)
    vim.keymap.set("n", "[s", function() jump_to_frame_line(-1) end, kopts)
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

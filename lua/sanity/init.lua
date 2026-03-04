local M = {}
local pickers = require("sanity.pickers")
local S = require("sanity.state")
local F = require("sanity.format")
local D = require("sanity.diff")
local Q = require("sanity.quickfix")
local P = require("sanity.parsers")
local SUP = require("sanity.suppressions")
local UI = require("sanity.ui")
local N = require("sanity.navigate")
local STK = require("sanity.stack")

local stop_watching         -- Forward declaration; defined after sanity_stack.
local start_watching        -- Forward declaration; defined after stop_watching.

function M.setup(opts)
    opts = opts or {}
    S.config.picker = opts.picker
    S.config.diagnostics_enabled = true
    S.config.suppression_files = vim.tbl_extend("force", {
        valgrind = ".valgrind.supp",
        lsan = ".lsan.supp",
        tsan = ".tsan.supp",
    }, opts.suppression_files or {})
    S.config.valgrind_suppressions = opts.valgrind_suppressions or {}
    S.config.track_origins = opts.track_origins == nil and "ask" or opts.track_origins
    S.config.stack_fold_limit = opts.stack_fold_limit or 6
    S.config.snapshot_file = opts.snapshot_file == nil and ".sanity-snapshot.json" or opts.snapshot_file

    vim.api.nvim_create_user_command("SanityRunValgrind", M.run_valgrind, { nargs = 1 })
    vim.api.nvim_create_user_command("SanityLoadLog", M.sanity_load_log, {
        nargs = "*",
        complete = function(arg_lead)
            local matches = vim.fn.getcompletion(arg_lead, "file")
            return vim.tbl_filter(function(m)
                -- Keep directories so the user can navigate into them.
                if vim.fn.isdirectory(m) == 1 or m:sub(-1) == "/" then return true end
                return m:match("%.txt$") or m:match("%.log$") or m:match("%.xml$")
            end, matches)
        end,
    })
    vim.api.nvim_create_user_command("SanityStack", M.sanity_stack, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityStackNext", function() M.stack_next() end, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityStackPrev", function() M.stack_prev() end, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityDiagnostics", M.toggle_diagnostics, { nargs = "?" })
    vim.api.nvim_create_user_command("SanityFilter", M.filter_errors, {
        nargs = "*",
        complete = function()
            local items = Q.get_available_kinds()
            for name, _ in pairs(Q.filter_presets) do
                table.insert(items, name)
            end
            table.sort(items)
            return items
        end,
    })
    vim.api.nvim_create_user_command("SanityClearFilter", M.clear_filter, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityRelated", M.show_related, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityExplain", M.explain_error, { nargs = 0 })
    vim.api.nvim_create_user_command("SanitySuppress", M.suppress_error, { nargs = 0 })
    vim.api.nvim_create_user_command("SanitySaveSuppressions", M.save_suppressions, {
        nargs = "?",
        complete = "file",
    })
    vim.api.nvim_create_user_command("SanityAuditSuppressions", M.audit_suppressions, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityExport", M.export_errors, {
        nargs = "?",
        complete = "file",
    })
    vim.api.nvim_create_user_command("SanityDebug", M.debug_error, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityDiff", M.show_diff, { nargs = 0 })
    vim.api.nvim_create_user_command("SanityWatch", M.watch_toggle, {
        nargs = "?",
        complete = function() return { "on", "off" } end,
    })

    -- Refresh diagnostic columns when a source file is opened.
    vim.api.nvim_create_autocmd("BufReadPost", {
        group = vim.api.nvim_create_augroup("sanity", { clear = true }),
        callback = function(ev)
            if #S.errors > 0 and S.config.diagnostics_enabled then
                Q.set_diagnostics(ev.buf)
            end
        end,
    })

    -- Store keymap config; keymaps are registered on first log load.
    S.config.keymaps = opts.keymaps or {}
end

M.filter_errors = function(args)
    if args.args == "" then
        local kinds = Q.get_available_kinds()
        if #kinds == 0 then
            vim.notify("No errors loaded.", vim.log.levels.INFO)
            return
        end
        local preset_names = {}
        for name, _ in pairs(Q.filter_presets) do
            table.insert(preset_names, name)
        end
        table.sort(preset_names)
        local msg = "Available kinds: " .. table.concat(kinds, ", ")
            .. "\nPresets: " .. table.concat(preset_names, ", ")
        if S.current_filter then
            msg = msg .. "\nCurrent filter: " .. table.concat(S.current_filter, ", ")
        end
        vim.notify(msg, vim.log.levels.INFO)
        return
    end

    local raw_args = {}
    for token in args.args:gmatch("%S+") do
        table.insert(raw_args, token)
    end
    local filter_kinds = Q.expand_filter_args(raw_args)
    if #filter_kinds == 0 then return end
    S.current_filter = filter_kinds
    Q.populate_quickfix_from_errors()
    Q.set_diagnostics()
    vim.notify("Filter set: " .. table.concat(filter_kinds, ", "), vim.log.levels.INFO)
end

M.clear_filter = function()
    if not S.current_filter then
        vim.notify("No filter active.", vim.log.levels.INFO)
        return
    end
    S.current_filter = nil
    Q.populate_quickfix_from_errors()
    Q.set_diagnostics()
    vim.notify("Filter cleared.", vim.log.levels.INFO)
end

M.toggle_diagnostics = function(args)
    local arg = args.args
    if arg == "on" then
        S.config.diagnostics_enabled = true
        Q.set_diagnostics()
    elseif arg == "off" then
        S.config.diagnostics_enabled = false
        vim.diagnostic.reset(S.ns)
    else
        S.config.diagnostics_enabled = not S.config.diagnostics_enabled
        if S.config.diagnostics_enabled then
            Q.set_diagnostics()
        else
            vim.diagnostic.reset(S.ns)
        end
    end
end

M.parse_valgrind_xml = P.parse_valgrind_xml
M.parse_sanitizer_log = P.parse_sanitizer_log
M.parse_ubsan_log = P.parse_ubsan_log

M.run_valgrind = function(args)
    if S.valgrind_job_id then
        vim.fn.jobstop(S.valgrind_job_id)
        S.valgrind_job_id = nil
    end
    if S.valgrind_xml_file then
        vim.fn.delete(S.valgrind_xml_file)
        S.valgrind_xml_file = nil
    end
    S.valgrind_generation = S.valgrind_generation + 1
    local generation = S.valgrind_generation
    S.last_valgrind_args = args.args
    local xml_file = vim.fn.tempname()
    S.valgrind_xml_file = xml_file
    local cmd = { "valgrind", "--num-callers=500", "--xml=yes", "--xml-file=" .. xml_file }
    for _, supp_path in ipairs(S.config.valgrind_suppressions) do
        table.insert(cmd, "--suppressions=" .. supp_path)
    end
    for _, a in ipairs(vim.split(args.args, "%s+", { trimempty = true })) do
        table.insert(cmd, a)
    end
    vim.notify("Running valgrind...", vim.log.levels.INFO)
    local stderr_lines = {}
    local job_id = vim.fn.jobstart(cmd, {
        on_stderr = function(_, data)
            for _, line in ipairs(data) do
                if line ~= "" then
                    table.insert(stderr_lines, line)
                end
            end
        end,
        on_exit = function(_, code)
            S.valgrind_job_id = nil
            vim.schedule(function()
                -- Discard result if a newer run or reset has occurred.
                if generation ~= S.valgrind_generation then
                    return
                end

                -- Clear the tracked file before loading so that reset_state()
                -- (called inside valgrind_load_xml) does not delete the file
                -- we are about to parse.
                S.valgrind_xml_file = nil

                if vim.fn.filereadable(xml_file) ~= 1 then
                    local msg = "Valgrind did not produce output (exit code " .. code .. ")."
                    if code == 127 then
                        msg = "Command not found (exit code 127). Check that valgrind and the target program are installed and on PATH."
                    elseif code == 126 then
                        msg = "Permission denied (exit code 126). Check that the target program is executable."
                    end
                    if #stderr_lines > 0 then
                        msg = msg .. "\n" .. table.concat(stderr_lines, "\n")
                    end
                    vim.notify(msg, vim.log.levels.ERROR)
                    vim.fn.delete(xml_file)
                    return
                end

                if code ~= 0 then
                    vim.notify("Valgrind exited with code " .. code, vim.log.levels.WARN)
                end
                vim.notify("Valgrind completed, loading results...", vim.log.levels.INFO)
                local ok, load_err = pcall(M.valgrind_load_xml, { args = xml_file })
                if not ok then
                    vim.notify("Failed to load valgrind XML: " .. tostring(load_err), vim.log.levels.ERROR)
                end
                vim.fn.delete(xml_file)

                -- Offer to re-run with --track-origins=yes for uninitialised value errors.
                -- Deferred so the scheduled cfirst from valgrind_load_xml runs
                -- first; otherwise it dismisses the vim.ui.select prompt.
                vim.schedule(function()
                    if S.config.track_origins == false then return end
                    if S.last_valgrind_args and S.last_valgrind_args:find("%-%-track%-origins") then return end
                    local has_uninit = false
                    for _, e in ipairs(S.errors) do
                        if e.kind == "UninitCondition" or e.kind == "UninitValue" then
                            has_uninit = true
                            break
                        end
                    end
                    if not has_uninit then return end
                    local rerun_args = "--track-origins=yes " .. S.last_valgrind_args
                    if S.config.track_origins == true then
                        M.run_valgrind({ args = rerun_args })
                    else
                        vim.ui.select({ "Yes", "No" }, {
                            prompt = "Uninitialised value errors found. Re-run with --track-origins=yes?",
                        }, function(choice)
                            if choice == "Yes" then
                                M.run_valgrind({ args = rerun_args })
                            end
                        end)
                    end
                end)
            end)
        end,
    })
    if job_id <= 0 then
        vim.notify("Failed to start valgrind.", vim.log.levels.ERROR)
        vim.fn.delete(xml_file)
        S.valgrind_xml_file = nil
        S.valgrind_generation = S.valgrind_generation + 1
    else
        S.valgrind_job_id = job_id
    end
end

-- Register keymaps on first log load.
local keymaps_registered = false
local function register_keymaps()
    if keymaps_registered then return end
    keymaps_registered = true
    local keymaps = S.config.keymaps or {}
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
    local explain_key = keymaps.explain
    if explain_key then
        vim.keymap.set("n", explain_key, M.explain_error, { desc = "Explain error at cursor" })
    end
    local related_key = keymaps.related
    if related_key then
        vim.keymap.set("n", related_key, M.show_related, { desc = "Jump to related error" })
    end
    local suppress_key = keymaps.suppress
    if suppress_key then
        vim.keymap.set("n", suppress_key, M.suppress_error, { desc = "Suppress error at cursor" })
    end
    local debug_key = keymaps.debug
    if debug_key then
        vim.keymap.set("n", debug_key, M.debug_error, { desc = "Debug error at cursor" })
    end
end

-- Restore fingerprints from a previous session's snapshot file.
-- Validates that every key is a string and every value is a number.
local function restore_snapshot()
    if not S.config.snapshot_file then return end
    if S.prev_error_fingerprints then return end
    local sf = io.open(S.config.snapshot_file, "r")
    if not sf then return end
    local content = sf:read("*a")
    sf:close()
    local ok, decoded = pcall(vim.json.decode, content)
    if not ok or type(decoded) ~= "table" then return end
    local valid = {}
    for k, v in pairs(decoded) do
        if type(k) == "string" and type(v) == "number" then
            valid[k] = v
        end
    end
    S.prev_error_fingerprints = valid
end

-- Save current fingerprints to the snapshot file atomically.
local function save_snapshot()
    if not S.config.snapshot_file then return end
    local fps = D.snapshot_fingerprints()
    local ok, encoded = pcall(vim.json.encode, fps)
    if not ok then return end
    local tmp_path = S.config.snapshot_file .. ".tmp"
    local sf = io.open(tmp_path, "w")
    if not sf then return end
    sf:write(encoded)
    sf:close()
    os.rename(tmp_path, S.config.snapshot_file)
end

-- Prepare diff state before a load: snapshot existing S.errors or restore from disk.
local function pre_load_diff()
    if S.has_loaded then
        S.prev_error_fingerprints = D.snapshot_fingerprints()
    else
        restore_snapshot()
    end
end

M.valgrind_load_xml = function(args)
    register_keymaps()
    local xml_file = args.args
    pre_load_diff()
    S.reset_state()
    local num_errors = M.parse_valgrind_xml(xml_file)
    Q.populate_quickfix_from_errors()
    Q.set_diagnostics()
    -- Schedule cfirst so it runs after BufReadPost autocmds (e.g.
    -- last-position-jump) that would otherwise override the cursor.
    if #S.qf_error_ids > 0 then vim.schedule(function() vim.cmd("cfirst") end) end
    local msg = "Processed " .. num_errors .. " errors from '" .. xml_file .. "' into " .. #S.qf_error_ids .. " locations."
    local diff = D.compute_diff_summary()
    if diff then msg = msg .. diff end
    S.has_loaded = true
    save_snapshot()
    vim.notify(msg)
end

local function load_files(filepaths)
    register_keymaps()
    pre_load_diff()
    S.reset_state()
    for _, filepath in ipairs(filepaths) do
        local format = P.detect_log_format(filepath)
        if format == "valgrind_xml" then
            M.parse_valgrind_xml(filepath)
            vim.notify("Parsed valgrind XML: " .. filepath)
        elseif format == "sanitizer_log" then
            M.parse_sanitizer_log(filepath)
            vim.notify("Parsed sanitizer log: " .. filepath)
        elseif format == "ubsan_log" then
            M.parse_ubsan_log(filepath)
            vim.notify("Parsed UBSAN log: " .. filepath)
        end
    end
    Q.populate_quickfix_from_errors()
    Q.set_diagnostics()
    -- Schedule cfirst so it runs after BufReadPost autocmds (e.g.
    -- last-position-jump) that would otherwise override the cursor.
    if #S.qf_error_ids > 0 then vim.schedule(function() vim.cmd("cfirst") end) end
    local msg = "Loaded " .. #S.errors .. " errors into " .. #S.qf_error_ids .. " quickfix entries."
    local diff = D.compute_diff_summary()
    if diff then msg = msg .. diff end
    S.has_loaded = true
    S.last_loaded_files = filepaths
    -- Restart watchers if watch mode is active so they track the new files.
    if #S.watchers > 0 then
        stop_watching()
        start_watching(S.last_loaded_files)
    end
    save_snapshot()
    vim.notify(msg)
end

-- Stack frame navigation.

-- Local aliases for navigate functions used by thin wrappers below.
local get_error_at_cursor = N.get_error_at_cursor
local get_current_position = N.get_current_position
local is_source_window = N.is_source_window
local find_source_win = N.find_source_win

M.stack_next = function()
    N.navigate_stack(-1, STK.refresh_stack)
end

M.stack_prev = function()
    N.navigate_stack(1, STK.refresh_stack)
end

M.sanity_stack = function() STK.sanity_stack() end

-- Show a floating window with the given title and content lines.
local show_floating_window = UI.show_floating_window

-- SanitySuppress: queue a suppression for the error at cursor.
M.suppress_error = function()
    local err = get_error_at_cursor()
    if not err then
        vim.notify("No error at cursor.", vim.log.levels.WARN)
        return
    end
    local text, tool_or_reason = SUP.generate_suppression(err)
    if not text then
        vim.notify(tool_or_reason, vim.log.levels.WARN)
        return
    end
    table.insert(S.suppressions, { text = text, tool = tool_or_reason })
    vim.notify("Suppression queued (" .. #S.suppressions .. " total).")
end

M.save_suppressions = function(args) SUP.save_suppressions(args) end

M.audit_suppressions = function()
    SUP.audit_suppressions(show_floating_window)
end

M.export_errors = function(args) UI.export_errors(args) end
M.show_diff = function() UI.show_diff() end

M.explain_error = function()
    UI.explain_error(get_error_at_cursor)
end

M.debug_error = function()
    UI.debug_error({
        get_error_at_cursor = get_error_at_cursor,
        get_current_position = get_current_position,
        is_source_window = is_source_window,
        find_source_win = find_source_win,
    })
end

M.show_related = function()
    N.show_related(STK.refresh_stack)
end

-- Close all active file watchers.
stop_watching = function()
    if S.watch_timer then
        S.watch_timer:stop()
        S.watch_timer:close()
        S.watch_timer = nil
    end
    for _, w in ipairs(S.watchers) do
        w:stop()
        w:close()
    end
    S.watchers = {}
end

-- Start watching the given file paths for changes.
start_watching = function(files)
    -- Create a single shared debounce timer for all watched files.
    if not S.watch_timer then
        S.watch_timer = vim.uv.new_timer()
    end

    for _, filepath in ipairs(files) do
        local handle = vim.uv.new_fs_event()
        if handle then
            local ok, start_err = handle:start(filepath, {}, function(err)
                if err then return end
                -- Debounce: restart the shared timer on each change event.
                vim.schedule(function()
                    if not S.watch_timer then return end
                    S.watch_timer:stop()
                    S.watch_timer:start(100, 0, vim.schedule_wrap(function()
                        load_files(S.last_loaded_files)
                    end))
                end)
            end)
            if ok == 0 then
                table.insert(S.watchers, handle)
            else
                handle:close()
                vim.notify("Failed to watch: " .. filepath .. " (" .. tostring(start_err) .. ")",
                    vim.log.levels.WARN)
            end
        end
    end
end

-- SanityWatch: toggle file-system watchers that reload on changes.
M.watch_toggle = function(args)
    local arg = args and args.fargs and args.fargs[1]
    local want_on
    if arg == "on" then
        want_on = true
    elseif arg == "off" then
        want_on = false
    else
        want_on = #S.watchers == 0
    end

    if not want_on then
        stop_watching()
        vim.notify("Watch mode off.", vim.log.levels.INFO)
        return
    end

    if #S.last_loaded_files == 0 then
        vim.notify("No files loaded. Load files first with :SanityLoadLog.", vim.log.levels.WARN)
        return
    end

    stop_watching()
    start_watching(S.last_loaded_files)

    local names = {}
    for _, f in ipairs(S.last_loaded_files) do
        table.insert(names, vim.fn.fnamemodify(f, ":t"))
    end
    vim.notify("Watching: " .. table.concat(names, ", "), vim.log.levels.INFO)
end

M.sanity_load_log = function(args)
    local filepaths = args.fargs
    if #filepaths == 0 then
        pickers.pick_files(S.config.picker, load_files)
        return
    end
    load_files(filepaths)
end

-- Expose internals for testing behind a single table.
M._test = {
  new_error = Q.new_error,
  reset_state = S.reset_state,
  build_stack_content = STK.build_stack_content,
  strip_label = STK.strip_label,
  find_related_targets = N.find_related_targets,
  generate_suppression = SUP.generate_suppression,
  errors = function() return S.errors end,
  location_index = function() return S.location_index end,
  error_fingerprint = D.error_fingerprint,
  snapshot_fingerprints = D.snapshot_fingerprints,
  compute_diff_summary = function() return D.compute_diff_summary() end,
  compute_diff_details = function() return D.compute_diff_details() end,
  set_prev_fingerprints = function(fps) S.prev_error_fingerprints = fps; S.has_loaded = fps ~= nil end,
  detect_log_format = P.detect_log_format,
  parse_section_header = P.parse_section_header,
  parse_frame_line = P.parse_frame_line,
  parse_suppression_names = SUP.parse_suppression_names,
  parse_sanitizer_suppression_names = SUP.parse_sanitizer_suppression_names,
  get_available_kinds = Q.get_available_kinds,
  expand_filter_args = Q.expand_filter_args,
  matches_filter = Q.matches_filter,
  set_filter = function(f) S.current_filter = f end,
  format_link_set = F.format_link_set,
  format_valgrind_group = F.format_valgrind_group,
  format_sanitizer_group = F.format_sanitizer_group,
  starts_with = F.starts_with,
  summarize_rw = F.summarize_rw,
  summarize_table_keys = F.summarize_table_keys,
  merge_meta_sets = F.merge_meta_sets,
  load_files = load_files,
  populate_quickfix = Q.populate_quickfix_from_errors,
  get_qf_type = Q.get_qf_type,
  compute_sharing_ratio = STK.compute_sharing_ratio,
  normalize_path = F.normalize_path,
  resolve_path = F.resolve_path,
  set_config = function(key, val) S.config[key] = val end,
  restore_snapshot = restore_snapshot,
  save_snapshot = save_snapshot,
}
return M

-- Shared mutable state for all sanity sub-modules.
-- Lua's require caching ensures every module gets the same table reference.
local S = {}

S.config = {}

-- Structured error storage.
S.errors = {}
S.errors_by_id = {}
S.error_id_counter = 0
S.location_index = {}  -- "file:line" -> { error_id, ... }
S.qf_error_ids = {}    -- qf index -> { error_id, ... }
S.qf_file_lines = {}   -- qf index -> { file, line } using normalized paths
S.current_filter = nil  -- Array of kind strings when active.
S.suppressions = {}     -- Queued suppression entries: { text, tool }.
S.valgrind_job_id = nil  -- Active async valgrind job.
S.last_valgrind_args = nil  -- Raw args string from last :SanityRunValgrind.
S.valgrind_xml_file = nil -- Temp XML file for the active job.
S.valgrind_generation = 0 -- Counter to detect stale async callbacks.
S.suppression_counts = {}  -- name -> count from last valgrind XML run.
S.prev_error_fingerprints = nil  -- Fingerprint bag from previous load for diff summary (nil = no previous load).
S.has_loaded = false  -- Whether at least one load has completed.
S.last_loaded_files = {}  -- Paths from the last load_files call.
S.watchers = {}  -- Active vim.uv.new_fs_event handles.
S.watch_timer = nil  -- Debounce timer for watch mode reloads.

S.ns = vim.api.nvim_create_namespace("sanity")

-- Stack explorer state.
S.stack_bufnr = nil       -- Track the stack split buffer for toggling.
S.stack_frame_map = nil   -- buf line number (1-based) -> { file, line }
S.stack_win = nil         -- The stack split window.
S.stack_preview_win = nil -- The source/preview window.
S.stack_last_key = nil    -- "file:line" key to avoid redundant refreshes.
S.stack_augroup = nil     -- Augroup for source-tracking autocmd.
S.stack_last_preview = "" -- Preview dedup key.
S.stack_preview_ns = vim.api.nvim_create_namespace("sanity_stack_preview")
S.stack_hl_ns = vim.api.nvim_create_namespace("sanity_stack_hl")

function S.reset_state()
    S.errors = {}
    S.errors_by_id = {}
    S.error_id_counter = 0
    S.location_index = {}
    S.qf_error_ids = {}
    S.qf_file_lines = {}
    S.current_filter = nil
    S.suppressions = {}
    S.suppression_counts = {}
    if S.valgrind_job_id then
        vim.fn.jobstop(S.valgrind_job_id)
        S.valgrind_job_id = nil
    end
    if S.valgrind_xml_file then
        vim.fn.delete(S.valgrind_xml_file)
        S.valgrind_xml_file = nil
    end
    S.valgrind_generation = S.valgrind_generation + 1
    vim.diagnostic.reset(S.ns)
end

return S

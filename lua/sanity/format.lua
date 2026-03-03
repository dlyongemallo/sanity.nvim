-- Pure formatting helpers with no state mutation.
local F = {}

function F.starts_with(str, start)
    return str:sub(1, #start) == start
end

-- Normalise a file path so redundant slashes and relative segments
-- do not cause location_index misses.
function F.normalize_path(path)
    return vim.fs.normalize(path)
end

-- Resolve a possibly-relative path to an absolute, normalised form.
-- Uses fnamemodify(":p") which is cross-platform (handles Windows drive
-- letters, backslashes, etc.) and resolves relative paths against cwd.
function F.resolve_path(path)
    return F.normalize_path(vim.fn.fnamemodify(path, ":p"))
end

function F.summarize_rw(rw)
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

function F.summarize_table_keys(t, show_only_first_entry, sort_by_numeric_value)
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

-- Format a link set into a summary string.
-- Link sets contain entries like "->basename:000042" and "END".
function F.format_link_set(link_set)
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

-- Merge a set-valued meta field from multiple errors into one set.
function F.merge_meta_sets(errs, field)
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

-- Format a quickfix message for a group of valgrind errors with the same kind.
function F.format_valgrind_group(kind, errs, links)
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
            F.summarize_rw(rw_set),
            F.summarize_table_keys(size_set, false, true),
            F.summarize_table_keys(addr_set, true),
            F.summarize_table_keys(thr_set),
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
            F.summarize_table_keys(leak_type_set, false),
            F.summarize_table_keys(size_set2, true, true),
            F.summarize_table_keys(blocks_set, true, true),
            F.summarize_table_keys(loss_set, true, true),
            F.summarize_table_keys(total_set, false, true),
            links)
    end

    -- General errors.
    local msg = errs[1].message
    if F.starts_with(msg, kind) then
        msg = msg:sub(#kind + 1):match("^%s*(.*)")
    end
    return string.format("[%s] %s (%s)", kind, msg, links)
end

-- Format a quickfix message for a group of sanitizer errors with the same kind.
function F.format_sanitizer_group(kind, errs, links)
    -- rw_op errors (data race read/write).
    if errs[1].meta.rw_op then
        local rw_op_set = F.merge_meta_sets(errs, "rw_op")
        local size_set = F.merge_meta_sets(errs, "size")
        local addr_set = F.merge_meta_sets(errs, "addr")
        local thr_set = F.merge_meta_sets(errs, "thr")
        return string.format("[%s] %s of size %s at %s by thread %s (%s)",
            kind,
            F.summarize_table_keys(rw_op_set),
            F.summarize_table_keys(size_set, false, true),
            F.summarize_table_keys(addr_set, true),
            F.summarize_table_keys(thr_set),
            links)
    end

    -- Mutex creation.
    if errs[1].meta.mutex then
        local mutex_set = F.merge_meta_sets(errs, "mutex")
        return string.format("[%s] Mutex %s created (%s)",
            kind,
            F.summarize_table_keys(mutex_set),
            links)
    end

    -- Heap allocation.
    if errs[1].meta.heap_block then
        local size_set = F.merge_meta_sets(errs, "size")
        local addr_set = F.merge_meta_sets(errs, "addr")
        local thr_set = F.merge_meta_sets(errs, "thr")
        return string.format("[%s] Location is heap block of size %s at %s allocated by %s (%s)",
            kind,
            F.summarize_table_keys(size_set, false, true),
            F.summarize_table_keys(addr_set, true),
            F.summarize_table_keys(thr_set),
            links)
    end

    -- Leak errors.
    if errs[1].meta.leak_type then
        local leak_type_set = F.merge_meta_sets(errs, "leak_type")
        local size_set = F.merge_meta_sets(errs, "size")
        local num_objs_set = F.merge_meta_sets(errs, "num_objs")
        return string.format("[%s] %s leak of %s byte(s) in %s object(s) allocated from (%s)",
            kind,
            F.summarize_table_keys(leak_type_set),
            F.summarize_table_keys(size_set, false, true),
            F.summarize_table_keys(num_objs_set, false, true),
            links)
    end

    -- General errors.
    local msg = errs[1].message
    if F.starts_with(msg, kind) then
        msg = msg:sub(#kind + 1):match("^%s*(.*)")
    end
    return string.format("[%s] %s (%s)", kind, msg, links)
end

return F

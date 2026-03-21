-- Log format detection and parsers for valgrind XML, sanitizer, and UBSAN logs.
local S = require("sanity.state")
local F = require("sanity.format")
local Q = require("sanity.quickfix")

local P = {}

-- Unescape the five predefined XML entities.
local function xml_unescape(s)
    s = s:gsub("&lt;", "<")
    s = s:gsub("&gt;", ">")
    s = s:gsub("&amp;", "&")
    s = s:gsub("&quot;", '"')
    s = s:gsub("&apos;", "'")
    return s
end

-- Detect the format of a log file by reading the first few lines.
function P.detect_log_format(filepath)
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
        if line:match(": runtime error:") then
            f:close()
            return "ubsan_log"
        end
    end
    f:close()
    vim.notify("Unrecognised log format: " .. filepath, vim.log.levels.ERROR)
    return nil
end

-- Parse a valgrind XML file into structured error objects.
-- Uses a line-by-line state machine instead of a full XML library.
function P.parse_valgrind_xml(xml_file)
    local fh = io.open(xml_file, "r")
    if not fh then
        vim.notify("Failed to open XML file: " .. xml_file, vim.log.levels.ERROR)
        return 0
    end

    local cwd = vim.fn.getcwd()
    local num_errors = 0

    -- Element nesting stack (tag names).
    local name_stack = {}
    -- Per-error state.
    local err_kind = nil
    local err_message = nil
    local err_auxwhats = {}
    -- Per-frame state.
    local frame_ip = nil
    local frame_fn = nil
    local frame_dir = nil
    local frame_file = nil
    local frame_line = nil
    -- Per-stack state.
    local stack_frames = {}
    -- Per-error stacks.
    local err_stacks_raw = {}  -- { frames = { ... } } for each stack
    -- Per-suppcount pair state.
    local pair_name = nil
    local pair_count = nil

    -- Emit a completed error.
    local function emit_error()
        if not err_kind then return end
        local message = err_message or ""

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
            meta.leak_type = err_kind:match("^Leak_(.*)") or "unknown"
            meta.size = lsize
            meta.blocks = blocks
            meta.loss_record = loss_record
            meta.total_records = total_records
        end

        -- Build final stacks with labels from auxwhat.
        -- Use the raw stack index for auxwhat lookup so that filtered-out
        -- stacks don't shift the label mapping.
        local final_stacks = {}
        for raw_idx, raw_stack in ipairs(err_stacks_raw) do
            local frames = {}
            for _, f in ipairs(raw_stack.frames) do
                if f.dir and f.file and F.starts_with(f.dir, cwd) then
                    table.insert(frames, {
                        file = f.dir .. "/" .. f.file,
                        line = tonumber(f.line) or 1,
                        func = f.fn,
                    })
                end
            end
            if #frames > 0 then
                local label
                if raw_idx == 1 then
                    label = message
                elseif err_auxwhats[raw_idx - 1] then
                    label = err_auxwhats[raw_idx - 1]
                else
                    label = message
                end
                table.insert(final_stacks, { label = label, frames = frames })
            end
        end

        if #final_stacks > 0 then
            Q.new_error(err_kind, message, "valgrind", final_stacks, meta)
            num_errors = num_errors + 1
        end

        err_kind = nil
        err_message = nil
        err_auxwhats = {}
        err_stacks_raw = {}
    end

    -- Current parent element name.
    local function parent()
        return name_stack[#name_stack]
    end

    local ok, parse_err = pcall(function()
    for line in fh:lines() do
        -- Match self-closing tag (rare in valgrind XML, but handle it).
        local self_close = line:match("^%s*<(%w+)%s*/>%s*$")
        if self_close then
            goto xml_continue
        end

        -- Match opening tag.
        local open_tag = line:match("^%s*<(%w+)>%s*$")
        if open_tag then
            table.insert(name_stack, open_tag)
            goto xml_continue
        end

        -- Match closing tag.
        local close_tag = line:match("^%s*</(%w+)>%s*$")
        if close_tag then
            if close_tag == "frame" then
                table.insert(stack_frames, {
                    ip = frame_ip, fn = frame_fn,
                    dir = frame_dir, file = frame_file, line = frame_line,
                })
                frame_ip = nil
                frame_fn = nil
                frame_dir = nil
                frame_file = nil
                frame_line = nil
            elseif close_tag == "stack" then
                table.insert(err_stacks_raw, { frames = stack_frames })
                stack_frames = {}
            elseif close_tag == "error" then
                emit_error()
            elseif close_tag == "pair" then
                -- Suppression count pair.
                if pair_name and pair_count then
                    S.suppression_counts[pair_name] = tonumber(pair_count) or 0
                end
                pair_name = nil
                pair_count = nil
            end
            if #name_stack > 0 then
                table.remove(name_stack)
            end
            goto xml_continue
        end

        -- Match single-line leaf element: <tag>text</tag>
        local tag, text = line:match("^%s*<(%w+)>(.-)</(%w+)>%s*$")
        if tag and text then
            text = xml_unescape(text)
            -- Route based on nesting context.
            if parent() == "frame" then
                if tag == "ip" then frame_ip = text
                elseif tag == "fn" then frame_fn = text
                elseif tag == "dir" then frame_dir = text
                elseif tag == "file" then frame_file = text
                elseif tag == "line" then frame_line = text
                end
            elseif parent() == "error" then
                if tag == "kind" then err_kind = text
                elseif tag == "what" then err_message = text
                elseif tag == "auxwhat" then table.insert(err_auxwhats, text)
                end
            elseif parent() == "xwhat" then
                if tag == "text" then err_message = text end
            elseif parent() == "xauxwhat" then
                if tag == "text" then table.insert(err_auxwhats, text) end
            elseif parent() == "pair" then
                if tag == "name" then pair_name = text
                elseif tag == "count" then pair_count = text
                end
            end
            goto xml_continue
        end

        ::xml_continue::
    end
    end)
    fh:close()
    if not ok then
        vim.notify("Failed to parse XML: " .. tostring(parse_err), vim.log.levels.ERROR)
        return 0
    end

    return num_errors
end

-- Parse a sanitizer error/warning header line.
-- Returns (kind, message) or nil if the line is not a header.
function P.parse_section_header(line)
    local msg = string.match(line, "==%d+==ERROR: .*Sanitizer: (.*)")
        or string.match(line, "==%d+==WARNING: .*Sanitizer: (.*)")
        or string.match(line, "^WARNING: .*Sanitizer: (.*)")
    if not msg then return nil end
    -- Handle multi-word kinds like "data race (pid=...)" -> "data-race".
    local kind = msg:match("^(%S+%s%S+)%s+%(")
        or msg:match("^(%S+)") or "unknown"
    kind = kind:gsub("%s+", "-")
    return kind, msg
end

-- Parse a sanitizer stack frame line.
-- Returns a frame table { file, line, func } or nil if the line is not a
-- frame or the file is outside cwd.
function P.parse_frame_line(line, cwd)
    -- Extract function name (nil when unavailable).
    local func_name = line:match("#%d+ 0x%x+ in (%S+)")       -- ASAN format.
    if not func_name then
        func_name = line:match("#%d+ (%S+) /")                 -- TSAN format.
    end

    local target = string.match(line, "#%d+ 0x%x+ .* (.+)")   -- ASAN format.
    if not target then
        target = string.match(line, "#%d+ %S+ ([^%(]+)%s+%(") -- TSAN format.
    end
    if not target then return nil end
    target = F.resolve_path(target)
    if not F.starts_with(target, cwd) then return nil end
    -- Match file:line:col (clang/MSAN) or file:line (GCC).
    local filename, line_number = string.match(target, "(%S+):(%d+):%d+")
    if not filename then
        filename, line_number = string.match(target, "(%S+):(%d+)")
    end
    if not filename or not line_number then return nil end

    return {
        file = filename,
        line = tonumber(line_number),
        func = func_name,
    }
end

-- Parse a sanitizer log file into structured error objects.
function P.parse_sanitizer_log(log_file)
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

    -- Finalise the current stack section (if it has frames).
    local function finalize_stack()
        if #current_frames > 0 then
            table.insert(current_stacks, {
                label = current_label,
                frames = current_frames,
            })
            current_frames = {}
        end
    end

    -- Finalise the current error (if it has stacks).
    local function finalize_error()
        finalize_stack()
        if #current_stacks > 0 then
            Q.new_error(current_kind, current_message, "sanitizer", current_stacks, current_meta)
        end
        current_stacks = {}
        current_meta = {}
        current_label = ""
        current_frames = {}
        in_error = false
    end

    local ok, parse_err = pcall(function()
    for line in log_file_handle:lines() do
        if F.starts_with(line, "allocated by") then
            -- "allocated by" continues the current error as a new stack section.
            finalize_stack()
            current_label = last_addr .. " " .. line
            current_meta.heap_block = true
        elseif not F.starts_with(line, "    #") then
            -- Non-frame line: could be a new error or a section header within an error.
            local kind, msg = P.parse_section_header(line)
            if kind then
                -- New error starts.
                finalize_error()
                current_message = msg
                current_kind = kind
                current_label = msg
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
            local frame = P.parse_frame_line(line, cwd)
            if frame then
                table.insert(current_frames, frame)
                num_processed_lines = num_processed_lines + 1
            end
        end
    end
    end)
    log_file_handle:close()
    if not ok then
        vim.notify("Error parsing log: " .. tostring(parse_err), vim.log.levels.ERROR)
        return 0
    end

    -- Finalise the last error.
    finalize_error()

    return num_processed_lines
end

-- Parse a UndefinedBehaviourSanitizer log file into structured error objects.
-- UBSAN format: file:line:col: runtime error: message
-- Optionally followed by ASAN-style stack frames (#N 0xaddr in func file:line).
function P.parse_ubsan_log(log_file)
    local log_file_handle = io.open(log_file, "r")
    if not log_file_handle then
        vim.notify("Failed to read UBSAN log file: " .. log_file, vim.log.levels.ERROR)
        return 0
    end

    local cwd = vim.fn.getcwd()
    local num_errors = 0
    local current_file = nil
    local current_line_num = nil
    local current_kind = nil
    local current_message = nil
    local current_frames = {}

    -- Finalise the current error (if any).
    local function finalize_error()
        if not current_kind then return end
        local stacks = {}
        if #current_frames > 0 then
            table.insert(stacks, { label = current_message, frames = current_frames })
        elseif current_file and F.starts_with(current_file, cwd) then
            -- No stack frames; use the header location as a single-frame stack.
            table.insert(stacks, {
                label = current_message,
                frames = { { file = current_file, line = current_line_num, func = nil } },
            })
        end
        if #stacks > 0 then
            Q.new_error(current_kind, current_message, "sanitizer", stacks, {})
            num_errors = num_errors + 1
        end
        current_file = nil
        current_line_num = nil
        current_kind = nil
        current_message = nil
        current_frames = {}
    end

    local ok, parse_err = pcall(function()
    for line in log_file_handle:lines() do
        -- Match UBSAN error header: file:line:col: runtime error: message
        local file, lnum, msg = line:match("^(.+):(%d+):%d+: runtime error: (.+)$")
        if file and lnum and msg then
            finalize_error()
            current_file = F.resolve_path(file)
            current_line_num = tonumber(lnum)
            current_message = msg
            -- Derive kind by lowercasing, truncating at the first colon or comma,
            -- stripping trailing digits/punctuation, then converting spaces to hyphens
            -- (e.g. "signed integer overflow: ..." -> "signed-integer-overflow",
            --  "null pointer passed as argument 1, ..." -> "null-pointer-passed-as-argument").
            local kind_text = msg:match("^(.-)[:,%d]") or msg
            kind_text = kind_text:gsub("%s+$", ""):lower()
            current_kind = kind_text:gsub("%s+", "-")
        elseif current_kind and line:match("^%s+#%d+") then
            -- Stack frame line (ASAN-style).
            local frame = P.parse_frame_line(line, cwd)
            if frame then
                table.insert(current_frames, frame)
            end
        end
    end
    end)
    log_file_handle:close()
    if not ok then
        vim.notify("Error parsing UBSAN log: " .. tostring(parse_err), vim.log.levels.ERROR)
        return 0
    end

    finalize_error()
    return num_errors
end

return P

-- Fingerprinting and run-to-run diff logic.
local S = require("sanity.state")

local D = {}

-- Build a fingerprint for an error: kind + source + first frame location.
function D.error_fingerprint(err)
    local ff = ""
    if err.stacks and err.stacks[1] and err.stacks[1].frames and err.stacks[1].frames[1] then
        local f = err.stacks[1].frames[1]
        ff = f.file .. ":" .. f.line
    end
    return err.kind .. "\0" .. err.source .. "\0" .. ff
end

-- Snapshot the current error list as a fingerprint bag (multiset).
-- Each fingerprint maps to its occurrence count so that duplicate errors
-- are tracked individually rather than collapsed into a set.
function D.snapshot_fingerprints()
    local fps = {}
    for _, err in ipairs(S.errors) do
        local fp = D.error_fingerprint(err)
        fps[fp] = (fps[fp] or 0) + 1
    end
    return fps
end

-- Compare current errors against the previous fingerprint bag.
-- Returns a summary string or nil if there was no previous load.
function D.compute_diff_summary()
    if S.prev_error_fingerprints == nil then return nil end
    local new_fps = D.snapshot_fingerprints()
    local new_count = 0
    local fixed_count = 0
    local unchanged_count = 0
    -- Collect all fingerprints from both bags.
    local all_fps = {}
    for fp in pairs(new_fps) do all_fps[fp] = true end
    for fp in pairs(S.prev_error_fingerprints) do all_fps[fp] = true end
    for fp in pairs(all_fps) do
        local cur = new_fps[fp] or 0
        local prev = S.prev_error_fingerprints[fp] or 0
        local common = math.min(cur, prev)
        unchanged_count = unchanged_count + common
        new_count = new_count + (cur - common)
        fixed_count = fixed_count + (prev - common)
    end
    return string.format(" (%d new, %d fixed, %d unchanged)", new_count, fixed_count, unchanged_count)
end

-- Compute detailed per-error diff between current errors and the previous load.
-- Returns nil if there is no previous load. Otherwise returns a table with:
--   new       = list of current error objects not matched in the previous set
--   fixed     = list of { kind, source, location } for previous errors gone now
--   unchanged = list of current error objects matched in the previous set
function D.compute_diff_details()
    if S.prev_error_fingerprints == nil then return nil end

    -- Copy previous counts so we can decrement as we match.
    local prev_remaining = {}
    for fp, count in pairs(S.prev_error_fingerprints) do
        prev_remaining[fp] = count
    end

    local new_errors = {}
    local unchanged_errors = {}

    for _, err in ipairs(S.errors) do
        local fp = D.error_fingerprint(err)
        if prev_remaining[fp] and prev_remaining[fp] > 0 then
            prev_remaining[fp] = prev_remaining[fp] - 1
            table.insert(unchanged_errors, err)
        else
            table.insert(new_errors, err)
        end
    end

    -- Remaining previous fingerprints are errors that were fixed.
    local fixed_entries = {}
    for fp, count in pairs(prev_remaining) do
        if count > 0 then
            local kind, source, location = fp:match("^(.-)%z(.-)%z(.*)$")
            for _ = 1, count do
                table.insert(fixed_entries, {
                    kind = kind or "?",
                    source = source or "?",
                    location = location ~= "" and location or nil,
                })
            end
        end
    end

    return {
        new = new_errors,
        fixed = fixed_entries,
        unchanged = unchanged_errors,
    }
end

return D

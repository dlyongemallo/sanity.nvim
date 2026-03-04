-- Interactive stack split, trie rendering, and stack navigation.
local S = require("sanity.state")
local N = require("sanity.navigate")

local STK = {}

function STK.close_stack_split()
    if S.stack_augroup then
        vim.api.nvim_del_augroup_by_id(S.stack_augroup)
        S.stack_augroup = nil
    end
    if S.stack_bufnr and vim.api.nvim_buf_is_valid(S.stack_bufnr) then
        local wins = vim.fn.win_findbuf(S.stack_bufnr)
        for _, win in ipairs(wins) do
            vim.api.nvim_win_close(win, true)
        end
    end
    -- Clear preview highlights from all buffers.
    for _, b in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_is_valid(b) then
            vim.api.nvim_buf_clear_namespace(b, S.stack_preview_ns, 0, -1)
        end
    end
    S.stack_bufnr = nil
    S.stack_frame_map = nil
    S.stack_win = nil
    S.stack_preview_win = nil
    S.stack_last_key = nil
    S.stack_last_preview = ""
end

-- Find a suitable preview window, avoiding quickfix and stack buffer windows.
local function find_preview_win()
    local alt = vim.fn.win_getid(vim.fn.winnr("#"))
    if alt ~= 0 and vim.api.nvim_win_is_valid(alt) then
        local bt = vim.bo[vim.api.nvim_win_get_buf(alt)].buftype
        local bn = vim.api.nvim_win_get_buf(alt)
        if bt == "" and bn ~= S.stack_bufnr then
            return alt
        end
    end
    for _, win in ipairs(vim.api.nvim_tabpage_list_wins(0)) do
        local buf = vim.api.nvim_win_get_buf(win)
        if vim.bo[buf].buftype == "" and buf ~= S.stack_bufnr then
            return win
        end
    end
    return vim.api.nvim_get_current_win()
end

-- Strip leading whitespace and trailing colon from a stack label.
function STK.strip_label(label)
    if not label then return "" end
    local s = label:match("^%s*(.-)%s*$") or label
    s = s:gsub(":$", "")
    return s
end

-- Return a dedup key for a frame.
local function frame_key(frame)
    return frame.file .. ":" .. frame.line
end

-- Compute the fraction of frame locations shared between 2+ stacks.
-- Returns 0.0 when no frames are shared, 1.0 when all are shared.
function STK.compute_sharing_ratio(stacks)
    if #stacks < 2 then return 0 end
    local counts = {}  -- frame_key -> number of stacks containing it
    local total_unique = 0
    for _, stack in ipairs(stacks) do
        local seen = {}
        for _, frame in ipairs(stack.frames) do
            local key = frame_key(frame)
            if not seen[key] then
                seen[key] = true
                counts[key] = (counts[key] or 0) + 1
            end
        end
    end
    local shared = 0
    for _, c in pairs(counts) do
        total_unique = total_unique + 1
        if c >= 2 then shared = shared + 1 end
    end
    if total_unique == 0 then return 0 end
    return shared / total_unique
end

-- Deduplicate stacks by frame sequence.
local function dedup_stacks(stacks)
    local seen = {}
    local out = {}
    for _, stack in ipairs(stacks) do
        local parts = {}
        for _, frame in ipairs(stack.frames) do
            table.insert(parts, frame_key(frame))
        end
        local fp = table.concat(parts, "\0")
        if not seen[fp] then
            seen[fp] = true
            table.insert(out, stack)
        end
    end
    return out
end

-- Compose thread-aware stacks for sanitizer errors.  Operation stacks
-- ("by thread T1") are concatenated with the corresponding creation stacks
-- ("Thread T1 ... created") so the trie can merge shared callers.
local function compose_thread_stacks(all_stacks)
    -- Index creation stacks by thread ID.
    local creation_by_tid = {}  -- tid -> stack
    for _, stack in ipairs(all_stacks) do
        local tid = stack.label and stack.label:match("^%s*Thread (T%d+).*created")
        if tid then
            creation_by_tid[tid] = stack
        end
    end
    if not next(creation_by_tid) then return all_stacks end

    local used_creation = {}
    local out = {}
    for _, stack in ipairs(all_stacks) do
        -- Skip creation stacks; they'll be inlined.
        if stack.label and stack.label:match("^%s*Thread T%d+.*created") then
            goto compose_continue
        end

        -- Check if this operation stack references a thread.
        local tid = stack.label and (
            stack.label:match("[Bb]y thread (T%d+)")
            or stack.label:match("[Ii]n thread (T%d+)")
        )
        local creation = tid and creation_by_tid[tid]
        if creation then
            used_creation[tid] = true
            -- Compose: operation frames ++ creation frames.
            local composed_frames = {}
            for _, f in ipairs(stack.frames) do
                table.insert(composed_frames, f)
            end
            local transition_idx = #composed_frames + 1
            for _, f in ipairs(creation.frames) do
                table.insert(composed_frames, f)
            end
            table.insert(out, {
                label = stack.label,
                frames = composed_frames,
                sub_labels = { [transition_idx] = creation.label },
            })
        else
            table.insert(out, stack)
        end
        ::compose_continue::
    end

    -- Pass through any creation stacks that were never consumed.
    for _, stack in ipairs(all_stacks) do
        local tid = stack.label and stack.label:match("^%s*Thread (T%d+).*created")
        if tid and not used_creation[tid] then
            table.insert(out, stack)
        end
    end

    return out
end

-- Build a trie from stacks reversed so shallowest frames (callers) come first.
-- Returns root node and a parallel structure for label/sub_label assignment.
local function build_call_trie(all_stacks)
    local root = { frame = nil, children = {}, children_by_key = {}, labels = {}, sub_labels = {} }

    -- Per-stack reversed frames and sub_label maps, used for label assignment.
    local stack_paths = {}

    for si, stack in ipairs(all_stacks) do
        local reversed = {}
        for i = #stack.frames, 1, -1 do
            table.insert(reversed, stack.frames[i])
        end

        -- Map sub_labels from original indices to reversed indices.
        local reversed_sub_labels = {}
        if stack.sub_labels then
            for idx, lbl in pairs(stack.sub_labels) do
                local rev_idx = #stack.frames - idx + 1
                reversed_sub_labels[rev_idx] = lbl
            end
        end

        local node = root
        local path_nodes = {}
        for i, frame in ipairs(reversed) do
            local key = frame_key(frame)
            local child = node.children_by_key[key]
            if not child then
                child = { frame = frame, children = {}, children_by_key = {}, labels = {}, sub_labels = {} }
                node.children_by_key[key] = child
                table.insert(node.children, child)
            end
            -- Attach sub_labels at the correct trie node, skipping duplicates.
            if reversed_sub_labels[i] then
                local dup = false
                for _, existing in ipairs(child.sub_labels) do
                    if existing == reversed_sub_labels[i] then dup = true; break end
                end
                if not dup then
                    table.insert(child.sub_labels, reversed_sub_labels[i])
                end
            end
            table.insert(path_nodes, child)
            node = child
        end
        stack_paths[si] = { reversed = reversed, nodes = path_nodes, label = stack.label }
    end

    -- Assign labels at divergence points: the first node whose parent has
    -- multiple children.  This places labels where branches split.
    for _, sp in ipairs(stack_paths) do
        local placed = false
        local parent = root
        for _, tnode in ipairs(sp.nodes) do
            if #parent.children > 1 then
                table.insert(tnode.labels, sp.label)
                placed = true
                break
            end
            parent = tnode
        end
        if not placed and #sp.nodes > 0 then
            -- No branching found; place label on the leaf.
            table.insert(sp.nodes[#sp.nodes].labels, sp.label)
        end
    end

    return root
end

local function factor_common_leaves(node)
    -- Walk past single-child prefix to reach the branching point.
    while #node.children == 1 do
        node = node.children[1]
    end
    if #node.children < 2 then return {} end

    -- Collect all leaf frame_keys from a subtree.
    local function collect_leaf_keys(n)
        if #n.children == 0 then
            return { [frame_key(n.frame)] = n.frame }
        end
        local keys = {}
        for _, c in ipairs(n.children) do
            for k, f in pairs(collect_leaf_keys(c)) do
                keys[k] = f
            end
        end
        return keys
    end

    -- Remove the first leaf matching key from a subtree.
    local function remove_leaf(n, key)
        for i, c in ipairs(n.children) do
            if #c.children == 0 and frame_key(c.frame) == key then
                table.remove(n.children, i)
                n.children_by_key[key] = nil
                return true
            end
            if remove_leaf(c, key) then return true end
        end
        return false
    end

    -- Iteratively extract leaf frames common to every non-leaf child.
    -- Each pass finds the current leaves, intersects across children that
    -- still have sub-trees, removes matches, and repeats.  Children that
    -- are themselves leaves (all callees already factored) are skipped so
    -- they don't block factoring of leaves shared by the remaining branches.
    local common_frames = {}
    while true do
        local leaf_sets = {}
        for _, child in ipairs(node.children) do
            if #child.children > 0 then
                table.insert(leaf_sets, collect_leaf_keys(child))
            end
        end
        if #leaf_sets < 2 then break end

        local batch = {}
        for key, frm in pairs(leaf_sets[1]) do
            local all_have = true
            for i = 2, #leaf_sets do
                if not leaf_sets[i][key] then
                    all_have = false
                    break
                end
            end
            if all_have then
                table.insert(batch, { key = key, frame = frm })
            end
        end

        if #batch == 0 then break end
        table.sort(batch, function(a, b) return a.key < b.key end)

        for _, entry in ipairs(batch) do
            table.insert(common_frames, entry.frame)
            for _, child in ipairs(node.children) do
                remove_leaf(child, entry.key)
            end
        end
    end

    return common_frames
end

-- Render the call trie with tree-drawing characters.
-- Output: deepest frames at top, shallowest at bottom.
local function render_call_trie(root, common_leaves, emit_frame, emit_label, fold_limit, emit_summary)
    -- UTF-8 tree-drawing characters.
    local TOP   = "\xe2\x94\x8c"  -- ┌
    local MID   = "\xe2\x94\x82"  -- │
    local BRANCH = "\xe2\x94\x9c" -- ├
    local BOT   = "\xe2\x94\x94"  -- └
    local CLOSE = "\xe2\x94\x98"  -- ┘
    local MERGE = "\xe2\x94\xb4"  -- ┴
    local HORIZ = "\xe2\x94\x80"  -- ─

    -- rails[d] = true when column d has an active vertical line.
    local rails = {}
    local max_depth = 0

    -- Compute max depth for common-leaf rendering.
    -- Linear chains (single-child paths) contribute depth 1 regardless of
    -- length, since they are rendered flat at the child column.
    local function find_max_depth(node, depth)
        if depth > max_depth then max_depth = depth end
        for _, child in ipairs(node.children) do
            local terminal = child
            while #terminal.children == 1 do
                terminal = terminal.children[1]
            end
            -- Chain from child..terminal collapses to depth+1.
            -- Recurse from terminal at that collapsed depth.
            find_max_depth(terminal, depth + 1)
        end
    end
    find_max_depth(root, -1)

    -- Build prefix string from rails state plus a character at each column.
    -- Pads to max_depth so labels with closing characters at deeper columns
    -- render correctly.  Frame callers rstrip the result to avoid excess
    -- trailing spaces when deeper rails are inactive.
    local function make_prefix(depth, self_char, closing)
        local parts = {}
        for d = 0, depth - 1 do
            table.insert(parts, rails[d] and MID or " ")
        end
        table.insert(parts, self_char)
        for d = depth + 1, max_depth do
            if closing and rails[d] then
                table.insert(parts, closing)
                rails[d] = false
            else
                table.insert(parts, rails[d] and MID or " ")
            end
        end
        return table.concat(parts)
    end

    -- Strip trailing spaces so frames at shallow depths are not padded
    -- out to max_depth when all deeper rails are inactive.
    local function rstrip(s)
        return (s:gsub(" +$", ""))
    end

    -- Depth of the deepest non-branching descendant from a node.
    -- Linear chains are collapsed, so single-child paths do not increase depth.
    local function get_leaf_depth(node, depth)
        if #node.children == 0 then return depth end
        if #node.children == 1 then
            local terminal = node.children[1]
            while #terminal.children == 1 do
                terminal = terminal.children[1]
            end
            if #terminal.children == 0 then return depth end
            return depth
        end
        return depth
    end

    -- Render common leaves at the top with ┌─ cap.
    -- common_leaf_rail tracks whether the visual rail from the cap is still
    -- active so that the first label line can close it with ┴ and subsequent
    -- labels use ─ as a horizontal connector.
    local common_leaf_rail = false
    if #common_leaves > 0 then
        local ld = max_depth + 1
        for i, frame in ipairs(common_leaves) do
            local parts = {}
            for _ = 1, ld do
                table.insert(parts, " ")
            end
            table.insert(parts, i == 1 and (TOP .. HORIZ) or (BRANCH .. HORIZ))
            emit_frame(table.concat(parts) .. " ", frame)
        end
        common_leaf_rail = true
    end

    -- Build prefix for label/sub_label lines.  When common leaves exist,
    -- inactive rail positions between the label column and the common-leaf
    -- column are filled with ─ so the line connects visually.
    local function make_label_prefix(depth, ch, closing)
        if #common_leaves == 0 then
            return make_prefix(depth, ch, closing)
        end
        local parts = {}
        for d = 0, depth - 1 do
            table.insert(parts, rails[d] and MID or " ")
        end
        table.insert(parts, ch)
        for d = depth + 1, max_depth do
            if closing and rails[d] then
                table.insert(parts, closing)
                rails[d] = false
            else
                table.insert(parts, rails[d] and MID or HORIZ)
            end
        end
        if common_leaf_rail then
            table.insert(parts, MERGE)
            common_leaf_rail = false
        else
            table.insert(parts, HORIZ)
        end
        return table.concat(parts)
    end

    -- Collect a linear chain starting from node.  Returns an array of trie
    -- nodes [node, node.children[1], ...] following single-child links, or
    -- nil when node has != 1 children (no chain to collapse).
    local function collect_chain(node)
        if #node.children ~= 1 then return nil end
        local chain = { node }
        local cursor = node.children[1]
        while #cursor.children == 1 do
            table.insert(chain, cursor)
            cursor = cursor.children[1]
        end
        table.insert(chain, cursor)  -- terminal: 0 or 2+ children
        return chain
    end

    -- Emit an interior chain frame at column cd.
    local function emit_interior_chain_frame(cframe, cd, depth)
        local ch
        if not rails[cd] then
            ch = TOP
            rails[cd] = true
        else
            ch = BRANCH
        end
        local has_deeper = false
        for d = cd + 1, max_depth do
            if rails[d] then has_deeper = true; break end
        end
        local pfx
        if has_deeper then
            pfx = make_prefix(cd, ch, CLOSE)
        else
            pfx = make_prefix(cd, ch, nil)
        end
        pfx = rstrip(pfx)
        emit_frame(pfx .. "  ", cframe)
    end

    -- Emit frames for a collapsed chain at column cd.  chain_frames is
    -- ordered deepest-first (output order).  emit_last handles the final
    -- frame (the child node from the parent's perspective) which may need
    -- special rail management.
    local function emit_chain_frames(chain_frames, cd, depth, emit_last)
        local nf = #chain_frames
        -- Fold long chains: show first 2, summary, last 1.
        -- Require nf > 3 so at least 1 frame is hidden (2 shown + 1 last).
        if fold_limit and fold_limit > 0 and nf > fold_limit and nf > 3 and emit_summary then
            -- First 2 interior frames.
            for fi = 1, 2 do
                emit_interior_chain_frame(chain_frames[fi], cd, depth)
            end
            -- Summary line for the hidden frames.
            local hidden = {}
            for fi = 3, nf - 1 do
                table.insert(hidden, chain_frames[fi])
            end
            local ch = BRANCH
            local pfx = make_prefix(cd, ch, nil)
            if depth < 0 then pfx = rstrip(pfx) end
            emit_summary(pfx, hidden, cd)
            -- Last frame (the child node).
            emit_last(chain_frames[nf])
            return
        end
        for fi, cframe in ipairs(chain_frames) do
            if fi == nf then
                emit_last(cframe)
            else
                emit_interior_chain_frame(cframe, cd, depth)
            end
        end
    end

    -- Inline DFS rendering.  For each child of a node:
    --   1. Emit labels (introduce the section) at the child's leaf depth.
    --   2. Recurse into subtree (deeper content), or emit collapsed chain.
    --   3. Emit sub_labels (transition from subtree) at the child's depth.
    --   4. Emit the child's frame at the child's depth.
    -- When a child starts a linear chain (single-child path), steps 2-4 are
    -- replaced by flat chain rendering at the child's depth column.
    local function render_node(node, depth)
        local n = #node.children
        for ci, child in ipairs(node.children) do
            local cd = depth + 1  -- child depth
            local is_last = (ci == n)
            -- Labels are emitted at the leaf depth so they sit next to the
            -- deepest callee frame rather than at the branch point.
            local ld = get_leaf_depth(child, cd)

            -- Determine whether this child is the effective last (final
            -- child and the parent has no sub_labels that would keep the
            -- rail open after it).
            local effective_last = is_last and #node.sub_labels == 0

            -- Detect linear chain: child -> ... -> terminal.
            local chain = collect_chain(child)
            if chain then
                -- Build output frames deepest-first, interleaving sub_labels.
                local terminal = chain[#chain]

                -- 1. Labels on child (entry node of chain).
                local label_closed_rail = false
                local chain_is_leaf = (#terminal.children == 0)
                for li, lbl in ipairs(child.labels) do
                    local ch
                    if effective_last and depth < 0 and li == #child.labels
                       and chain_is_leaf then
                        if rails[ld] then
                            ch = BOT
                            rails[ld] = false
                        else
                            ch = BOT
                        end
                        label_closed_rail = true
                    elseif not rails[ld] then
                        ch = TOP
                        rails[ld] = true
                    else
                        ch = BRANCH
                    end
                    emit_label(make_label_prefix(ld, ch, nil), STK.strip_label(lbl))
                end

                -- 2a. If terminal has children, recurse into its subtree
                --     at the collapsed depth.
                if #terminal.children > 0 then
                    render_node(terminal, cd)
                end

                -- 2b. Collect chain frames deepest-first with sub_labels.
                --     Chain nodes are [child, ..., terminal] (shallow to deep).
                --     Output order is deep to shallow.
                local chain_frames = {}
                for i = #chain, 1, -1 do
                    local cnode = chain[i]
                    -- Emit sub_labels for this chain node.
                    for _, sl in ipairs(cnode.sub_labels) do
                        local ch
                        if not rails[cd] then
                            ch = TOP
                            rails[cd] = true
                        else
                            ch = BRANCH
                        end
                        emit_label(make_label_prefix(cd, ch, MERGE), STK.strip_label(sl))
                    end
                    table.insert(chain_frames, cnode.frame)
                end

                -- 2c. Emit the chain frames.  The last frame (child) gets
                --     special handling based on effective_last.
                emit_chain_frames(chain_frames, cd, depth, function(cframe)
                    -- This is the child's frame (shallowest in chain).
                    if effective_last and label_closed_rail then
                        local open_parent = depth >= 0 and not rails[depth]
                        if open_parent then rails[depth] = true end
                        local parts = {}
                        for d = 0, max_depth do
                            if d == depth and open_parent then
                                table.insert(parts, TOP)
                            else
                                table.insert(parts, rails[d] and MID or " ")
                            end
                        end
                        emit_frame(table.concat(parts) .. "  ", cframe)
                    elseif effective_last then
                        if depth >= 0 and not rails[depth] then
                            rails[depth] = true
                            local parts = {}
                            for d = 0, depth - 1 do
                                table.insert(parts, rails[d] and MID or " ")
                            end
                            table.insert(parts, TOP)
                            table.insert(parts, CLOSE)
                            rails[cd] = false
                            for d = cd + 1, max_depth do
                                table.insert(parts, rails[d] and MID or " ")
                            end
                            emit_frame(table.concat(parts) .. "  ", cframe)
                        else
                            rails[cd] = false
                            emit_frame(rstrip(make_prefix(cd, BOT, CLOSE)) .. "  ", cframe)
                        end
                    else
                        local ch
                        if not rails[cd] then
                            ch = TOP
                            rails[cd] = true
                        else
                            ch = MID
                        end
                        local has_deeper = false
                        for d = cd + 1, max_depth do
                            if rails[d] then has_deeper = true; break end
                        end
                        local pfx
                        if has_deeper then
                            pfx = make_prefix(cd, ch, CLOSE)
                        else
                            pfx = make_prefix(cd, ch, nil)
                        end
                        if depth < 0 then pfx = rstrip(pfx) end
                        emit_frame(pfx .. "  ", cframe)
                    end
                end)
            else
                -- No chain: original rendering path.
                local label_closed_rail = false

                -- 1. Labels: introduce this branch's section.
                for li, lbl in ipairs(child.labels) do
                    local ch
                    if effective_last and depth < 0 and li == #child.labels
                       and #child.children == 0 then
                        if rails[ld] then
                            ch = BOT
                            rails[ld] = false
                        else
                            ch = BOT
                        end
                        label_closed_rail = true
                    elseif not rails[ld] then
                        ch = TOP
                        rails[ld] = true
                    else
                        ch = BRANCH
                    end
                    emit_label(make_label_prefix(ld, ch, nil), STK.strip_label(lbl))
                end

                -- 2. Recurse into subtree.
                render_node(child, cd)

                -- 3. Sub_labels: transition from deeper subtree.
                --    Close any deeper rails with ┴.
                for _, sl in ipairs(child.sub_labels) do
                    local ch
                    if not rails[cd] then
                        ch = TOP
                        rails[cd] = true
                    else
                        ch = BRANCH
                    end
                    emit_label(make_label_prefix(cd, ch, MERGE), STK.strip_label(sl))
                end

                -- 4. Emit the child's frame.
                if effective_last and label_closed_rail then
                    local open_parent = depth >= 0 and not rails[depth]
                    if open_parent then rails[depth] = true end
                    local parts = {}
                    for d = 0, max_depth do
                        if d == depth and open_parent then
                            table.insert(parts, TOP)
                        else
                            table.insert(parts, rails[d] and MID or " ")
                        end
                    end
                    emit_frame(table.concat(parts) .. "  ", child.frame)
                elseif effective_last then
                    local is_pass_through_branch =
                        (n == 1)
                        and (#child.children > 1)
                        and (#child.labels == 0)
                        and (#child.sub_labels == 0)
                    if depth >= 0 and not rails[depth] and not is_pass_through_branch then
                        rails[depth] = true
                        local parts = {}
                        for d = 0, depth - 1 do
                            table.insert(parts, rails[d] and MID or " ")
                        end
                        table.insert(parts, TOP)
                        table.insert(parts, CLOSE)
                        rails[cd] = false
                        for d = cd + 1, max_depth do
                            table.insert(parts, rails[d] and MID or " ")
                        end
                        emit_frame(table.concat(parts) .. "  ", child.frame)
                    else
                        if is_pass_through_branch and depth >= 0 then
                            local parts = {}
                            for d = 0, depth - 1 do
                                table.insert(parts, rails[d] and MID or " ")
                            end
                            table.insert(parts, TOP)
                            table.insert(parts, MERGE)
                            rails[depth] = true
                            rails[cd] = false
                            for d = cd + 1, max_depth do
                                table.insert(parts, rails[d] and MID or " ")
                            end
                            emit_frame(rstrip(table.concat(parts)) .. "  ", child.frame)
                        else
                            rails[cd] = false
                            emit_frame(rstrip(make_prefix(cd, BOT, CLOSE)) .. "  ", child.frame)
                        end
                    end
                else
                    local ch
                    if not rails[cd] then
                        ch = TOP
                        rails[cd] = true
                    else
                        ch = MID
                    end
                    local has_deeper = false
                    for d = cd + 1, max_depth do
                        if rails[d] then has_deeper = true; break end
                    end
                    if has_deeper then
                        local pfx = make_prefix(cd, ch, CLOSE)
                        if depth < 0 then pfx = rstrip(pfx) end
                        emit_frame(pfx .. "  ", child.frame)
                    else
                        local pfx = make_prefix(cd, ch, nil)
                        if depth < 0 then pfx = rstrip(pfx) end
                        emit_frame(pfx .. "  ", child.frame)
                    end
                end
            end
        end
    end

    render_node(root, -1)
end

-- Build the stack content lines and frame map for a given file:line.
-- When error_ids is provided (from quickfix), uses those directly instead of
-- looking up S.location_index, which avoids path-normalisation mismatches.
-- Returns buf_lines, frame_map, cursor_line or nil if no errors.
function STK.build_stack_content(file, line, error_ids)
    local ids = error_ids
    if not ids or #ids == 0 then
        ids = S.location_index[file .. ":" .. line]
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
        local err = N.get_error_by_id(queue[qi])
        qi = qi + 1
        if err then
            for _, stack in ipairs(err.stacks) do
                for _, frame in ipairs(stack.frames) do
                    local neighbours = S.location_index[frame.file .. ":" .. frame.line]
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
        local err = N.get_error_by_id(id)
        if err then table.insert(err_list, err) end
    end
    if #err_list == 0 then return nil end
    -- Sort by ID so the tree structure is stable regardless of which
    -- quickfix entry triggered the expansion.
    table.sort(err_list, function(a, b) return a.id < b.id end)

    local buf_lines = {}
    local frame_map = {}
    local preferred_ids = {}
    if error_ids and #error_ids > 0 then
        for _, id in ipairs(error_ids) do
            preferred_ids[id] = true
        end
    end
    local cursor_line_preferred = nil
    local cursor_line_fallback = nil
    local active_group_has_preferred = false
    local active_group_error_ids = nil

    local function format_frame(prefix, frame)
        local func_col = frame.func or "???"
        local basename = frame.file:match("[^/]+$") or frame.file
        return string.format("%s%-28s %s:%d", prefix, func_col, basename, frame.line)
    end

    local function emit_frame(prefix, frame)
        table.insert(buf_lines, format_frame(prefix, frame))
        frame_map[#buf_lines] = {
            file = frame.file,
            line = frame.line,
            prefix_bytes = #prefix,
            error_ids = active_group_error_ids,
        }
        if frame.file == file and frame.line == line then
            if active_group_has_preferred then
                if not cursor_line_preferred then
                    cursor_line_preferred = #buf_lines
                end
            elseif not cursor_line_fallback then
                cursor_line_fallback = #buf_lines
            end
        end
    end

    local function emit_label(prefix, text)
        table.insert(buf_lines, prefix .. " " .. text .. ":")
        frame_map[#buf_lines] = { prefix_bytes = #prefix + 1, error_ids = active_group_error_ids }
    end

    -- Emit a flat (single-stack) list of frames joined with tree chars.
    local function emit_flat(frames)
        local n = #frames
        for i, frame in ipairs(frames) do
            if i == 1 and n > 1 then
                emit_frame("\xe2\x94\x8c  ", frame)  -- ┌
            elseif i == n and n > 1 then
                emit_frame("\xe2\x94\x94  ", frame)  -- └
            elseif n > 1 then
                emit_frame("\xe2\x94\x9c  ", frame)  -- ├
            else
                emit_frame("   ", frame)
            end
        end
    end

    -- Emit multiple stacks as flat sections, annotating shared frames with *.
    local function emit_flat_sections(stacks, shared_keys)
        local TOP   = "\xe2\x94\x8c"  -- ┌
        local BRANCH = "\xe2\x94\x9c" -- ├
        local BOT   = "\xe2\x94\x94"  -- └
        for si, stack in ipairs(stacks) do
            if si > 1 then table.insert(buf_lines, "") end
            if stack.label then
                emit_label("", STK.strip_label(stack.label))
            end
            local nf = #stack.frames
            for i, fr in ipairs(stack.frames) do
                -- Emit sub_labels at the transition point.
                if stack.sub_labels and stack.sub_labels[i] then
                    emit_label("", STK.strip_label(stack.sub_labels[i]))
                end
                local ch
                if i == 1 and nf > 1 then ch = TOP
                elseif i == nf and nf > 1 then ch = BOT
                elseif nf > 1 then ch = BRANCH
                else ch = " " end
                local is_shared = shared_keys[frame_key(fr)]
                local func_col = fr.func or "???"
                local basename = fr.file:match("[^/]+$") or fr.file
                local prefix = ch .. "  "
                local rendered
                if is_shared then
                    rendered = string.format("%s%-27s* %s:%d", prefix, func_col, basename, fr.line)
                else
                    rendered = string.format("%s%-28s %s:%d", prefix, func_col, basename, fr.line)
                end
                table.insert(buf_lines, rendered)
                frame_map[#buf_lines] = {
                    file = fr.file,
                    line = fr.line,
                    prefix_bytes = #prefix,
                    error_ids = active_group_error_ids,
                }
                if fr.file == file and fr.line == line then
                    if active_group_has_preferred then
                        if not cursor_line_preferred then
                            cursor_line_preferred = #buf_lines
                        end
                    elseif not cursor_line_fallback then
                        cursor_line_fallback = #buf_lines
                    end
                end
            end
        end
    end

    -- Group S.errors by kind so same-kind errors are merged into one tree.
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
        active_group_error_ids = {}
        active_group_has_preferred = false
        for _, gerr in ipairs(group_errs) do
            table.insert(active_group_error_ids, gerr.id)
            if preferred_ids[gerr.id] then
                active_group_has_preferred = true
            end
        end

        if ki > 1 then table.insert(buf_lines, "") end

        local header = string.format("[%s] %s", kind, group_errs[1].message)
        if #group_errs > 1 then
            header = header .. string.format(" (+%d more)", #group_errs - 1)
        end
        table.insert(buf_lines, header)
        frame_map[#buf_lines] = { error_ids = active_group_error_ids }

        -- Pool all stacks, deduplicating by frame sequence.
        local raw_stacks = {}
        for _, err in ipairs(group_errs) do
            for _, stack in ipairs(err.stacks) do
                table.insert(raw_stacks, stack)
            end
        end
        local all_stacks = dedup_stacks(raw_stacks)

        if #all_stacks == 1 then
            -- Single unique stack: flat display.
            emit_flat(all_stacks[1].frames)
        else
            -- Compose thread-aware stacks, then dedup again.
            local composed = compose_thread_stacks(all_stacks)
            local deduped = dedup_stacks(composed)

            if #deduped == 1 then
                -- All stacks collapsed after composition: flat display.
                emit_flat(deduped[1].frames)
            elseif #deduped > 2 and STK.compute_sharing_ratio(deduped) < 0.3 then
                -- Low sharing: flat sections are clearer than a trie.
                -- Count how many stacks each frame_key appears in,
                -- deduplicating within each stack so recursive calls
                -- are not incorrectly marked as shared.
                local shared_keys = {}
                for _, st in ipairs(deduped) do
                    local seen = {}
                    for _, fr in ipairs(st.frames) do
                        local key = frame_key(fr)
                        if not seen[key] then
                            seen[key] = true
                            shared_keys[key] = (shared_keys[key] or 0) + 1
                        end
                    end
                end
                -- Keep only keys appearing in 2+ stacks.
                for key, cnt in pairs(shared_keys) do
                    if cnt < 2 then shared_keys[key] = nil end
                end
                emit_flat_sections(deduped, shared_keys)
            else
                local trie_root = build_call_trie(deduped)
                local common_leaves = factor_common_leaves(trie_root)
                local function emit_fold_summary(prefix, hidden_frames, cd)
                    local text = string.format("%s  ... (%d more)", prefix, #hidden_frames)
                    table.insert(buf_lines, text)
                    frame_map[#buf_lines] = {
                        prefix_bytes = #prefix,
                        error_ids = active_group_error_ids,
                        collapsed_frames = hidden_frames,
                    }
                end
                render_call_trie(trie_root, common_leaves, emit_frame, emit_label,
                    S.config.stack_fold_limit, emit_fold_summary)
            end
        end
    end

    return buf_lines, frame_map, cursor_line_preferred or cursor_line_fallback or 1
end

-- Apply syntax highlights to the stack buffer via extmarks.
local function highlight_stack_buf(buf, lines, fmap)
    vim.api.nvim_buf_clear_namespace(buf, S.stack_hl_ns, 0, -1)
    for i, line in ipairs(lines) do
        local row = i - 1
        local fi = fmap[i]
        if fi and fi.file then
            -- Frame line: prefix (tree chars) | function name | file:line.
            local pb = fi.prefix_bytes
            if pb > 0 then
                vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, 0, {
                    end_col = pb, hl_group = "NonText",
                })
            end
            -- Derive function field and location dynamically from the
            -- rendered line so long names (%-28s does not truncate) work.
            local loc_byte_idx1 = line:match("()%S+:%d+%s*$", pb + 1)
            local func_end_1b
            if loc_byte_idx1 and loc_byte_idx1 > (pb + 1) then
                func_end_1b = loc_byte_idx1 - 2
            else
                func_end_1b = #line
            end
            if func_end_1b >= (pb + 1) then
                local func_field = line:sub(pb + 1, func_end_1b)
                local trimmed = func_field:match("^(.-)%s*$") or func_field
                if #trimmed > 0 then
                    vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, pb, {
                        end_col = pb + #trimmed, hl_group = "Function",
                    })
                end
            end
            if loc_byte_idx1 then
                local loc_start = loc_byte_idx1 - 1
                if loc_start < #line then
                    vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, loc_start, {
                        end_col = #line, hl_group = "Directory",
                    })
                end
            end
        elseif line:match("^%[.-%]") then
            -- Header line: [Kind] message.
            vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, 0, {
                end_col = #line, hl_group = "Title",
            })
        elseif fi and fi.collapsed_frames then
            -- Collapsed chain summary line: highlight entirely as Comment.
            local pb = fi.prefix_bytes or 0
            if pb > 0 then
                vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, 0, {
                    end_col = pb, hl_group = "NonText",
                })
            end
            if pb < #line then
                vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, pb, {
                    end_col = #line, hl_group = "Comment",
                })
            end
        elseif fi then
            -- Label line: tree prefix then label text.
            local pb = fi.prefix_bytes
            if pb > 0 then
                vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, 0, {
                    end_col = pb, hl_group = "NonText",
                })
            end
            if pb < #line then
                vim.api.nvim_buf_set_extmark(buf, S.stack_hl_ns, row, pb, {
                    end_col = #line, hl_group = "Comment",
                })
            end
        end
    end
end

-- Refresh the stack buffer content for a new file:line position.
-- When there are no errors at the new position, keeps the last stack visible.
function STK.refresh_stack(file, line, error_ids)
    if not S.stack_bufnr or not vim.api.nvim_buf_is_valid(S.stack_bufnr) then return end

    local new_key = file .. ":" .. line
    if new_key == S.stack_last_key then return end

    local buf_lines, frame_map, cursor_line = STK.build_stack_content(file, line, error_ids)
    if not buf_lines then
        S.stack_last_key = new_key
        return
    end

    S.stack_last_key = new_key
    S.stack_frame_map = frame_map

    vim.bo[S.stack_bufnr].modifiable = true
    vim.api.nvim_buf_set_lines(S.stack_bufnr, 0, -1, false, buf_lines)
    vim.bo[S.stack_bufnr].modifiable = false
    highlight_stack_buf(S.stack_bufnr, buf_lines, frame_map)

    if S.stack_win and vim.api.nvim_win_is_valid(S.stack_win) then
        vim.api.nvim_win_set_height(S.stack_win, math.min(15, #buf_lines))
        vim.api.nvim_win_set_cursor(S.stack_win, { cursor_line, 0 })
    end

    -- Reset preview so the next CursorMoved triggers a fresh preview.
    S.stack_last_preview = ""
end

-- Expand a collapsed summary line in the stack buffer.
local function expand_collapsed_line(line_nr)
    if not S.stack_bufnr or not vim.api.nvim_buf_is_valid(S.stack_bufnr) then return end
    local info = S.stack_frame_map and S.stack_frame_map[line_nr]
    if not info or not info.collapsed_frames then return end

    local frames = info.collapsed_frames
    local error_ids = info.error_ids

    -- Reuse the prefix from the summary line (up to prefix_bytes).
    -- The summary line was rendered with the correct rail characters, so
    -- we extract that prefix and pad it for each expanded frame.
    local summary_text = vim.api.nvim_buf_get_lines(S.stack_bufnr, line_nr - 1, line_nr, false)[1] or ""
    local pb = info.prefix_bytes or 0
    local prefix = summary_text:sub(1, pb) .. "  "

    local expanded_lines = {}
    local expanded_entries = {}
    for _, fr in ipairs(frames) do
        local func_col = fr.func or "???"
        local basename = fr.file:match("[^/]+$") or fr.file
        local rendered = string.format("%s%-28s %s:%d", prefix, func_col, basename, fr.line)
        table.insert(expanded_lines, rendered)
        table.insert(expanded_entries, {
            file = fr.file,
            line = fr.line,
            prefix_bytes = #prefix,
            error_ids = error_ids,
        })
    end

    -- Replace the summary line with expanded lines.
    vim.bo[S.stack_bufnr].modifiable = true
    vim.api.nvim_buf_set_lines(S.stack_bufnr, line_nr - 1, line_nr, false, expanded_lines)
    vim.bo[S.stack_bufnr].modifiable = false

    -- Rebuild frame_map: replace the summary entry with expanded entries
    -- and shift everything after the insertion point.
    local shift = #expanded_lines - 1
    local new_map = {}
    for k, v in pairs(S.stack_frame_map) do
        if type(k) == "number" then
            if k < line_nr then
                new_map[k] = v
            elseif k == line_nr then
                -- This entry is replaced by the expanded entries.
                goto expand_continue
            else
                new_map[k + shift] = v
            end
        else
            new_map[k] = v
        end
        ::expand_continue::
    end
    -- Insert expanded entries.
    for i, entry in ipairs(expanded_entries) do
        new_map[line_nr + i - 1] = entry
    end
    S.stack_frame_map = new_map

    -- Re-highlight the buffer.
    local all_lines = vim.api.nvim_buf_get_lines(S.stack_bufnr, 0, -1, false)
    highlight_stack_buf(S.stack_bufnr, all_lines, S.stack_frame_map)
end

function STK.sanity_stack()
    -- Toggle off if already open.
    if S.stack_bufnr and vim.api.nvim_buf_is_valid(S.stack_bufnr) then
        local wins = vim.fn.win_findbuf(S.stack_bufnr)
        if #wins > 0 then
            STK.close_stack_split()
            return
        end
    end

    local file, line, error_ids = N.get_current_position()
    if not file or not line then
        vim.notify("No position to show stacks for.", vim.log.levels.WARN)
        return
    end

    local buf_lines, frame_map, cursor_line = STK.build_stack_content(file, line, error_ids)
    if not buf_lines then
        vim.notify("No errors at this line.", vim.log.levels.INFO)
        return
    end

    -- Find the preview window before creating the split.
    S.stack_preview_win = find_preview_win()

    -- Create the stack buffer.
    local buf = vim.api.nvim_create_buf(false, true)
    S.stack_bufnr = buf
    vim.bo[buf].buftype = "nofile"
    vim.bo[buf].bufhidden = "wipe"
    vim.bo[buf].swapfile = false
    vim.bo[buf].filetype = "sanity_stack"
    vim.api.nvim_buf_set_name(buf, "sanity_stack")

    -- Open a horizontal split at the bottom.
    local height = math.min(15, #buf_lines)
    vim.cmd("botright " .. height .. "split")
    S.stack_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_buf(S.stack_win, buf)
    vim.wo[S.stack_win].cursorline = true
    vim.wo[S.stack_win].number = false
    vim.wo[S.stack_win].relativenumber = false
    vim.wo[S.stack_win].signcolumn = "no"
    vim.wo[S.stack_win].winfixheight = true

    -- Set initial content.
    S.stack_frame_map = frame_map
    S.stack_last_key = file .. ":" .. line
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, buf_lines)
    vim.bo[buf].modifiable = false
    highlight_stack_buf(buf, buf_lines, frame_map)
    vim.api.nvim_win_set_cursor(S.stack_win, { cursor_line, 0 })

    -- Preview a frame in the source window.
    local function preview_frame(frame_info)
        local preview_key = frame_info.file .. ":" .. frame_info.line
        if preview_key == S.stack_last_preview then return end
        S.stack_last_preview = preview_key

        if not S.stack_preview_win or not vim.api.nvim_win_is_valid(S.stack_preview_win) then
            return
        end

        -- Open the file in the preview window.
        local cur_buf = vim.api.nvim_win_get_buf(S.stack_preview_win)
        local cur_name = vim.api.nvim_buf_get_name(cur_buf)
        if cur_name ~= frame_info.file then
            vim.api.nvim_win_call(S.stack_preview_win, function()
                vim.cmd("edit " .. vim.fn.fnameescape(frame_info.file))
            end)
        end

        -- Scroll to the line and centre it.
        local target_buf = vim.api.nvim_win_get_buf(S.stack_preview_win)
        local lc = vim.api.nvim_buf_line_count(target_buf)
        local target_line = math.min(frame_info.line, lc)
        vim.api.nvim_win_set_cursor(S.stack_preview_win, { target_line, 0 })
        vim.api.nvim_win_call(S.stack_preview_win, function()
            vim.cmd("normal! zz")
        end)

        -- Highlight the previewed line.
        vim.api.nvim_buf_clear_namespace(target_buf, S.stack_preview_ns, 0, -1)
        vim.api.nvim_buf_add_highlight(target_buf, S.stack_preview_ns, "CursorLine",
            target_line - 1, 0, -1)
    end

    -- Preview the initial frame.
    if S.stack_frame_map[cursor_line] and S.stack_frame_map[cursor_line].file then
        preview_frame(S.stack_frame_map[cursor_line])
    end

    -- CursorMoved autocmd on the stack buffer for live preview.
    -- nested = true so that :edit inside preview_frame triggers BufReadPost
    -- and FileType, which are needed for filetype detection and treesitter.
    vim.api.nvim_create_autocmd("CursorMoved", {
        buffer = buf,
        nested = true,
        callback = function()
            if not S.stack_win or not vim.api.nvim_win_is_valid(S.stack_win) then return end
            local cur = vim.api.nvim_win_get_cursor(S.stack_win)[1]
            local info = S.stack_frame_map and S.stack_frame_map[cur]
            if info and info.file then
                preview_frame(info)
            end
        end,
    })

    -- Source-tracking autocmd: refresh stack when cursor moves in other windows.
    -- Deferred via vim.schedule so buffer modifications happen outside the
    -- CursorMoved handler (avoids silent failures in special buffers like quickfix).
    S.stack_augroup = vim.api.nvim_create_augroup("sanity_stack_track", { clear = true })
    vim.api.nvim_create_autocmd("CursorMoved", {
        group = S.stack_augroup,
        callback = function()
            if vim.api.nvim_get_current_buf() == S.stack_bufnr then return end
            vim.schedule(function()
                local f, l, ids = N.get_current_position()
                if f and l then STK.refresh_stack(f, l, ids) end
            end)
        end,
    })

    -- Clean up when the stack buffer is wiped.
    vim.api.nvim_create_autocmd("BufWipeout", {
        buffer = buf,
        callback = function()
            STK.close_stack_split()
        end,
    })

    -- Helper: find next/previous frame line.
    local function jump_to_frame_line(direction)
        if not S.stack_win or not vim.api.nvim_win_is_valid(S.stack_win) then return end
        local cur = vim.api.nvim_win_get_cursor(S.stack_win)[1]
        local line_count = vim.api.nvim_buf_line_count(S.stack_bufnr)
        local target = cur + direction
        while target >= 1 and target <= line_count do
            if S.stack_frame_map and S.stack_frame_map[target] and S.stack_frame_map[target].file then
                vim.api.nvim_win_set_cursor(S.stack_win, { target, 0 })
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
        local pw = S.stack_preview_win
        STK.close_stack_split()
        if pw and vim.api.nvim_win_is_valid(pw) then
            vim.api.nvim_set_current_win(pw)
        end
    end
    vim.keymap.set("n", "q", close, kopts)
    vim.keymap.set("n", "<Esc>", close, kopts)

    -- Jump to frame under cursor.
    vim.keymap.set("n", "<CR>", function()
        if not S.stack_win or not vim.api.nvim_win_is_valid(S.stack_win) then return end
        local cur = vim.api.nvim_win_get_cursor(S.stack_win)[1]
        local info = S.stack_frame_map and S.stack_frame_map[cur]
        if not info or not info.file then return end
        local pw = S.stack_preview_win
        STK.close_stack_split()
        if pw and vim.api.nvim_win_is_valid(pw) then
            vim.api.nvim_set_current_win(pw)
            vim.cmd("edit " .. vim.fn.fnameescape(info.file))
            vim.api.nvim_win_set_cursor(pw, { info.line, 0 })
        end
    end, kopts)

    -- Navigate between frame lines.
    vim.keymap.set("n", "]s", function() jump_to_frame_line(1) end, kopts)
    vim.keymap.set("n", "[s", function() jump_to_frame_line(-1) end, kopts)

    -- Expand collapsed chain summary lines.
    vim.keymap.set("n", "<Tab>", function()
        if not S.stack_win or not vim.api.nvim_win_is_valid(S.stack_win) then return end
        local cur = vim.api.nvim_win_get_cursor(S.stack_win)[1]
        expand_collapsed_line(cur)
    end, kopts)
end

return STK

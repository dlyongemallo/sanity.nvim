local P = {}

-- File pickers: open a file browser filtered to log/xml/txt and call callback with paths.

local function pick_files_fzf_lua(callback)
    require("fzf-lua").files({
        prompt = "SanityLoadLog> ",
        fd_opts = "--type f --no-ignore -e xml -e log -e txt",
        rg_opts = "--files --no-ignore -g *.xml -g *.log -g *.txt",
        actions = {
            ["default"] = function(selected)
                local paths = {}
                for _, sel in ipairs(selected) do
                    table.insert(paths, require("fzf-lua.path").entry_to_file(sel).path)
                end
                callback(paths)
            end,
        },
    })
end

local function pick_files_telescope(callback)
    local actions = require("telescope.actions")
    local action_state = require("telescope.actions.state")
    require("telescope.builtin").find_files({
        prompt_title = "SanityLoadLog",
        no_ignore = true,
        find_command = { "fd", "--type", "f", "--no-ignore", "-e", "xml", "-e", "log", "-e", "txt" },
        attach_mappings = function(prompt_bufnr, _)
            actions.select_default:replace(function()
                local picker = action_state.get_current_picker(prompt_bufnr)
                local selections = picker:get_multi_selection()
                actions.close(prompt_bufnr)
                local paths = {}
                if #selections > 0 then
                    for _, entry in ipairs(selections) do
                        table.insert(paths, entry[1])
                    end
                else
                    local entry = action_state.get_selected_entry()
                    if entry then table.insert(paths, entry[1]) end
                end
                callback(paths)
            end)
            return true
        end,
    })
end

local function pick_files_mini_pick(callback)
    require("mini.pick").builtin.cli(
        { command = { "rg", "--files", "--no-follow", "--color=never", "--no-ignore",
                       "--glob", "*.xml", "--glob", "*.log", "--glob", "*.txt" } },
        {
            source = {
                name = "SanityLoadLog",
                choose = function(item)
                    if item then callback({ item }) end
                end,
                choose_marked = function(items)
                    if #items > 0 then callback(items) end
                end,
            },
        }
    )
end

local function pick_files_snacks(callback)
    require("snacks").picker.files({
        ft = { "xml", "log", "txt" },
        ignored = true,
        confirm = function(picker)
            picker:close()
            local items = picker:selected({ fallback = true })
            local paths = {}
            for _, item in ipairs(items) do
                if item.file then
                    table.insert(paths, item.file)
                end
            end
            if #paths > 0 then callback(paths) end
        end,
    })
end

local files_pickers = {
    ["fzf-lua"]   = { mod = "fzf-lua",   fn = pick_files_fzf_lua },
    ["telescope"] = { mod = "telescope",  fn = pick_files_telescope },
    ["mini.pick"] = { mod = "mini.pick",  fn = pick_files_mini_pick },
    ["snacks"]    = { mod = "snacks",     fn = pick_files_snacks },
}

function P.pick_files(picker_name, callback)
    if picker_name then
        local p = files_pickers[picker_name]
        if not p then
            vim.notify("SanityLoadLog: unknown picker '" .. picker_name .. "'", vim.log.levels.ERROR)
            return
        end
        local ok = pcall(require, p.mod)
        if not ok then
            vim.notify("SanityLoadLog: picker '" .. picker_name .. "' is not installed.", vim.log.levels.ERROR)
            return
        end
        p.fn(callback)
        return
    end
    -- Auto-detect in priority order.
    for _, name in ipairs({ "fzf-lua", "telescope", "mini.pick", "snacks" }) do
        local ok = pcall(require, files_pickers[name].mod)
        if ok then
            files_pickers[name].fn(callback)
            return
        end
    end
    vim.notify("SanityLoadLog: no picker available (install fzf-lua, telescope.nvim, mini.pick, or snacks.nvim)",
        vim.log.levels.ERROR)
end

return P

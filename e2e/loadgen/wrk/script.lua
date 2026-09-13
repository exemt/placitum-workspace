-- План пишет Node (wrk/plan.mjs) во временный .lua.
--   wrk -s script.lua http://haproxy:8080 -- /tmp/waf-wrk-plan.lua <rps> <threads> <conns>
--
-- Обычный wrk не знает -R: без delay() число в ступени становилось -c,
-- и 200 соединений били сильно выше 200 rps. delay() -- общий на поток
-- жетонный бакет: факт не выше плана, ниже -- если стенд не успевает.
--
-- response() считает коды и разбирает X-WAF-Debug модуля: вердикт, fail=,
-- сколько модуль ждал каждого инспектора. done() сливает потоки и печатает
-- одну строку `waf-summary: {...}` -- её читает wrk/parse.mjs.
--
-- Состояние потока -- только числа и ПЛОСКИЕ таблицы: thread:get() у wrk
-- 4.x на вложенной таблице падает с segfault, поэтому гистограммы
-- инспекторов лежат под ключом "имя:корзина", а не таблицей в таблице.

local plan
local pad_src = ""
local interval
local next_at = 0
local nconn = 0
local nthreads = 1
local target_rate = 0
local now_s
local threads = {}

-- Границы корзин гистограммы, мс. Квантиль -- верхняя граница корзины.
local BOUNDS = {
    1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 60, 80, 100, 125, 150,
    200, 250, 300, 400, 500, 600, 800, 1000, 1250, 1500, 2000, 2500, 3000,
    4000, 5000, 8000, 12000, 1e9,
}
local NBOUNDS = #BOUNDS

-- Ключи X-WAF-Debug, которые не инспекторы.
local NOT_INSPECTOR = {
    rid = true, ray = true, v = true, score = true, shadow = true, wave = true,
    by = true, fail = true, rewrite = true, body = true, headers = true, args = true,
}

do
    local ok, ffi = pcall(require, "ffi")
    if ok then
        ffi.cdef[[
            typedef long time_t;
            typedef int clockid_t;
            struct timespec { time_t tv_sec; long tv_nsec; };
            int clock_gettime(clockid_t clk_id, struct timespec *tp);
        ]]
        local ts = ffi.new("struct timespec")
        now_s = function()
            ffi.C.clock_gettime(1, ts)
            return tonumber(ts.tv_sec) + tonumber(ts.tv_nsec) * 1e-9
        end
    end
end

-- ---------------------------------------------------------------- состояние
-- Глобальные: done() читает их из каждого потока через thread:get().
id = 0
seq = 0
-- Счётчик запросов потока: по нему выбирается путь, когда их несколько.
nth = 0
codes = {}
unexpected = 0
seen = 0
verdicts = {}
fails = {}
none = 0
wait_n = 0
wait_sum = 0
wait_max = 0
wait_hist = {}
insp_n = {}
insp_sum = {}
insp_max = {}
insp_hist = {}
insp_deny = {}

local function bucket(ms)
    local i = 1
    while i < NBOUNDS and ms > BOUNDS[i] do
        i = i + 1
    end
    return i
end

-- ---------------------------------------------------------------- выбор
local function pick_pad(rows)
    if not rows or #rows == 0 then
        return 0
    end
    local total = 0
    for i = 1, #rows do
        total = total + rows[i].w
    end
    local n = math.random() * total
    local acc = 0
    for i = 1, #rows do
        acc = acc + rows[i].w
        if n < acc then
            return rows[i].bytes
        end
    end
    return rows[#rows].bytes
end

-- ---------------------------------------------------------------- адреса
local function ip4(n)
    return string.format("%d.%d.%d.%d",
        math.floor(n / 16777216) % 256,
        math.floor(n / 65536) % 256,
        math.floor(n / 256) % 256,
        n % 256)
end

-- Зарезервированное по RFC 6890: частные сети, loopback, link-local, CGNAT,
-- TEST-NET, бенчмарки, multicast и выше. Остальное -- «публичное».
local function reserved(n)
    local a = math.floor(n / 16777216) % 256
    local b = math.floor(n / 65536) % 256
    if a == 0 or a == 10 or a == 127 or a >= 224 then
        return true
    end
    if a == 100 and b >= 64 and b <= 127 then
        return true
    end
    if a == 169 and b == 254 then
        return true
    end
    if a == 172 and b >= 16 and b <= 31 then
        return true
    end
    if a == 192 and (b == 0 or b == 168) then
        return true
    end
    if a == 198 and (b == 18 or b == 19 or b == 51) then
        return true
    end
    if a == 203 and b == 0 then
        return true
    end
    return false
end

--[[
Обход списка вместо случайного адреса. Пул задан настоящими префиксами, из
которых кейс собрал списки инспектора; индекс идёт по порядку, поэтому прогон
повторяем. Поток начинает со своего смещения и шагает на число потоков, так что
вместе они обходят пул ровно один раз за круг.
]]
local walk_i = 0
local walk_total = 0

local function walk_ip()
    local rows = plan.ip_walk
    if not rows or #rows == 0 or walk_total == 0 then
        return nil
    end
    local n = walk_i % walk_total
    walk_i = walk_i + nthreads
    -- Адрес по глобальному индексу: префиксы идут подряд, как их дал кейс.
    for i = 1, #rows do
        if n < rows[i].size then
            return ip4(rows[i].base + n)
        end
        n = n - rows[i].size
    end
    return ip4(rows[1].base)
end

local function random_ip()
    if plan.ip_mode == "public" then
        local n
        repeat
            n = math.random(0, 4294967295)
        until not reserved(n)
        return ip4(n)
    end
    local pools = plan.ip_pools
    if not pools or #pools == 0 then
        return nil
    end
    local pool = pools[math.random(1, #pools)]
    -- без адреса сети и широковещательного
    local host = pool.size <= 2 and 0 or math.random(1, pool.size - 2)
    return ip4(pool.base + host)
end

-- ---------------------------------------------------------------- сборка
local function apply_args(path, bytes)
    local q = string.find(path, "?", 1, true)
    local base, query
    if q then
        base = string.sub(path, 1, q - 1)
        query = string.sub(path, q + 1)
    else
        base = path
        query = ""
    end
    if plan.unique then
        seq = seq + 1
        local tag = "_n=" .. id .. "-" .. seq
        query = (query ~= "" and (query .. "&") or "") .. tag
    end
    if bytes > 0 then
        local prefix = (query ~= "" and (query .. "&") or "") .. "_pad="
        local need = bytes - #prefix
        if need > 0 then
            query = prefix .. string.sub(pad_src, 1, need)
        end
    end
    if query == "" then
        return base
    end
    return base .. "?" .. query
end

local function apply_headers(bytes)
    local out = {}
    for k, v in pairs(plan.headers) do
        out[k] = v
    end
    local ip = walk_ip()
    if ip == nil and plan.ip_mode ~= "" then
        ip = random_ip()
    end
    if ip then
        out["X-Forwarded-For"] = ip
    end
    if bytes > 0 then
        out["X-Load-Pad"] = string.sub(pad_src, 1, bytes)
    end
    return out
end

local function has_body(method)
    return method == "POST" or method == "PUT" or method == "PATCH"
end

local function apply_body(method, bytes)
    if not has_body(method) then
        return nil
    end
    local src = plan.body or ""
    if bytes <= 0 then
        return src
    end
    -- JSON добирается полем _pad, форма -- параметром, прочее -- хвостом.
    local prefix, suffix
    if src == "" or src == "{}" then
        prefix = '{"_pad":"'
        suffix = '"}'
    elseif string.sub(src, -1) == "}" then
        prefix = string.sub(src, 1, -2) .. ',"_pad":"'
        suffix = '"}'
    elseif string.find(src, "=", 1, true) then
        prefix = src .. "&_pad="
        suffix = ""
    else
        prefix = src
        suffix = ""
    end
    local need = bytes - #prefix - #suffix
    if need < 0 then
        need = 0
    end
    return prefix .. string.sub(pad_src, 1, need) .. suffix
end

-- ---------------------------------------------------------------- wrk
function setup(thread)
    thread:set("id", #threads + 1)
    table.insert(threads, thread)
end

function delay()
    if interval == nil then
        return 0
    end
    if now_s then
        local now = now_s()
        if now < next_at then
            local wait_s = next_at - now
            next_at = next_at + interval
            return math.floor(wait_s * 1000)
        end
        next_at = now + interval
        return 0
    end
    if target_rate > 0 and nconn > 0 then
        return math.floor(1000 * nconn / target_rate)
    end
    return 0
end

function init(args)
    local path = args[1]
    if not path then
        error("wrk: нет пути к плану")
    end
    target_rate = tonumber(args[2]) or 0
    nthreads = tonumber(args[3]) or 1
    nconn = tonumber(args[4]) or 0
    if target_rate > 0 and nthreads > 0 then
        interval = nthreads / target_rate
    end
    plan = dofile(path)
    math.randomseed(os.time() * 1000 + id * 7919)
    walk_total = tonumber(plan.ip_walk_count) or 0
    if walk_total > 0 then
        local have = 0
        for i = 1, #plan.ip_walk do
            have = have + plan.ip_walk[i].size
        end
        if have < walk_total then
            walk_total = have
        end
        -- Своё смещение у каждого потока: вместе они идут по пулу без дыр.
        walk_i = (id - 1) % math.max(1, walk_total)
    end
    local need = 1024
    for _, key in ipairs({ "body_pads", "header_pads", "arg_pads" }) do
        local rows = plan[key] or {}
        for i = 1, #rows do
            if rows[i].bytes > need then
                need = rows[i].bytes
            end
        end
    end
    pad_src = string.rep("x", need)
end

function request()
    -- Путей может быть несколько: поток идёт по ним по кругу, поровну.
    local base = plan.path
    if plan.paths and #plan.paths > 0 then
        nth = nth + 1
        base = plan.paths[(nth % #plan.paths) + 1]
    end
    local path = apply_args(base, pick_pad(plan.arg_pads))
    local headers = apply_headers(pick_pad(plan.header_pads))
    local body = apply_body(plan.method, pick_pad(plan.body_pads))
    return wrk.format(plan.method, path, headers, body)
end

function response(status, headers)
    codes[status] = (codes[status] or 0) + 1
    if status ~= plan.expect then
        unexpected = unexpected + 1
    end
    local dbg = headers["X-WAF-Debug"] or headers["x-waf-debug"]
    if not dbg then
        return
    end
    seen = seen + 1
    local v = string.match(dbg, "^rid=%S+ ray=%S+ v=(%a+)")
    if v then
        verdicts[v] = (verdicts[v] or 0) + 1
    end
    local fail = string.match(dbg, " fail=([%w_]+)")
    if fail then
        fails[fail] = (fails[fail] or 0) + 1
    end
    local max_ms = -1
    for name, rest in string.gmatch(dbg, " ([%w_%-]+)=(%S+)") do
        if not NOT_INSPECTOR[name] then
            if rest == "none" then
                none = none + 1
            else
                local ms = string.match(rest, "/(%d+)ms")
                if ms then
                    local n = tonumber(ms)
                    insp_n[name] = (insp_n[name] or 0) + 1
                    -- Отказ этого инспектора: у кейса с несколькими маршрутами
                    -- общий счётчик вердиктов не говорит, который из них отказал.
                    if string.sub(rest, 1, 4) == "deny" then
                        insp_deny[name] = (insp_deny[name] or 0) + 1
                    end
                    insp_sum[name] = (insp_sum[name] or 0) + n
                    if n > (insp_max[name] or 0) then
                        insp_max[name] = n
                    end
                    local key = name .. ":" .. bucket(n)
                    insp_hist[key] = (insp_hist[key] or 0) + 1
                    if n > max_ms then
                        max_ms = n
                    end
                end
            end
        end
    end
    if max_ms >= 0 then
        wait_n = wait_n + 1
        wait_sum = wait_sum + max_ms
        if max_ms > wait_max then
            wait_max = max_ms
        end
        local b = bucket(max_ms)
        wait_hist[b] = (wait_hist[b] or 0) + 1
    end
end

-- ---------------------------------------------------------------- итог
local function new_stat()
    return { n = 0, sum = 0, max = 0, hist = {} }
end

local function quantile(stat, q)
    if stat.n == 0 then
        return nil
    end
    local want = q * stat.n
    local acc = 0
    for i = 1, NBOUNDS do
        acc = acc + (stat.hist[i] or 0)
        if acc >= want then
            if i == NBOUNDS then
                return stat.max
            end
            return BOUNDS[i]
        end
    end
    return stat.max
end

local function stat_out(stat)
    if stat.n == 0 then
        return nil
    end
    return {
        count = stat.n,
        avg = stat.sum / stat.n,
        p50 = quantile(stat, 0.5),
        p90 = quantile(stat, 0.9),
        p99 = quantile(stat, 0.99),
        max = stat.max,
    }
end

local function add_counts(into, from)
    for k, c in pairs(from or {}) do
        local key = tostring(k)
        into[key] = (into[key] or 0) + c
    end
end

local function json_str(s)
    s = string.gsub(s, '[%c"\\]', function(c)
        if c == '"' then return '\\"' end
        if c == "\\" then return "\\\\" end
        if c == "\n" then return "\\n" end
        if c == "\r" then return "\\r" end
        if c == "\t" then return "\\t" end
        return string.format("\\u%04x", string.byte(c))
    end)
    return '"' .. s .. '"'
end

local function json(v)
    local t = type(v)
    if v == nil then
        return "null"
    elseif t == "boolean" then
        return v and "true" or "false"
    elseif t == "number" then
        if v ~= v or v == math.huge or v == -math.huge then
            return "null"
        end
        if v == math.floor(v) and math.abs(v) < 1e15 then
            return string.format("%d", v)
        end
        return string.format("%.3f", v)
    elseif t == "string" then
        return json_str(v)
    elseif t == "table" then
        if #v > 0 then
            local parts = {}
            for i = 1, #v do
                parts[i] = json(v[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        end
        local keys = {}
        for k in pairs(v) do
            keys[#keys + 1] = tostring(k)
        end
        table.sort(keys)
        local parts = {}
        for _, k in ipairs(keys) do
            parts[#parts + 1] = json_str(k) .. ":" .. json(v[k])
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    return "null"
end

function done(summary, latency, requests)
    local all = {
        codes = {},
        unexpected = 0,
        seen = 0,
        verdicts = {},
        fails = {},
        none = 0,
        wait = new_stat(),
        insp = {},
    }
    for _, th in ipairs(threads) do
        add_counts(all.codes, th:get("codes"))
        add_counts(all.verdicts, th:get("verdicts"))
        add_counts(all.fails, th:get("fails"))
        all.unexpected = all.unexpected + (th:get("unexpected") or 0)
        all.seen = all.seen + (th:get("seen") or 0)
        all.none = all.none + (th:get("none") or 0)
        all.wait.n = all.wait.n + (th:get("wait_n") or 0)
        all.wait.sum = all.wait.sum + (th:get("wait_sum") or 0)
        local wmax = th:get("wait_max") or 0
        if wmax > all.wait.max then
            all.wait.max = wmax
        end
        for i, c in pairs(th:get("wait_hist") or {}) do
            all.wait.hist[i] = (all.wait.hist[i] or 0) + c
        end
        local n_by = th:get("insp_n") or {}
        local sum_by = th:get("insp_sum") or {}
        local max_by = th:get("insp_max") or {}
        local deny_by = th:get("insp_deny") or {}
        for name, n in pairs(n_by) do
            local stat = all.insp[name]
            if not stat then
                stat = new_stat()
                all.insp[name] = stat
            end
            stat.n = stat.n + n
            stat.sum = stat.sum + (sum_by[name] or 0)
            stat.deny = (stat.deny or 0) + (deny_by[name] or 0)
            if (max_by[name] or 0) > stat.max then
                stat.max = max_by[name]
            end
        end
        for key, c in pairs(th:get("insp_hist") or {}) do
            local name, i = string.match(key, "^(.*):(%d+)$")
            if name and all.insp[name] then
                i = tonumber(i)
                all.insp[name].hist[i] = (all.insp[name].hist[i] or 0) + c
            end
        end
    end
    local inspectors = {}
    local names = {}
    for name in pairs(all.insp) do
        names[#names + 1] = name
    end
    table.sort(names)
    for _, name in ipairs(names) do
        local row = stat_out(all.insp[name])
        row.name = name
        row.deny = all.insp[name].deny or 0
        inspectors[#inspectors + 1] = row
    end
    local out = {
        codes = all.codes,
        unexpected = all.unexpected,
        seen = all.seen,
        verdicts = all.verdicts,
        fails = all.fails,
        none = all.none,
        wait = stat_out(all.wait),
        inspectors = inspectors,
    }
    io.write("waf-summary: " .. json(out) .. "\n")
end

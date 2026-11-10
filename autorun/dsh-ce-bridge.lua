--[==[
  dsh-ce bridge  (mailbox 传输)
  ------------------------------------------------------------------
  在 Cheat Engine 内部挂一个定时器，轮询 %LOCALAPPDATA%\dsh-ce\mail\req，
  执行请求后把结果写到 res。外部工具（DSH 插件）用文件与它对话。

  为什么用文件而不是命名管道：CE 的 LuaPipe 在 readString/readBytes 上
  行为不稳定（读到 nil / 不消耗数据），而 createTimer 回调本身就运行在
  CE 主线程，天然线程安全。

  安装：把本文件复制到 %LOCALAPPDATA%\dsh-ce\bridge.lua，
        并在 Cheat Engine 安装目录的 main.lua 末尾加一行：
          pcall(dofile, [[C:\Users\<你>\AppData\Local\dsh-ce\bridge.lua]])
  手动：CE -> Table -> Show Cheat Table Lua Script -> 粘贴上面那行 -> Execute

  协议（纯文本，UTF-8，不用 JSON 解析器）：
    req 文件: "<id>\n<op>\n<body>"
    res 文件: "<id>\n<json>"
]==]

if _G.__DSH_CE_BRIDGE__ then return end
_G.__DSH_CE_BRIDGE__ = true

local BASE = (os.getenv('LOCALAPPDATA') or [[C:\]]) .. [[\dsh-ce]]
local MAILDIR = BASE .. [[\mail]]
local REQ = MAILDIR .. [[\req]]
local RES = MAILDIR .. [[\res]]
local ALIVE = MAILDIR .. [[\alive]]
local LOGFILE = BASE .. [[\bridge.log]]

os.execute('mkdir "' .. MAILDIR .. '" 2>nul')

local function log (msg)
  local f = io.open(LOGFILE, 'a')
  if not f then return end
  f:write(os.date('%H:%M:%S ') .. tostring(msg) .. '\n')
  f:close()
end

----------------------------------------------------------------------
-- JSON 编码
----------------------------------------------------------------------
local function jesc (s)
  return (s:gsub('[%c\\"]', function (c)
    if c == '"' then return '\\"' end
    if c == '\\' then return '\\\\' end
    if c == '\n' then return '\\n' end
    if c == '\r' then return '\\r' end
    if c == '\t' then return '\\t' end
    return string.format('\\u%04x', c:byte())
  end))
end

local function enc (v, depth)
  depth = depth or 0
  if depth > 12 then return '"<too deep>"' end
  if v == nil then return 'null' end
  local tv = type(v)
  if tv == 'boolean' then return v and 'true' or 'false' end
  if tv == 'number' then
    if math.type(v) == 'integer' then return string.format('%d', v) end
    -- CE 的 getCEVersion 之类返回 7.5999999999999996，%.17g 会原样带出去很难看；
    -- 浮点统一压到 12 位有效数字，足够表达 CE 里的任何实际数值。
    if v == math.floor(v) and math.abs(v) < 1e15 then return string.format('%d', v) end
    return string.format('%.12g', v)
  end
  if tv == 'string' then return '"' .. jesc(v) .. '"' end
  if tv == 'table' then
    local n, count = #v, 0
    for _ in pairs(v) do count = count + 1 end
    if count == 0 then return '[]' end
    if n > 0 and count == n then
      local parts = {}
      for i = 1, n do parts[i] = enc(v[i], depth + 1) end
      return '[' .. table.concat(parts, ',') .. ']'
    end
    local parts = {}
    for k, val in pairs(v) do
      local key = type(k) == 'string' and k or tostring(k)
      parts[#parts + 1] = '"' .. jesc(key) .. '":' .. enc(val, depth + 1)
    end
    return '{' .. table.concat(parts, ',') .. '}'
  end
  return '"' .. jesc(tostring(v)) .. '"'
end

local function ok (v, ptext)
  local s = '{"ok":true,"value":' .. enc(v)
  if ptext and ptext ~= '' then s = s .. ',"print":' .. enc(ptext) end
  return s .. '}'
end

local function fail (msg, ptext)
  local s = '{"ok":false,"error":' .. enc(tostring(msg))
  if ptext and ptext ~= '' then s = s .. ',"print":' .. enc(ptext) end
  return s .. '}'
end

----------------------------------------------------------------------
-- ops
----------------------------------------------------------------------
local function execute (code)
  local lines = {}
  local realprint = print
  print = function (...)
    local n = select('#', ...)
    local parts = {}
    for i = 1, n do parts[i] = tostring((select(i, ...))) end
    lines[#lines + 1] = table.concat(parts, '\t')
  end

  local chunk, loaderr = load(code, 'dsh', 't', _G)
  if not chunk then
    print = realprint
    return fail('compile: ' .. tostring(loaderr))
  end
  local results = table.pack(pcall(chunk))
  print = realprint
  local ptext = table.concat(lines, '\n')

  if not results[1] then return fail(results[2], ptext) end
  if results.n > 2 then
    local arr = {}
    for i = 2, results.n do arr[#arr + 1] = results[i] end
    return ok(arr, ptext)
  end
  return ok(results[2], ptext)
end

local function info ()
  local t = {}
  t.ceVersion = getCEVersion()
  t.pid = getOpenedProcessID()
  t.process = process or ''
  local ok64, is64 = pcall(targetIs64Bit)
  t.is64 = ok64 and is64 or false
  t.transport = 'mailbox'
  t.bridge = 'v2'
  return ok(t)
end

local function handle (op, body)
  if op == 'ping' then return ok('pong') end
  if op == 'info' then return info() end
  if op == 'eval' then return execute(body) end
  return fail('unknown op: ' .. tostring(op))
end

----------------------------------------------------------------------
-- 读写文件
----------------------------------------------------------------------
local function readAll (path)
  local f = io.open(path, 'rb')
  if not f then return nil end
  local data = f:read('a')
  f:close()
  return data
end

local function writeAll (path, data)
  local f = io.open(path, 'wb')
  if not f then return false end
  f:write(data)
  f:close()
  return true
end

local function writeAtomic (path, data)
  local tmp = path .. '.tmp'
  if not writeAll(tmp, data) then
    -- 连临时文件都写不出来，直接试目标文件
    return writeAll(path, data)
  end
  -- Windows 上 os.rename 不会覆盖已存在的文件，必须先删。如果这一刻对方正在读
  -- （插件侧每 10ms 轮询一次），os.remove 会失败，接着 rename 也会失败，
  -- 响应就永久卡在 .tmp 里 —— 客户端只能干等到超时。所以这里必须重试。
  for _ = 1, 50 do
    os.remove(path)
    if os.rename(tmp, path) then return true end
    for _ = 1, 2000 do end
  end
  -- 最后兜底：直接覆盖目标文件
  local ok = writeAll(path, data)
  os.remove(tmp)
  return ok
end

----------------------------------------------------------------------
-- 轮询定时器（运行在 CE 主线程）
----------------------------------------------------------------------
local ticks = 0

local function pollBody ()
  ticks = ticks + 1
  if ticks % 15 == 1 then
    writeAtomic(ALIVE, string.format('%d %s %d %d', getOpenedProcessID(), tostring(getCEVersion()), os.time(), ticks))
    -- 每约 5 秒记一次心跳即可，免得日志被刷满
    if ticks % 250 == 1 then log('heartbeat tick=' .. ticks) end
  end

  local raw = readAll(REQ)
  if not raw then return end
  os.remove(REQ)

  local id, rest = raw:match('^([^\n]*)\n(.*)$')
  if not id then log('bad req: no id') return end
  local op, body = rest:match('^([^\n]*)\n(.*)$')
  if not op then op, body = rest:match('^([^\n]*)$'), '' end

  local started = os.clock()
  local response
  local okrun, err = pcall(handle, op, body or '')
  if okrun then response = err else response = fail('dispatch: ' .. tostring(err)) end
  if type(response) ~= 'string' then response = fail('no response') end

  local wok = writeAtomic(RES, id .. '\n' .. response)
  log(string.format('%s op=%s %.0fms %dB%s', id, tostring(op), (os.clock() - started) * 1000, #response,
    wok and '' or ' WRITE-FAILED'))
end

local function poll ()
  local okrun, err = pcall(pollBody)
  if not okrun then log('POLL ERROR: ' .. tostring(err)) end
end

-- 传输层：CE 主线程定时器轮询信箱。
--
-- 两个必须记住的坑：
-- 1) createTimer(delay, fn) 是「一次性」定时器，执行完会自毁，用它做轮询只跑一次。
--    正确姿势是 createTimer(nil) 再设置 Interval / OnTimer，并且把对象存到全局，
--    否则被 GC 回收后回调也会停。
-- 2) 回调运行在 CE 主线程，调用 CE API 是安全的。早期版本用 createThread 在后台
--    线程里调 CE API，遇到 getProcesslist 这类函数会静默把线程搞死（心跳停止、
--    请求无人处理，外部看起来就是「连不上」）。
local ticks = 0
local timer = createTimer(nil, true)
timer.Interval = 20
timer.OnTimer = function (t)
  ticks = ticks + 1
  if ticks % 15 == 1 then
    pcall(writeAtomic, ALIVE,
      string.format('%d %s %d %d', getOpenedProcessID(), tostring(getCEVersion()), os.time(), ticks))
  end
  pcall(pollBody)
end
_G.__DSH_CE_TIMER__ = timer
log('bridge v3 (main-thread timer) started, maildir=' .. MAILDIR)

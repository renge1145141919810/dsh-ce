import { existsSync, readFileSync, writeFileSync, unlinkSync, renameSync, statSync, mkdirSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'

// 这个插件不在 Node 侧实现任何调试能力，只做一件事：
// 通过 %LOCALAPPDATA%\dsh-ce\mail 这个「单槽信箱」把 Lua 代码交给本机
// Cheat Engine 执行，再把结果取回来。扫描器、反汇编、自动汇编、调试器
// 全部由 CE 自己完成，这里只负责搬运。

export const inject = ['tools']

const BASE = join(process.env.LOCALAPPDATA || '', 'dsh-ce')
const MAIL = join(BASE, 'mail')
const REQ = join(MAIL, 'req')
const RES = join(MAIL, 'res')
const ALIVE = join(MAIL, 'alive')
const BRIDGE_LUA = join(BASE, 'bridge.lua')
// 断点命中记录走文件而不是 Lua 全局：CE 的调试回调跑在另一个上下文里，
// 主线程那次 eval 读不到它写的表，但文件是共享的。
const BP_DIR = join(BASE, 'bp')
const HERE = dirname(fileURLToPath(import.meta.url))
const BRIDGE_SRC = join(HERE, 'autorun', 'dsh-ce-bridge.lua')

// 桥脚本要放在一个 CE 能用 ANSI fopen 打开的纯 ASCII 路径下，
// 插件目录带中文，所以载入时自动复制一份到 %LOCALAPPDATA%\dsh-ce。
function ensureBridge () {
  try {
    if (!existsSync(BRIDGE_SRC)) return { deployed: false, reason: '插件里没有 autorun/dsh-ce-bridge.lua' }
    mkdirSync(BASE, { recursive: true })
    const next = readFileSync(BRIDGE_SRC, 'utf8')
    const prev = existsSync(BRIDGE_LUA) ? readFileSync(BRIDGE_LUA, 'utf8') : ''
    if (prev !== next) writeFileSync(BRIDGE_LUA, next, 'utf8')
    return { deployed: true, updated: prev !== next, path: BRIDGE_LUA }
  } catch (error) {
    return { deployed: false, reason: String(error?.message ?? error) }
  }
}

// 找 CE 安装目录（只认标准位置，避免误判）
function findCeDir () {
  const roots = [process.env.ProgramFiles, process.env['ProgramFiles(x86)']].filter(Boolean)
  for (const root of roots) {
    const dir = join(root, 'Cheat Engine')
    if (existsSync(join(dir, 'cheatengine-x86_64.exe'))) return dir
  }
  return ''
}

// 把加载钩子写进 CE 的 main.lua。
//
// 两个关键点：
//   1) 钩子必须放在 require("defines") 之前。defines 一旦加载失败会中断整个
//      main.lua，钩子写在后面就永远不会执行（这个坑排查了很久）。
//   2) 原文件先整份备份到 %LOCALAPPDATA%\dsh-ce\main.lua.bak，只做前置插入，
//      不改动原有内容。
const HOOK_MARKER = 'dsh-ce bridge'
function ensureMainLuaHook () {
  const dir = findCeDir()
  if (!dir) return { ok: false, reason: '没有找到 Cheat Engine 安装目录（Program Files\\Cheat Engine）' }
  const mainLua = join(dir, 'main.lua')
  try {
    const original = existsSync(mainLua) ? readFileSync(mainLua, 'utf8') : ''
    if (original.includes(HOOK_MARKER)) return { ok: true, already: true, path: mainLua }
    const mainLuaBak = join(BASE, 'main.lua.bak')
    const eol = original.includes('\r\n') ? '\r\n' : '\n'
    const header = [
      `-- ${HOOK_MARKER}：必须放在 require("defines") 之前`,
      '-- defines 若加载失败会中断整个 main.lua，钩子写在后面就永远执行不到',
      `pcall(dofile, [[${BRIDGE_LUA.replace(/\\/g, '/')}]])`,
      '',
    ].join(eol)
    try { writeFileSync(mainLuaBak, original, 'utf8') } catch {}
    writeFileSync(mainLua, header + original, 'utf8')
    return { ok: true, already: false, path: mainLua, backup: mainLuaBak }
  } catch (error) {
    return { ok: false, path: mainLua, reason: `写入被拒绝：${String(error?.message ?? error)}（需要用管理员权限改这个文件）` }
  }
}

// 只读检查：main.lua 里是否已经装好加载钩子
function mainLuaHookInstalled () {
  const dir = findCeDir()
  if (!dir) return false
  try { return readFileSync(join(dir, 'main.lua'), 'utf8').includes(HOOK_MARKER) } catch { return false }
}

const INSTALL_HINT = [
  'Cheat Engine 桥没有运行。多半是 CE 没启动，或 main.lua 里没有加载钩子。',
  '调用 ce_install 可以让插件自动把钩子写进 main.lua（会先备份）。',
  `手动的话：确认 ${BASE}\\main.lua.bak 存在，并在 CE 安装目录 main.lua 的**第一行区域**`,
  '（必须在 require("defines") 之前）加上：',
  `  pcall(dofile, [[${BRIDGE_LUA.replace(/\\/g, '/')}]])`,
  '改完重启 Cheat Engine 即可，之后每次开 CE 都会自动连上。',
].join('\n')

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const text = (value) => [{ type: 'text', text: String(value) }]

const BP_REGS = ['RIP', 'RSP', 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'EFLAGS']

function readBpFile (addrHex, limit = 50) {
  try {
    const txt = readFileSync(join(BP_DIR, `${addrHex}.log`), 'utf8')
    const lines = txt.split('\n').filter(Boolean)
    return lines.slice(0, limit).map((line, i) => {
      const [regPart, stackPart] = line.split('#')
      const vals = String(regPart || '').split('|')
      const regs = {}
      BP_REGS.forEach((n, k) => { if (vals[k] !== undefined && vals[k] !== '') regs[n] = vals[k] })
      const stack = String(stackPart || '').split(',').filter(Boolean).map((item) => {
        const at = item.indexOf('@')
        return at < 0 ? { address: item } : { address: item.slice(0, at), where: item.slice(at + 1) }
      })
      return { hitIndex: i + 1, regs, stack }
    })
  } catch {
    return []
  }
}

function listBpFiles () {
  try {
    return readdirSync(BP_DIR)
      .filter((f) => f.endsWith('.log'))
      .map((f) => {
        const addr = f.replace(/\.log$/, '')
        let count = 0
        let mtime = 0
        try {
          const full = join(BP_DIR, f)
          count = readFileSync(full, 'utf8').split('\n').filter(Boolean).length
          mtime = statSync(full).mtimeMs
        } catch {}
        return { address: addr, hits: count, updatedAt: mtime }
      })
      .sort((a, b) => b.updatedAt - a.updatedAt)
  } catch {
    return []
  }
}

function readAlive () {
  try {
    const info = statSync(ALIVE)
    const age = Date.now() - info.mtimeMs
    const parts = readFileSync(ALIVE, 'utf8').trim().split(/\s+/)
    return {
      online: age < 15000,
      age,
      pid: Number(parts[0]) || 0,
      ceVersion: Number(parts[1]) || 0,
      tick: Number(parts[3]) || 0,
    }
  } catch {
    return { online: false, age: Infinity, pid: 0, ceVersion: 0, tick: 0 }
  }
}

// 单槽信箱：一次只能有一个请求在飞，并发调用必须排队。
let chain = Promise.resolve()
function enqueue (fn) {
  const run = chain.then(fn, fn)
  chain = run.then(() => {}, () => {})
  return run
}

async function bridge (op, body = '', timeoutMs = 60000) {
  return enqueue(async () => {
    // 扫描期间 CE 主线程会被占住，心跳会短暂停更。所以不能一看心跳旧就判离线，
    // 先等最多 15 秒看它是否恢复，避免「扫完一次就整条链路掉线」的假故障。
    let status = readAlive()
    if (!status.online) {
      const waitUntil = Date.now() + 15000
      while (Date.now() < waitUntil) {
        await sleep(200)
        status = readAlive()
        if (status.online) break
      }
      if (!status.online) throw new Error(INSTALL_HINT)
    }
    try { mkdirSync(MAIL, { recursive: true }) } catch {}

    const id = randomUUID().slice(0, 8)
    try { if (existsSync(RES)) unlinkSync(RES) } catch {}
    const tmp = REQ + '.tmp'
    writeFileSync(tmp, `${id}\n${op}\n${body}`, 'utf8')
    renameSync(tmp, REQ)

    const deadline = Date.now() + timeoutMs
    const dbg = !!process.env.DSH_CE_DEBUG
    if (dbg) console.error(`[dsh-ce] → req id=${id} op=${op} bytes=${body.length}`)
    while (Date.now() < deadline) {
      let raw = null
      let readErr = null
      try {
        if (existsSync(RES)) raw = readFileSync(RES, 'utf8')
      } catch (e) { readErr = e.code || e.message }
      if (readErr && dbg) console.error(`[dsh-ce] res 读取失败: ${readErr}`)
      if (raw) {
        const nl = raw.indexOf('\n')
        if (dbg) console.error(`[dsh-ce] ← res id=${JSON.stringify(raw.slice(0, nl))} 期望=${id} len=${raw.length}`)
        if (nl >= 0 && raw.slice(0, nl) === id) {
          const payload = raw.slice(nl + 1)
          try { unlinkSync(RES) } catch {}
          try {
            return JSON.parse(payload)
          } catch {
            // 千万不能把解析失败当成「还没回包」继续轮询：
            // 响应文件上面已经删掉了，再等只会一路等到超时，看起来像 CE 没响应。
            throw new Error(`CE 回了内容但无法解析（${payload.length}B）: ${payload.slice(0, 300)}`)
          }
        }
      }
      await sleep(10)
    }
    try { if (existsSync(REQ)) unlinkSync(REQ) } catch {}
    throw new Error(`Cheat Engine 在 ${Math.round(timeoutMs / 1000)} 秒内没有回包`)
  })
}

async function lua (code, timeoutMs = 60000) {
  // Lua 侧超时比桥的等待短一点，让脚本自己先中断并回一条可读的错误，
  // 而不是让桥干等到超时、CE 主线程还卡在死循环里。
  const sec = Math.max(5, Math.floor((timeoutMs / 1000) * 0.9))
  const res = await bridge('eval', withTimeout(code, sec), timeoutMs)
  if (!res.ok) throw new Error(res.error || 'CE 执行失败')
  return res
}

// debug.sethook 每 10 万条 Lua 指令检查一次，超时就抛错。
// 只能中断纯 Lua 的死循环；卡在 C 函数里（比如 waitTillDone 的扫描）中断不了。
function withTimeout (code, sec) {
  return `${PRELUDE}
local __dshT0 = os.clock()
local __dshLim = ${sec}
local __dshOk, __dshRes = pcall(function ()
  debug.sethook(function ()
    if os.clock() - __dshT0 > __dshLim then
      debug.sethook()
      error('dsh: 脚本执行超过 ${sec} 秒，已被中断', 0)
    end
  end, '', 100000)
${code}
end)
debug.sethook()
if not __dshOk then error(__dshRes, 0) end
return __dshRes`
}

// 每次调用都注入的公共库：地址解析、模块缓存、内存区域、保护属性名字
const PRELUDE = `
local function dsh_addr (v)
  if type(v) == 'number' then return v end
  local s = tostring(v or ''):match('^%s*(.-)%s*$')
  if s == '' then return nil end
  local sym = getAddressSafe(s)
  if sym and sym ~= 0 then return sym end
  local hex = s:gsub('^0[xX]', '')
  return tonumber(hex, 16)
end

local function dsh_modules ()
  local now = os.clock()
  local cached = _G.__DSH_MODS
  if cached and _G.__DSH_MODS_T and (now - _G.__DSH_MODS_T) < 3 then return cached end
  local out = {}
  local ok, list = pcall(enumModules)
  if ok and list then
    for _, m in ipairs(list) do
      out[#out + 1] = { name = m.Name, path = m.Path, base = m.Address, size = m.Size }
    end
    table.sort(out, function (a, b) return a.base < b.base end)
  end
  _G.__DSH_MODS = out
  _G.__DSH_MODS_T = now
  return out
end

local function dsh_module_of (addr)
  local mods = dsh_modules()
  local lo, hi = 1, #mods
  while lo <= hi do
    local mid = math.floor((lo + hi) / 2)
    local m = mods[mid]
    if addr < m.base then hi = mid - 1
    elseif addr >= m.base + m.size then lo = mid + 1
    else return m, addr - m.base end
  end
  return nil
end

local function dsh_prot (p)
  p = p or 0
  if p == 0 then return '---' end
  local r = (p == 2 or p == 4 or p == 8 or p == 0x20 or p == 0x40 or p == 0x80) and 'r' or '-'
  local w = (p == 4 or p == 8 or p == 0x40 or p == 0x80) and 'w' or '-'
  local x = (p == 0x10 or p == 0x20 or p == 0x40 or p == 0x80) and 'x' or '-'
  local s = r .. w .. x
  if p == 1 then s = 'noaccess' end
  if math.floor(p / 0x100) % 2 == 1 then s = s .. '+guard' end
  return s
end

local function dsh_regions ()
  local raw = enumMemoryRegions()
  local out = {}
  for _, r in ipairs(raw) do
    local st = r.State or 0
    if st == 0x1000 then
      out[#out + 1] = {
        base = r.BaseAddress, size = r.RegionSize, protect = r.Protect or 0,
        allocBase = r.AllocationBase, kind = r.Type or 0,
      }
    end
  end
  table.sort(out, function (a, b) return a.base < b.base end)
  return out
end

local function dsh_region_of (addr, regions)
  regions = regions or dsh_regions()
  local lo, hi = 1, #regions
  while lo <= hi do
    local mid = math.floor((lo + hi) / 2)
    local r = regions[mid]
    if addr < r.base then hi = mid - 1
    elseif addr >= r.base + r.size then lo = mid + 1
    else return r end
  end
  return nil
end

-- 值 -> 小端字节串（用于 AOB 模式匹配）
local function dsh_lebytes (value, size)
  local v = value
  local t = {}
  for i = 1, size do
    t[i] = string.format('%02X', v % 256)
    v = math.floor(v / 256)
  end
  return table.concat(t, ' ')
end

local function dsh_readle (addr, size)
  local b = readBytes(addr, size, true)
  if not b then return nil end
  local v = 0
  for i = size, 1, -1 do v = v * 256 + b[i] end
  return v
end
`

const str = (v) => JSON.stringify(String(v))

const VTYPES = ['byte', 'word', 'dword', 'qword', 'float', 'double', 'string', 'aob']
// 读写额外支持 bytes（按字节串读写）。扫描不支持，所以单独一个列表。
const RW_TYPES = [...VTYPES, 'bytes']
const SCAN_FIRST = ['exact', 'unknown', 'between', 'bigger', 'smaller']
const SCAN_NEXT = ['exact', 'changed', 'unchanged', 'increased', 'decreased', 'increased_by', 'decreased_by', 'between', 'bigger', 'smaller']

const VT_MAP_LUA = `
-- 注意：这里必须引用真正的全局常量（vtDword / soExactValue ...），
-- 不能写成字符串 'vtDword'。CE 的 firstScan 期待数字枚举，收到字符串会按 0 处理，
-- 而 soUnknownValue 正好是 0 —— 于是「精确值扫描」会静默退化成「未知初始值扫描」(count 恒为 0)。
local DSH_VT = { byte = vtByte, word = vtWord, dword = vtDword, qword = vtQword,
                 float = vtSingle, double = vtDouble, string = vtString, aob = vtByteArray }
local DSH_SO_FIRST = { exact = soExactValue, unknown = soUnknownValue, between = soValueBetween,
                       bigger = soBiggerThan, smaller = soSmallerThan }
local DSH_SO_NEXT = { exact = soExactValue, changed = soChanged, unchanged = soUnchanged,
                      increased = soIncreasedValue, decreased = soDecreasedValue,
                      increased_by = soIncreasedValueBy, decreased_by = soDecreasedValueBy,
                      between = soValueBetween, bigger = soBiggerThan, smaller = soSmallerThan }
local function dsh_sample (ms, limit)
  local fl = createFoundList(ms)
  fl.initialize()
  local count = fl.Count
  local items = {}
  local stop = math.min(count, limit) - 1
  for i = 0, stop do
    items[#items + 1] = { address = fl.getAddress(i), value = fl.getValue(i) }
  end
  fl.deinitialize()
  return count, items
end
`

// 注意：不要用 export default。DSH 的 loader 会做 `exports.default ?? exports`，
// 一旦有默认导出就会把整个模块对象替换成这个函数，模块级的 inject 声明随之丢失，
// 于是 ctx.tools 抛 "cannot get property \"tools\" without inject"。
// 必须保持命名导出，让 loader 拿到模块命名空间（其中含 inject）。
export function apply (ctx) {
  const deploy = ensureBridge()

  // ---------------- 工具 ----------------

  const status = {
    name: 'ce_status',
    description: '检查 Cheat Engine 桥是否在线，返回 CE 版本、当前已附加的进程；离线时给出接入方法。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.online) return text('CE 未连接')
        return text(`CE ${value.ceVersion} 在线，目标 ${value.process || '(未附加)'} pid=${value.pid || 0}`)
      },
    },
    async execute () {
      const alive = readAlive()
      if (!alive.online) return { online: false, hookInstalled: mainLuaHookInstalled(), hint: INSTALL_HINT, bridgePath: BRIDGE_LUA }
      const res = await lua(`return {
        ce = getCEVersion(),
        pid = getOpenedProcessID(),
        process = process or '',
        is64 = (function() local o, v = pcall(targetIs64Bit) return o and v or false end)(),
      }`)
      return { online: true, hookInstalled: mainLuaHookInstalled(), cePid: alive.pid, ...res.value }
    },
  }

  const runLua = {
    name: 'ce_lua',
    description: '在 Cheat Engine 内执行一段 Lua，返回表达式的值。CE 的全部 API 都在这里（readInteger、createMemScan、AOBScan、autoAssemble、debug_setBreakpoint…），这是在现有工具不够用时自己拼逻辑的通用入口。',
    parameters: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Lua 代码，用 return 返回结果。结果会转成 JSON（table/数组/数字/字符串都可以）。' },
        timeoutMs: { type: 'integer', description: '超时毫秒，默认 60000。大范围扫描可以调到 300000。' },
      },
      required: ['code'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        const printed = value?.print ? `\n${value.print}` : ''
        return text(`${JSON.stringify(value?.value)}${printed}`)
      },
    },
    async execute (args) {
      const res = await lua(String(args?.code ?? ''), Number(args?.timeoutMs) || 60000)
      return { value: res.value ?? null, print: res.print ?? '' }
    },
  }

  const ps = {
    name: 'ce_ps',
    description: '列出系统里的进程（走 CE 自己的进程枚举，能看到 CE 能附加的那些）。可按名字片段过滤。',
    parameters: {
      type: 'object',
      properties: {
        filter: { type: 'string', description: '名字包含这个片段（不区分大小写）' },
        limit: { type: 'integer', description: '最多返回多少个，默认 200' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.processes?.length) return text('没有匹配的进程')
        const head = value.processes.slice(0, 15).map((p) => `${p.pid}\t${p.name}`).join('\n')
        const more = value.processes.length > 15 ? `\n…共 ${value.total} 个` : ''
        return text(`${head}${more}`)
      },
    },
    async execute (args) {
      const res = await lua(`
        local t = getProcesslist()
        local out = {}
        for k, v in pairs(t) do
          local pid, name
          if type(k) == 'number' then pid, name = k, tostring(v) else pid, name = tonumber(v), tostring(k) end
          if pid and pid > 0 then out[#out + 1] = { pid = pid, name = name } end
        end
        table.sort(out, function (a, b) return a.name:lower() < b.name:lower() end)
        return out
      `)
      const needle = String(args?.filter ?? '').trim().toLowerCase()
      const limit = Number(args?.limit) || 200
      let list = Array.isArray(res.value) ? res.value : []
      if (needle) list = list.filter((p) => String(p.name).toLowerCase().includes(needle))
      return { total: list.length, processes: list.slice(0, limit) }
    },
  }

  const attach = {
    name: 'ce_attach',
    description: '让 Cheat Engine 附加到目标进程。传 pid 或进程名（可不带 .exe）。附加成功后所有读写/扫描都针对它。',
    parameters: {
      type: 'object',
      properties: {
        pid: { type: 'integer', description: '进程 id' },
        name: { type: 'string', description: '进程名，例如 game.exe' },
        debug: { type: 'boolean', description: 'true = 同时启用 CE 调试器（下断点、看寄存器前必须先这么做）' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) { return text(`已附加 ${value?.process} pid=${value?.pid}（${value?.is64 ? 64 : 32} 位）`) },
    },
    async execute (args) {
      const pid = Number(args?.pid) || 0
      const name = String(args?.name ?? '')
      const debug = args?.debug === true
      const res = await lua(`
        local pid = ${pid}
        local name = ${str(name)}
        if pid == 0 and name ~= '' then
          pid = getProcessIDFromProcessName(name)
          if (not pid or pid == 0) and not name:lower():match('%.exe$') then
            pid = getProcessIDFromProcessName(name .. '.exe')
          end
        end
        if not pid or pid == 0 then error('找不到进程 ' .. name) end
        -- 已经打开同一个进程时就别再 openProcess 一次：在调试会话里重复调用会卡住主线程
        if getOpenedProcessID() ~= pid then openProcess(pid) end
        local opened = getOpenedProcessID()
        if opened ~= pid then error('openProcess 失败：CE 仍指向 ' .. tostring(opened)) end
        local isDbg = (function () local o, v = pcall(debug_isDebugging) return o and v == true or false end)()
        if ${debug} and not isDbg then
          -- 必须显式指定 1（Windows 调试接口）。默认的 0 启动的会话会在几百毫秒后自己退出，
          -- 断点看着下上了却永远不命中。另外：已经处于调试状态时不能再调一次
          -- debugProcess，那会直接阻塞住 CE 主线程（CE 没有提供停止调试的 API）。
          local ok, err = pcall(debugProcess, 1)
          if not ok then error('启用调试器失败: ' .. tostring(err) .. '（多半是权限不足，CE 要以管理员运行）') end
          isDbg = (function () local o, v = pcall(debug_isDebugging) return o and v == true or false end)()
          if not isDbg then error('调试器没有真正启动（debug_isDebugging 仍为 false）') end
        end
        return {
          pid = pid, process = process or '',
          is64 = (function() local o, v = pcall(targetIs64Bit) return o and v or false end)(),
          debugging = ${debug} and (function() local o, v = pcall(debug_isDebugging) return o and v == true or false end)() or false,
        }
      `, 60000)
      return res.value
    },
  }

  const modules = {
    name: 'ce_modules',
    description: '列出目标进程已加载的模块（模块名、基址、大小）。找基址、算模块内偏移都从这里开始。',
    parameters: {
      type: 'object',
      properties: { filter: { type: 'string', description: '模块名过滤，可空' } },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.modules?.length) return text('没有模块（先附加进程）')
        return text(value.modules.slice(0, 12).map((m) => `${m.name}  0x${m.base.toString(16)}  ${Math.round(m.size / 1024)}KB`).join('\n'))
      },
    },
    async execute (args) {
      const res = await lua(`
        local list = enumModules()
        local out = {}
        for _, m in ipairs(list) do
          out[#out + 1] = { name = m.Name, path = m.Path, base = m.Address, size = m.Size }
        end
        table.sort(out, function (a, b) return a.base < b.base end)
        return out
      `)
      const needle = String(args?.filter ?? '').trim().toLowerCase()
      let list = Array.isArray(res.value) ? res.value : []
      if (needle) list = list.filter((m) => String(m.name).toLowerCase().includes(needle) || String(m.path || '').toLowerCase().includes(needle))
      return { total: list.length, modules: list }
    },
  }

  const read = {
    name: 'ce_read',
    description: '读取目标进程内存。地址支持 0x1234、模块+偏移（如 game.exe+1A2B0）、CE 符号。type 选 byte/word/dword/qword/float/double/string/bytes/aob。',
    parameters: {
      type: 'object',
      properties: {
        address: { type: 'string', description: '地址，例如 0x140001000 或 game.exe+1A2B0' },
        type: { type: 'string', enum: RW_TYPES, description: '值类型，默认 dword；bytes/aob 表示按字节读' },
        count: { type: 'integer', description: 'bytes/aob/string 的长度，默认 64' },
      },
      required: ['address'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (value?.hex) return text(`${value.address}  ${value.hex}`)
        return text(`${value?.address} = ${value?.value}`)
      },
    },
    async execute (args) {
      const address = String(args?.address ?? '')
      const type = RW_TYPES.includes(args?.type) ? args.type : 'dword'
      const count = Math.max(1, Math.min(Number(args?.count) || 64, 65536))
      const res = await lua(`
        local a = dsh_addr(${str(address)})
        if not a or a == 0 then error('地址无法解析: ' .. ${str(address)}) end
        local t = ${str(type)}
        local n = ${count}
        local label = string.format('%X', a)
        if t == 'bytes' or t == 'aob' then
          local b = readBytes(a, n, true)
          if not b then error('读取失败（地址可能不可读）') end
          local hex = {}
          for i = 1, #b do hex[#hex + 1] = string.format('%02X', b[i]) end
          return { address = label, hex = table.concat(hex, ' '), bytes = b }
        elseif t == 'string' then
          local s = readString(a, n, false)
          if not s then error('读取失败') end
          return { address = label, value = s }
        elseif t == 'byte' then
          return { address = label, value = readByte(a) }
        elseif t == 'word' then
          return { address = label, value = readSmallInteger(a) }
        elseif t == 'qword' then
          local v = readQword(a)
          return { address = label, value = string.format('%d', v), unsigned = string.format('%X', v) }
        elseif t == 'float' then
          return { address = label, value = readFloat(a) }
        elseif t == 'double' then
          return { address = label, value = readDouble(a) }
        else
          return { address = label, value = readInteger(a) }
        end
      `, 20000)
      return res.value
    },
  }

  const write = {
    name: 'ce_write',
    description: '写目标进程内存。用于 CTF / 授权靶场里验证「改这个值会怎样」。bytes 类型写十六进制字符串。',
    parameters: {
      type: 'object',
      properties: {
        address: { type: 'string', description: '地址' },
        type: { type: 'string', enum: RW_TYPES.filter((t) => t !== 'aob'), description: '值类型，默认 dword' },
        value: { type: 'string', description: '要写入的值；bytes 时是 "4D 5A 90 00" 这种十六进制串' },
      },
      required: ['address', 'value'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) { return text(`已写入 ${value?.address}，回读 ${value?.verify}`) },
    },
    async execute (args) {
      const address = String(args?.address ?? '')
      const type = RW_TYPES.includes(args?.type) ? args.type : 'dword'
      const value = String(args?.value ?? '')
      const res = await lua(`
        local a = dsh_addr(${str(address)})
        if not a or a == 0 then error('地址无法解析: ' .. ${str(address)}) end
        local t = ${str(type)}
        local v = ${str(value)}
        if t == 'bytes' then
          local b = {}
          for hex in v:gmatch('%x%x') do b[#b + 1] = tonumber(hex, 16) end
          if #b == 0 then error('bytes 需要形如 4D 5A 90 00 的十六进制串') end
          writeBytes(a, b)
        elseif t == 'string' then
          writeString(a, v, false)
        elseif t == 'byte' then
          writeByte(a, tonumber(v) or tonumber(v, 16))
        elseif t == 'word' then
          writeSmallInteger(a, tonumber(v) or tonumber(v, 16))
        elseif t == 'qword' then
          writeQword(a, tonumber(v) or tonumber(v, 16))
        elseif t == 'float' then
          writeFloat(a, tonumber(v))
        elseif t == 'double' then
          writeDouble(a, tonumber(v))
        else
          writeInteger(a, tonumber(v) or tonumber(v, 16))
        end
        local back = readBytes(a, math.max(4, #v), true)
        local hex = {}
        if back then for i = 1, #back do hex[#hex + 1] = string.format('%02X', back[i]) end end
        return { address = string.format('%X', a), verify = table.concat(hex, ' ') }
      `, 20000)
      return res.value
    },
  }

  const aob = {
    name: 'ce_aob',
    description: '在目标进程里按字节特征码扫描（AOB scan），例如 "48 8B 05 ?? ?? ?? ?? 48 85 C0"。返回命中地址列表。',
    parameters: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: '特征码，? / ?? / * 是通配符' },
        protection: { type: 'string', description: '内存保护过滤，默认 "+X"（可执行）；扫全部传空字符串' },
        limit: { type: 'integer', description: '最多返回多少条，默认 20' },
      },
      required: ['pattern'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.count) return text('没有命中')
        return text(`${value.count} 处命中：${value.addresses.slice(0, 8).join(', ')}`)
      },
    },
    async execute (args) {
      const pattern = String(args?.pattern ?? '')
      const protection = args?.protection === undefined ? '+X' : String(args.protection)
      const limit = Math.max(1, Math.min(Number(args?.limit) || 20, 500))
      const res = await lua(`
        local pat = ${str(pattern)}
        local prot = ${str(protection)}
        local r
        if prot == '' then r = AOBScan(pat) else r = AOBScan(pat, prot) end
        if r == nil then return { count = 0, addresses = {} } end
        local out = {}
        local n = 0
        for i = 0, r.Count - 1 do
          n = n + 1
          if #out < ${limit} then out[#out + 1] = string.format('%X', tonumber(r[i], 16)) end
        end
        r.destroy()
        return { count = n, addresses = out }
      `, 120000)
      return res.value
    },
  }

  const disasm = {
    name: 'ce_disasm',
    description: '从指定地址反汇编若干条指令，附带每条指令的字节。分析函数入口、看某条指令改了什么必备。',
    parameters: {
      type: 'object',
      properties: {
        address: { type: 'string', description: '起始地址' },
        count: { type: 'integer', description: '指令条数，默认 10' },
      },
      required: ['address'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.instructions?.length) return text('反汇编失败')
        return text(value.instructions.map((i) => `${i.address}  ${i.bytes.padEnd(20)}  ${i.text}`).join('\n'))
      },
    },
    async execute (args) {
      const address = String(args?.address ?? '')
      const count = Math.max(1, Math.min(Number(args?.count) || 10, 200))
      const res = await lua(`
        local a = dsh_addr(${str(address)})
        if not a or a == 0 then error('地址无法解析') end
        local out = {}
        for i = 1, ${count} do
          local text = disassemble(a)
          if not text then break end
          local size = getInstructionSize(a) or 1
          local b = readBytes(a, size, true)
          local hex = {}
          if b then for k = 1, #b do hex[#hex + 1] = string.format('%02X', b[k]) end end
          out[#out + 1] = { address = string.format('%X', a), text = text, bytes = table.concat(hex, ' ') }
          a = a + size
        end
        return out
      `, 30000)
      return { instructions: Array.isArray(res.value) ? res.value : [] }
    },
  }

  const scanStart = {
    name: 'ce_scan_start',
    description: '开始一次新的值扫描（等价 CE 的首次扫描）。mode 支持 exact/unknown/between/bigger/smaller；先用 unknown 做「未知初始值」扫描，再用 ce_scan_next 逐步缩小，是找血条/坐标这类值的标准做法。',
    parameters: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: VTYPES, description: '值类型，默认 dword' },
        mode: { type: 'string', enum: SCAN_FIRST, description: '扫描方式，默认 exact' },
        value: { type: 'string', description: '目标值（unknown 模式不需要）' },
        value2: { type: 'string', description: 'between 模式的上界' },
        protection: { type: 'string', description: '内存保护过滤，默认 "+W-C"（可写）；扫全部传空字符串' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (value?.regionScan) {
          return text('已建立「未知初始值」扫描（此刻 CE 只记录内存区域，地址要等 ce_scan_next 之后才具体化）。改一下目标里的值，再用 changed/increased/decreased 筛选。')
        }
        const sample = (value?.sample || []).slice(0, 5).map((s) => `${s.address}=${s.value}`).join('  ')
        return text(`首次扫描命中 ${value?.count} 个${sample ? '\n' + sample : ''}`)
      },
    },
    async execute (args) {
      const type = VTYPES.includes(args?.type) ? args.type : 'dword'
      const mode = SCAN_FIRST.includes(args?.mode) ? args.mode : 'exact'
      const v1 = String(args?.value ?? '')
      const v2 = String(args?.value2 ?? '')
      const protection = args?.protection === undefined ? '+W-C' : String(args.protection)
      if (mode !== 'unknown' && v1 === '') throw new Error(`${mode} 模式需要 value`)

      const res = await lua(`
        ${VT_MAP_LUA}
        local ms = createMemScan()
        ms.firstScan(DSH_SO_FIRST[${str(mode)}], DSH_VT[${str(type)}], rtRounded,
          ${str(v1)}, ${str(v2)}, 0, 0xffffffffffffffff, ${str(protection)},
          fsmNotAligned, '1', false, false, false, false)
        ms.waitTillDone()
        _G.__DSH_SCAN = { ms = ms, type = ${str(type)}, mode = ${str(mode)} }
        local count, items = dsh_sample(ms, 5)
        return { count = count, sample = items, type = ${str(type)}, mode = ${str(mode)}, regionScan = (${str(mode)} == 'unknown') }
      `, 300000)
      return res.value
    },
  }

  const scanNext = {
    name: 'ce_scan_next',
    description: '在上一次扫描结果里继续筛选。mode 支持 exact/changed/unchanged/increased/decreased/increased_by/decreased_by/between/bigger/smaller。改一下游戏里的值再调一次，命中数会迅速收敛。',
    parameters: {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: SCAN_NEXT, description: '筛选方式，默认 exact' },
        value: { type: 'string', description: '目标值/增量（changed、unchanged、increased、decreased 不需要）' },
        value2: { type: 'string', description: 'between 的上界' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        const sample = (value?.sample || []).slice(0, 5).map((s) => `${s.address}=${s.value}`).join('  ')
        return text(`剩余 ${value?.count} 个${sample ? '\n' + sample : ''}`)
      },
    },
    async execute (args) {
      const mode = SCAN_NEXT.includes(args?.mode) ? args.mode : 'exact'
      const v1 = String(args?.value ?? '')
      const v2 = String(args?.value2 ?? '')
      const res = await lua(`
        ${VT_MAP_LUA}
        local s = _G.__DSH_SCAN
        if not s then error('还没有进行中的扫描，先调用 ce_scan_start') end
        s.ms.nextScan(DSH_SO_NEXT[${str(mode)}], rtRounded, ${str(v1)}, ${str(v2)},
          false, false, false, false, false)
        s.ms.waitTillDone()
        local count, items = dsh_sample(s.ms, 5)
        return { count = count, sample = items, mode = ${str(mode)} }
      `, 300000)
      return res.value
    },
  }

  const scanResults = {
    name: 'ce_scan_results',
    description: '读出当前扫描结果里的地址和值（分页）。用来确认锁定了哪些地址，或者交给 ce_write 去改。',
    parameters: {
      type: 'object',
      properties: {
        offset: { type: 'integer', description: '从第几条开始，默认 0' },
        limit: { type: 'integer', description: '取多少条，默认 50' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.items?.length) return text('没有结果')
        return text(value.items.slice(0, 20).map((i) => `${i.address}  ${i.value}`).join('\n'))
      },
    },
    async execute (args) {
      const offset = Math.max(0, Number(args?.offset) || 0)
      const limit = Math.max(1, Math.min(Number(args?.limit) || 50, 1000))
      const res = await lua(`
        ${VT_MAP_LUA}
        local s = _G.__DSH_SCAN
        if not s then error('还没有进行中的扫描') end
        local fl = createFoundList(s.ms)
        fl.initialize()
        local count = fl.Count
        local items = {}
        for i = ${offset}, math.min(${offset + limit}, count) - 1 do
          items[#items + 1] = { address = fl.getAddress(i), value = fl.getValue(i) }
        end
        fl.deinitialize()
        return { count = count, offset = ${offset}, items = items, type = s.type }
      `, 120000)
      return res.value
    },
  }

  const scanReset = {
    name: 'ce_scan_reset',
    description: '清空当前扫描会话，准备下一次全新扫描。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: { schema: { type: 'object', additionalProperties: true }, render () { return text('已清空') } },
    async execute () {
      await lua(`
        local s = _G.__DSH_SCAN
        if s and s.ms then pcall(function () s.ms.newScan() end) end
        _G.__DSH_SCAN = nil
        return true
      `, 20000)
      return { cleared: true }
    },
  }

  const aa = {
    name: 'ce_aa',
    description: '执行 CE 的自动汇编（Auto Assembler）脚本：可以注入代码、nop 掉校验、改跳转。脚本语法就是 CE 表格里那段 AA。',
    parameters: {
      type: 'object',
      properties: { script: { type: 'string', description: '完整 AA 脚本文本' } },
      required: ['script'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        return text(value?.enabled ? '已注入并启用' : `注入失败：${value?.error}`)
      },
    },
    async execute (args) {
      const script = String(args?.script ?? '')
      if (script.includes(']==]')) throw new Error('脚本里不能出现 ]==]')
      const res = await lua(`
        local src = [==[${script}]==]
        local ok, err = autoAssemble(src)
        if ok then return { enabled = true } end
        return { enabled = false, error = tostring(err) }
      `, 60000)
      return res.value
    },
  }

  const regions = {
    name: 'ce_regions',
    description: '枚举目标进程的内存区域：基址、大小、保护属性（rwx）、类型（image/mapped/private）、所属模块及模块内偏移。扫描前先看这块，能大幅缩小范围——通常只有 private+w 的堆才是你要找的数据。',
    parameters: {
      type: 'object',
      properties: {
        writable: { type: 'boolean', description: '只看可写区域' },
        executable: { type: 'boolean', description: '只看可执行区域' },
        module: { type: 'string', description: '只看名字含该片段的模块的映像区域' },
        minSize: { type: 'integer', description: '最小字节数，默认 4096' },
        limit: { type: 'integer', description: '最多返回多少条，默认 100' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.regions?.length) return text('没有匹配的区域')
        return text(value.regions.slice(0, 10).map((r) => `${r.base} ${r.protect.padEnd(9)} ${(r.size / 1024).toFixed(0)}KB ${r.module || r.kind}`).join('\n'))
      },
    },
    async execute (args) {
      const wantW = args?.writable === true
      const wantX = args?.executable === true
      const needle = String(args?.module ?? '').toLowerCase()
      const minSize = Math.max(0, Number(args?.minSize) || 4096)
      const limit = Math.max(1, Math.min(Number(args?.limit) || 100, 2000))
      const res = await lua(`
        local regs = dsh_regions()
        local out = {}
        local totalBytes, totalCount = 0, 0
        local byKind = {}
        for _, r in ipairs(regs) do
          if r.size >= ${minSize} then
            local prot = dsh_prot(r.protect)
            local kindName = 'other'
            if r.kind == 0x1000000 then kindName = 'image'
            elseif r.kind == 0x40000 then kindName = 'mapped'
            elseif r.kind == 0x20000 then kindName = 'private' end
            local m, moff = dsh_module_of(r.base)
            local keep = true
            if ${wantW} and prot:sub(2, 2) ~= 'w' then keep = false end
            if ${wantX} and prot:sub(3, 3) ~= 'x' then keep = false end
            if ${str(needle)} ~= '' then
              if not m or not m.name:lower():find(${str(needle)}, 1, true) then keep = false end
            end
            if keep then
              totalBytes = totalBytes + r.size
              totalCount = totalCount + 1
              byKind[kindName] = (byKind[kindName] or 0) + r.size
              if #out < ${limit} then
                out[#out + 1] = {
                  base = string.format('%X', r.base),
                  size = r.size,
                  protect = prot,
                  kind = kindName,
                  module = m and m.name or nil,
                  moduleOffset = moff and string.format('%X', moff) or nil,
                }
              end
            end
          end
        end
        return { total = totalCount, totalBytes = totalBytes, bytesByKind = byKind, returned = #out, regions = out }
      `, 30000)
      return res.value
    },
  }

  const scanMulti = {
    name: 'ce_scan_multi',
    description: '一次精确扫描多个值（CE 本身只支持单值，这里是按值转字节模式批量 AOB 扫描）。适合「一批候选值同时验证」，或者一次找齐血量/蓝量/等级这类分散的字段。返回每个值命中的地址。',
    parameters: {
      type: 'object',
      properties: {
        values: { type: 'string', description: '值列表，空格或逗号分隔，例如 "100 250 1000"；也接受 0x 开头的十六进制' },
        type: { type: 'string', enum: ['byte', 'word', 'dword', 'qword'], description: '值宽度，默认 dword' },
        protection: { type: 'string', description: '内存保护过滤，默认 "+W"（只扫可写）；扫全部传空字符串' },
        limitPerValue: { type: 'integer', description: '每个值最多返回多少地址，默认 20' },
      },
      required: ['values'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        const rows = (value?.groups || []).map((g) => `${g.value.padEnd(10)} ${g.count} 个${g.addresses?.length ? '  ' + g.addresses.slice(0, 4).join(' ') : ''}`)
        return text(rows.length ? rows.join('\n') : '没有命中')
      },
    },
    async execute (args) {
      const raw = String(args?.values ?? '')
      const list = raw.split(/[\s,;]+/).filter(Boolean)
      if (!list.length) throw new Error('values 不能为空')
      if (list.length > 64) throw new Error('一次最多 64 个值')
      const width = ['byte', 'word', 'dword', 'qword'].includes(args?.type) ? args.type : 'dword'
      const protection = args?.protection === undefined ? '+W' : String(args.protection)
      const limit = Math.max(1, Math.min(Number(args?.limitPerValue) || 20, 500))
      const res = await lua(`
        local width = (${str(width)} == 'byte') and 1 or ((${str(width)} == 'word') and 2 or ((${str(width)} == 'qword') and 8 or 4))
        local values = {}
        for _, s in ipairs({${list.map((v) => str(v)).join(',')}}) do
          values[#values + 1] = s
        end
        local out = {}
        for _, text in ipairs(values) do
          local n = tonumber(text)
          if n == nil and text:match('^0[xX]') then n = tonumber(text:sub(3), 16) end
          if n == nil then
            out[#out + 1] = { value = text, count = 0, error = '不是数字' }
          else
            local pat = dsh_lebytes(n, width)
            local fl = AOBScan(pat, ${str(protection)}, fsmNotAligned, '1')
            local addrs = {}
            local count = 0
            if fl then
              count = fl.Count or 0
              for i = 0, math.min(count, ${limit}) - 1 do
                addrs[#addrs + 1] = string.format('%X', tonumber(fl[i], 16) or 0)
              end
              fl.destroy()
            end
            out[#out + 1] = { value = string.format('%d', n), pattern = pat, count = count, addresses = addrs }
          end
        end
        return { width = width, protection = ${str(protection)}, groups = out }
      `, 180000)
      return res.value
    },
  }

  const xref = {
    name: 'ce_xref',
    description: '反查引用：给一个地址，找出所有引用它的指令（IDA 的 xref）。同时处理「立即数绝对引用」和「RIP 相对寻址」，返回指令地址、所属模块+偏移、指令文本。默认 quick 模式只扫最常见的几种（快），full=true 覆盖全部 ModRM 变体。CE 没有范围限定的扫描接口，所以是整块可执行区全扫：进程大时会慢（几秒到二十几秒，期间 CE 界面不响应），可以用 scope="module" / branch=false 缩小工作量。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: '被引用的地址，例如 0x7FF612340000 或 game.exe+1A2B0' },
        full: { type: 'boolean', description: 'true = 覆盖全部 ModRM 变体（慢），默认只扫高频模式' },
        includeAbsolute: { type: 'boolean', description: '是否扫立即数绝对引用，默认 true' },
        includeRipRelative: { type: 'boolean', description: '是否扫 RIP 相对引用，默认 true' },
        branch: { type: 'boolean', description: '是否扫 call/jmp/jcc 的 rel32 目标（E8/E9/0F8x）。这类指令候选量最大（几十万到上百万），是耗时主因。不填则自动判断：目标地址可执行（是函数）才扫，是普通数据就不扫' },
        scope: { type: 'string', enum: ['all', 'module'], description: 'all = 全地址空间（默认，能找到跨模块引用）；module = 只认目标所在模块内的引用（少扫一部分验证，仍然全空间扫）' },
        protection: { type: 'string', description: '搜索区域，默认 "+X"（可执行）' },
        maxCandidates: { type: 'integer', description: '每个模式最多验证多少个候选，0 = 不限（默认）。CE 的扫描结果按地址升序返回，限制会砍掉高地址部分，非必要别设' },
        limit: { type: 'integer', description: '最多返回多少条，默认 40' },
      },
      required: ['target'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.refs?.length) return text(`没有找到引用（扫了 ${value?.patterns} 个模式 / ${value?.candidates} 个候选 / ${value?.elapsedMs}ms）`)
        const head = value.refs.slice(0, 10).map((r) => `${r.instruction}`).join('\n')
        return text(value.truncated ? `${head}\n⚠ 有 ${value.truncated} 个模式被 maxCandidates 截断，结果可能不全` : head)
      },
    },
    async execute (args) {
      const target = String(args?.target ?? '')
      const full = args?.full === true
      const doAbs = args?.includeAbsolute !== false
      const doRip = args?.includeRipRelative !== false
      const doBranch = args?.branch === undefined ? null : args.branch === true
      const scope = args?.scope === 'module' ? 'module' : 'all'
      const protection = args?.protection === undefined ? '+X' : String(args.protection)
      const maxCand = Math.max(0, Number(args?.maxCandidates) || 0)
      const limit = Math.max(1, Math.min(Number(args?.limit) || 40, 500))
      const res = await lua(`
        local t = dsh_addr(${str(target)})
        if not t or t == 0 then error('地址无法解析: ' .. ${str(target)}) end
        local is64 = targetIs64Bit()
        local limit = ${limit}
        local maxCand = ${maxCand}
        local refs = {}
        local seen = {}
        local patterns = 0
        local candidates = 0
        local inspected = 0
        local truncated = 0
        local stats = {}
        local t0 = os.clock()

        -- scope=module：只认落在目标所在模块里的引用。注意 AOBScan 没有范围参数，
        -- 扫描仍然是全地址空间一遍，这里省掉的只是「逐个读内存验证」那部分。
        local scopeMod = nil
        if ${str(scope)} == 'module' then scopeMod = dsh_module_of(t) end
        local function inScope (a)
          if not scopeMod then return true end
          return a >= scopeMod.base and a < scopeMod.base + scopeMod.size
        end

        -- call/jmp 的 rel32 目标扫描是耗时主因（E8 一个模式就上百万候选），
        -- 只在「目标是代码地址」时才有意义：给数据地址找 call 引用基本是白花钱。
        local wantBranch = ${doBranch === null ? 'nil' : String(doBranch)}
        if wantBranch == nil then
          local reg = dsh_region_of(t)
          local p = reg and reg.protect or 0
          wantBranch = (p == 0x10 or p == 0x20 or p == 0x40 or p == 0x80)
        end

        -- addr 指向一段 width 字节的立即数。真正的指令引用要求这段字节正好落在
        -- 某条指令的末尾（mov reg,imm / C7 /0 imm 都是这个形状）。
        -- 找不到就说明它只是数据里恰好等于目标地址的 4/8 个字节，标注成 :data 让人自己判断。
        -- 注意：回溯要「就近优先」。同一个字节流常有两种合法解码，比如
        --   29: B8 00 08 C9 02      mov eax,imm32   （正确答案）
        --   28: 00 B8 ...           add [rax+disp32],bh 也从 0x2A 开始、也在 0x2A 结束
        -- 从远到近找会挑中 0x28 那条假指令；从近到远找才是真正的指令起点。
        local function locateInsn (addr, width)
          for back = 0, 7 do
            local s = addr - back
            if s > 0x10000 then
              local ok, size = pcall(getInstructionSize, s)
              if ok and type(size) == 'number' and size == back + width then return s end
            end
          end
          return nil
        end

        local function addRef (addr, how, width)
          -- 先判上限再干活：locateInsn 每次要试 8 个反向起点，超限后还算是纯浪费
          if #refs >= limit then return end
          local realAddr = addr
          if width then
            local insn = locateInsn(addr, width)
            if insn then
              realAddr = insn
              how = how .. ':insn'
            else
              how = how .. ':data'
            end
          end
          local key = string.format('%X|%s', realAddr, how)
          if seen[key] then return end
          seen[key] = true
          local m, moff = dsh_module_of(realAddr)
          local text = ''
          local okd, d = pcall(disassemble, realAddr)
          if okd and d then text = d end
          refs[#refs + 1] = {
            address = string.format('%X', realAddr),
            instruction = text,
            how = how,
            module = m and m.name or nil,
            moduleOffset = moff and string.format('%X', moff) or nil,
          }
        end

        -- 统一入口：扫一个模式，逐条验证。candidates 是原始命中数，
        -- inspected 是真正去读内存验证的条数（scope 过滤后），truncated 是被 maxCandidates 砍掉的次数。
        local function eachHit (pat, align, fn)
          patterns = patterns + 1
          local st0 = os.clock()
          local fl = AOBScan(pat, ${str(protection)}, fsmNotAligned, align)
          if not fl then return end
          local n = fl.Count or 0
          candidates = candidates + n
          local stop = n
          if maxCand > 0 and n > maxCand then
            stop = maxCand
            truncated = truncated + 1
          end
          local mine = 0
          for i = 0, stop - 1 do
            local a = tonumber(fl[i], 16)
            if a then
              if inScope(a) then
                inspected = inspected + 1
                mine = mine + 1
                fn(a)
              end
            end
          end
          fl.destroy()
          stats[#stats + 1] = { pattern = pat, hits = n, ms = math.floor((os.clock() - st0) * 1000) }
        end

        -- 绝对引用：内存里直接存着目标地址（4 或 8 字节）
        if ${doAbs} then
          local widths = is64 and { 4, 8 } or { 4 }
          for _, w in ipairs(widths) do
            eachHit(dsh_lebytes(t, w), tostring(w), function (a)
              addRef(a, 'abs' .. (w * 8), w)
            end)
          end
        end

        -- RIP 相对：[addr + insnLen + disp32] = target
        if ${doRip} and is64 then
          local movSet = full and { '05', '0D', '15', '1D', '25', '2D', '35', '3D' } or { '05', '0D', '15', '1D' }
          local ripPats = {}
          if wantBranch then
            ripPats[#ripPats + 1] = { 'E8 ?? ?? ?? ??', 5, 'call' }
            ripPats[#ripPats + 1] = { 'E9 ?? ?? ?? ??', 5, 'jmp' }
            ripPats[#ripPats + 1] = { '0F 84 ?? ?? ?? ??', 6, 'jz' }
            ripPats[#ripPats + 1] = { '0F 85 ?? ?? ?? ??', 6, 'jnz' }
            if full then
              for _, cc in ipairs({ '80', '81', '82', '83', '86', '87', '88', '89', '8A', '8B', '8C', '8D', '8E', '8F' }) do
                ripPats[#ripPats + 1] = { '0F ' .. cc .. ' ?? ?? ?? ??', 6, 'jcc' }
              end
            end
          end
          for _, r in ipairs(movSet) do
            ripPats[#ripPats + 1] = { '48 8B ' .. r .. ' ?? ?? ?? ??', 7, 'mov' }
            ripPats[#ripPats + 1] = { '48 8D ' .. r .. ' ?? ?? ?? ??', 7, 'lea' }
            ripPats[#ripPats + 1] = { '48 89 ' .. r .. ' ?? ?? ?? ??', 7, 'movstore' }
          end
          ripPats[#ripPats + 1] = { 'FF 15 ?? ?? ?? ??', 6, 'callind' }
          ripPats[#ripPats + 1] = { 'FF 25 ?? ?? ?? ??', 6, 'jmpind' }

          for _, p in ipairs(ripPats) do
            local need = p[2]
            eachHit(p[1], '1', function (a)
              -- readInteger 直接返回有符号 32 位。这里一次命中就是一次调用，
              -- 换成 dsh_readle（内部 readBytes 要建一张表）会慢一个数量级。
              local disp = readInteger(a + need - 4)
              if disp and a + need + disp == t then addRef(a, 'rip:' .. p[3]) end
            end)
          end
        end

        table.sort(refs, function (a, b) return tonumber(a.address, 16) < tonumber(b.address, 16) end)
        table.sort(stats, function (a, b) return a.ms > b.ms end)
        local slowest = {}
        for i = 1, math.min(#stats, 8) do slowest[i] = stats[i] end
        return {
          target = string.format('%X', t),
          is64 = is64,
          scope = scopeMod and scopeMod.name or 'all',
          branch = wantBranch and true or false,
          patterns = patterns,
          candidates = candidates,
          inspected = inspected,
          truncated = truncated,
          elapsedMs = math.floor((os.clock() - t0) * 1000),
          count = #refs,
          slowest = slowest,
          refs = refs,
        }
      `, 300000)
      return res.value
    },
  }

  const ptrscan = {
    name: 'ce_ptrscan',
    description: '指针扫描：给一个地址，向上回溯出稳定的指针链（CE 的 Pointer Scan 无头版）。返回所有以「模块映像内的静态地址」为根、能一路解引用到目标地址的链，每条链带模块名和偏移序列。maxBytes 控制扫描范围（默认 64MB，越大越慢），对几百 MB 的游戏堆建议分层试探。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: '目标地址，例如 0x2CD0000 或 game.exe+1A2B0' },
        maxLevel: { type: 'integer', description: '最大层数，默认 4' },
        maxOffset: { type: 'integer', description: '每层偏移上限（十进制或 0x 开头），默认 0x1000' },
        maxResults: { type: 'integer', description: '最多返回多少条链，默认 16' },
        maxBytes: { type: 'integer', description: '最多扫描多少字节的堆内存，默认 67108864（64MB）' },
        pointerSize: { type: 'integer', description: '指针宽度，4 或 8，默认按目标位数' },
      },
      required: ['target'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (!value?.chains?.length) return text(`没有找到链（扫了 ${(value?.scannedBytes / 1048576 || 0).toFixed(1)}MB，${value?.pointerCount} 个指针）`)
        return text(value.chains.slice(0, 6).map((c) => `${c.module}+${c.moduleOffset}  ${c.offsets.map((o) => '+' + o).join(' → ')}`).join('\n'))
      },
    },
    async execute (args) {
      const target = String(args?.target ?? '')
      const maxLevel = Math.max(1, Math.min(Number(args?.maxLevel) || 4, 8))
      const maxOffset = Math.max(0, Math.min(Number(args?.maxOffset) || 0x1000, 0x100000))
      const maxResults = Math.max(1, Math.min(Number(args?.maxResults) || 16, 200))
      const maxBytes = Math.max(1 << 20, Math.min(Number(args?.maxBytes) || 64 << 20, 1 << 30))
      const psArg = Number(args?.pointerSize) === 4 ? 4 : Number(args?.pointerSize) === 8 ? 8 : 0
      const res = await lua(`
        local t = dsh_addr(${str(target)})
        if not t or t == 0 then error('地址无法解析: ' .. ${str(target)}) end
        local is64 = targetIs64Bit()
        local ps = ${psArg} ~= 0 and ${psArg} or (is64 and 8 or 4)
        local maxLevel = ${maxLevel}
        local maxOffset = ${maxOffset}
        local maxResults = ${maxResults}
        local maxBytes = ${maxBytes}
        local t0 = os.clock()

        local regs = dsh_regions()
        -- 64KB 页位图：判断「这个值是不是一个合法地址」从 9 步二分降到一次哈希查表。
        -- 建表只做一次，几万页，但每 8 字节都要问一次，省下来的是百万级的比较。
        local pageMap = {}
        for _, r in ipairs(regs) do
          local p1 = r.base >> 16
          local p2 = (r.base + r.size - 1) >> 16
          for pg = p1, p2 do pageMap[pg] = true end
        end
        local function isMapped (a)
          if a < 0x10000 then return false end
          return pageMap[a >> 16] == true
        end

        -- 值 -> 存放它的位置列表。用哈希桶而不是「先建表再排序」：
        -- 22 万条 table + sort 会把这一步拖到十几秒，哈希插入只多一次查表。
        local pv = {}
        local ptrCount = 0
        local scanned = 0
        for _, r in ipairs(regs) do
          local prot = dsh_prot(r.protect)
          if prot:sub(2, 2) == 'w' and scanned < maxBytes then
            local off = 0
            while off < r.size and scanned < maxBytes do
              local n = math.min(262144, r.size - off)
              local b = readBytes(r.base + off, n, true)
              if b and #b >= ps then
                local stop = #b - (ps - 1)
                local addr0 = r.base + off
                local i = 1
                while i <= stop do
                  local v
                  if ps == 8 then
                    v = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)
                      | (b[i + 4] << 32) | (b[i + 5] << 40) | (b[i + 6] << 48) | (b[i + 7] << 56)
                  else
                    v = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)
                  end
                  if v > 0x10000 and v < 0x7FFFFFFFFFFF and isMapped(v) then
                    local at = addr0 + i - 1
                    local cur = pv[v]
                    if cur == nil then
                      pv[v] = at
                    elseif type(cur) == 'number' then
                      pv[v] = { cur, at }
                    else
                      cur[#cur + 1] = at
                    end
                    ptrCount = ptrCount + 1
                  end
                  i = i + ps
                end
              end
              off = off + n
              scanned = scanned + n
            end
          end
        end

        local results = {}
        local seen = {}
        local queue = { { addr = t, chain = {}, depth = 0 } }
        local head = 1
        while head <= #queue and #results < maxResults do
          local node = queue[head]
          head = head + 1
          if node.depth < maxLevel then
            -- 一层里所有合法偏移：值 == addr - off，直接查哈希桶，不再线性扫全表
            for off = 0, maxOffset do
              local slot = pv[node.addr - off]
              if slot ~= nil then
                local list = (type(slot) == 'number') and { slot } or slot
                for _, p in ipairs(list) do
                  local key = string.format('%X:%d', p, off)
                  if not seen[key] then
                    seen[key] = true
                    local offs = { off }
                    for _, o in ipairs(node.chain) do offs[#offs + 1] = o end
                    local m, moff = dsh_module_of(p)
                    local reg = dsh_region_of(p, regs)
                    if m and reg and reg.kind == 0x1000000 then
                      results[#results + 1] = {
                        base = string.format('%X', p),
                        module = m.name,
                        moduleOffset = string.format('%X', moff),
                        offsets = offs,
                        depth = node.depth + 1,
                      }
                    elseif #queue < 3000 then
                      queue[#queue + 1] = { addr = p, chain = offs, depth = node.depth + 1 }
                    end
                  end
                end
              end
            end
          end
        end

        -- 逐级解引用验证：base 读出的值 + off1 → 下一级…… 最后必须等于 target。
        -- 不验证就输出等于把「看起来像指针」的垃圾丢给调用方。
        local function verifyChain (baseNum, offs)
          local addr = baseNum
          for _, o in ipairs(offs) do
            local v = readPointer(addr)
            if not v or v < 0x10000 then return false end
            addr = v + o
          end
          return addr == t
        end
        for _, c in ipairs(results) do
          c.baseNum = tonumber(c.base, 16) or 0
          c.verified = verifyChain(c.baseNum, c.offsets)
        end

        table.sort(results, function (a, b)
          if a.verified ~= b.verified then return a.verified end
          if a.depth ~= b.depth then return a.depth < b.depth end
          return a.module < b.module
        end)

        local out = {}
        local verifiedCount = 0
        for idx, c in ipairs(results) do
          if idx > maxResults then break end
          local hex = {}
          for _, o in ipairs(c.offsets) do hex[#hex + 1] = string.format('%X', o) end
          if c.verified then verifiedCount = verifiedCount + 1 end
          out[#out + 1] = {
            base = c.base, module = c.module, moduleOffset = c.moduleOffset,
            offsets = hex, depth = c.depth, verified = c.verified,
            expression = c.module .. '+' .. c.moduleOffset .. ' → ' ..
              table.concat((function ()
                local parts = {}
                for _, h in ipairs(hex) do parts[#parts + 1] = '+' .. h end
                return parts
              end)(), ' → '),
          }
        end

        return {
          target = string.format('%X', t),
          pointerSize = ps,
          scannedBytes = scanned,
          pointerCount = ptrCount,
          elapsedMs = math.floor((os.clock() - t0) * 1000),
          verified = verifiedCount,
          chains = out,
        }
      `, 600000)
      return res.value
    },
  }

  const bp = {
    name: 'ce_bp',
    description: '断点（CE 调试器）。set 下断点后，每次命中都会把完整寄存器 + RSP 处的栈回溯（只留落在模块内的返回地址）追加写进一个日志文件，不占 Lua 状态，所以随时能查。action=hits 读这份日志。需要先 ce_attach 带 debug=true。注意：命中记录靠 CE 的调试回调写盘，必须先 set 再让目标运行起来，别指望同步返回。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['set', 'list', 'hits', 'remove', 'clear'], description: 'set 下断点 / list 看有哪些断点 / hits 读命中记录 / remove 删一个 / clear 全清' },
        address: { type: 'string', description: '断点地址（set / remove / hits 用）' },
        size: { type: 'integer', description: '监视宽度（write/access 时有效），默认 4' },
        trigger: { type: 'string', enum: ['execute', 'write', 'access'], description: '触发类型，默认 write' },
        threadId: { type: 'integer', description: '只对该线程生效；不填则对所有线程' },
        maxHits: { type: 'integer', description: '命中多少次后自动摘掉断点，默认 200' },
        stackDepth: { type: 'integer', description: '栈回溯扫描的指针个数，默认 48' },
        limit: { type: 'integer', description: 'hits 最多返回多少条记录，默认 20' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render (_args, value) {
        if (value?.hits) {
          if (!value.hits.length) return text(`暂无命中（日志 ${value.logPath || ''}）`)
          const h = value.hits[0]
          return text(`${value.hits.length} 次命中，首次 RIP=${h.regs?.RIP} ${h.stack?.[0]?.where || ''}`)
        }
        if (value?.breakpoints) return text(value.breakpoints.length ? `共 ${value.breakpoints.length} 个断点` : '没有断点')
        return text(value?.ok ? `已下断点 ${value.address}` : 'done')
      },
    },
    async execute (args) {
      const action = ['set', 'list', 'hits', 'remove', 'clear'].includes(args?.action) ? args.action : 'list'
      const address = String(args?.address ?? '')
      const size = Math.max(1, Math.min(Number(args?.size) || 4, 8))
      const trig = ['execute', 'write', 'access'].includes(args?.trigger) ? args.trigger : 'write'
      const threadId = Number(args?.threadId) || 0
      const maxHits = Math.max(1, Math.min(Number(args?.maxHits) || 200, 100000))
      const stackDepth = Math.max(0, Math.min(Number(args?.stackDepth) || 48, 512))
      const limit = Math.max(1, Math.min(Number(args?.limit) || 20, 500))

      try { mkdirSync(BP_DIR, { recursive: true }) } catch {}

      if (action === 'list') {
        const state = await lua(`return { dbg = (function () local o, v = pcall(debug_isDebugging) return o and v == true or false end)() }`, 20000).catch(() => null)
        return { isDebugging: state?.value?.dbg === true, breakpoints: listBpFiles() }
      }

      if (action === 'clear') {
        const files = listBpFiles()
        for (const f of files) { try { unlinkSync(join(BP_DIR, `${f.address}.log`)) } catch {} }
        await lua(`
          for _, a in ipairs({${files.map((f) => `0x${f.address}`).join(',')}}) do
            pcall(debug_removeBreakpoint, a)
          end
          return { cleared = ${files.length} }
        `, 20000).catch(() => null)
        return { ok: true, removed: files.length }
      }

      // 解析地址（支持 module+offset / 符号 / 0x）
      const resolved = await lua(`local a = dsh_addr(${str(address)}) if not a or a == 0 then error('地址无法解析: ' .. ${str(address)}) end return { hex = string.format('%X', a) }`, 20000)
      const hex = resolved.value.hex
      const logPath = join(BP_DIR, `${hex}.log`)

      if (action === 'remove') {
        await lua(`pcall(debug_removeBreakpoint, 0x${hex}) return 1`, 20000)
        try { unlinkSync(logPath) } catch {}
        return { ok: true, removed: hex }
      }

      if (action === 'hits') {
        return { address: hex, logPath, hits: readBpFile(hex, limit) }
      }

      // set
      try { writeFileSync(logPath, '', 'utf8') } catch {}
      const res = await lua(`
        local addr = 0x${hex}
        local path = ${str(logPath)}
        local REG = { 'RIP','RSP','RAX','RBX','RCX','RDX','RSI','RDI','RBP','R8','R9','R10','R11','R12','R13','R14','R15','EFLAGS' }
        local TRIG = { execute = bptExecute, write = bptWrite, access = bptAccess }
        local depth = ${stackDepth}
        local maxHits = ${maxHits}
        local hits = 0
        local function onHit ()
          debug_getContext(true)
          hits = hits + 1
          local reg = {}
          for _, k in ipairs(REG) do
            local v = _G[k]
            reg[#reg + 1] = (type(v) == 'number') and string.format('%X', v) or ''
          end
          local st = {}
          local sp = _G.RSP
          if sp and depth > 0 and type(sp) == 'number' then
            for i = 0, depth - 1 do
              local v = readPointer(sp + i * 8)
              if v and v > 0x10000 then
                local m, mo = dsh_module_of(v)
                if m then
                  st[#st + 1] = string.format('%X@%s+%X', v, m.name, mo)
                  if #st >= 6 then break end
                end
              end
            end
          end
          local f = io.open(path, 'a')
          if f then
            f:write(table.concat(reg, '|') .. '#' .. table.concat(st, ',') .. '\\n')
            f:close()
          end
          if hits >= maxHits then pcall(debug_removeBreakpoint, addr) end
          pcall(debug_continueFromBreakpoint, co_run)
        end
        local ok, err
        if ${threadId} > 0 then
          ok, err = pcall(debug_setBreakpointForThread, ${threadId}, addr, ${size}, TRIG[${str(trig)}] or bptWrite, function () onHit() end)
        else
          ok, err = pcall(debug_setBreakpoint, addr, ${size}, TRIG[${str(trig)}] or bptWrite, function () onHit() end)
        end
        if not ok then error('下断点失败: ' .. tostring(err) .. '（确认 ce_attach 时传了 debug=true）') end
        return { ok = true, address = string.format('%X', addr), trigger = ${str(trig)}, size = ${size}, logPath = path }
      `, 30000)
      return res.value
    },
  }

  const install = {
    name: 'ce_install',
    description: '安装/修复 Cheat Engine 桥：自动把加载钩子写进 CE 的 main.lua（先备份），并回报当前在线状态。',
    parameters: { type: 'object', properties: { fix: { type: 'boolean', description: '是否写入 main.lua 钩子，默认 true' } }, additionalProperties: false },
    output: { schema: { type: 'object', additionalProperties: true }, render (_args, value) { return text(value?.online ? '桥已在线' : (value?.hook?.ok ? '钩子已就位，重启 CE 后生效' : '桥未接入')) } },
    async execute (args) {
      const hook = args?.fix === false ? { skipped: true } : ensureMainLuaHook()
      const alive = readAlive()
      const ceDir = findCeDir()
      return {
        online: alive.online,
        cePid: alive.pid,
        hook,
        bridgeLuaPath: BRIDGE_LUA,
        bridgeLuaExists: existsSync(BRIDGE_LUA),
        deployed: deploy,
        mailDir: MAIL,
        ceDir: ceDir || '(未找到)',
        hookLine: `pcall(dofile, [[${BRIDGE_LUA.replace(/\\/g, '/')}]])`,
        hint: alive.online ? 'CE 已连上，直接用 ce_lua / ce_attach 等工具即可。' : INSTALL_HINT,
      }
    },
  }

  const tools = [status, runLua, ps, attach, modules, read, write, aob, disasm, scanStart, scanNext, scanResults, scanReset, aa, install, regions, scanMulti, xref, ptrscan, bp]
  for (const tool of tools) ctx.effect(() => ctx.tools.register(tool))

  // ---------------- HTTP 路由（给小窗口用）----------------
  ctx.inject(['webServer'], (webCtx) => {
    const sendJson = (res, statusCode, payload) => {
      if (res.writableEnded) return
      const body = JSON.stringify(payload)
      res.statusCode = statusCode
      res.setHeader('content-type', 'application/json; charset=utf-8')
      res.setHeader('content-length', Buffer.byteLength(body))
      res.end(body)
    }

    const readJsonBody = (req) => new Promise((resolve, reject) => {
      let raw = ''
      req.setEncoding('utf8')
      req.on('data', (chunk) => {
        raw += chunk
        if (raw.length > 2 * 1024 * 1024) { reject(new Error('请求体过大')); try { req.destroy() } catch {} }
      })
      req.on('end', () => {
        if (!raw.trim()) { resolve({}); return }
        try { resolve(JSON.parse(raw)) } catch { reject(new Error('请求体不是合法 JSON')) }
      })
      req.on('error', reject)
    })

    const route = (path, handler) => webCtx.effect(() => webCtx.webServer.register({
      kind: 'exact',
      path,
      handler: async (req, res) => {
        try { await handler(req, res) } catch (error) {
          sendJson(res, 500, { error: String(error?.message ?? error) })
        }
      },
    }))

    route('/api/dsh-ce/status', async (req, res) => {
      if (req.method !== 'GET') { sendJson(res, 405, { error: '只支持 GET' }); return }
      const alive = readAlive()
      if (!alive.online) { sendJson(res, 200, { online: false, hint: INSTALL_HINT, bridgePath: BRIDGE_LUA }); return }
      const result = await lua(`return { ce = getCEVersion(), pid = getOpenedProcessID(), process = process or '' }`)
      sendJson(res, 200, { online: true, cePid: alive.pid, ...result.value })
    })

    route('/api/dsh-ce/processes', async (req, res) => {
      if (req.method !== 'GET') { sendJson(res, 405, { error: '只支持 GET' }); return }
      const result = await lua(`
        local t = getProcesslist()
        local out = {}
        for k, v in pairs(t) do
          local pid, name
          if type(k) == 'number' then pid, name = k, tostring(v) else pid, name = tonumber(v), tostring(k) end
          if pid and pid > 0 then out[#out + 1] = { pid = pid, name = name } end
        end
        table.sort(out, function (a, b) return a.name:lower() < b.name:lower() end)
        return out
      `, 30000)
      sendJson(res, 200, { processes: Array.isArray(result.value) ? result.value : [] })
    })

    route('/api/dsh-ce/attach', async (req, res) => {
      if (req.method !== 'POST') { sendJson(res, 405, { error: '只支持 POST' }); return }
      const body = await readJsonBody(req)
      const pid = Number(body?.pid) || 0
      if (!pid) { sendJson(res, 400, { error: '缺少 pid' }); return }
      const result = await lua(`
        openProcess(${pid})
        local opened = getOpenedProcessID()
        if opened ~= ${pid} then error('openProcess 失败，CE 仍指向 ' .. tostring(opened)) end
        return { pid = ${pid}, process = process or '', is64 = (function() local o, v = pcall(targetIs64Bit) return o and v or false end)() }
      `, 30000)
      sendJson(res, 200, result.value)
    })

    route('/api/dsh-ce/lua', async (req, res) => {
      if (req.method !== 'POST') { sendJson(res, 405, { error: '只支持 POST' }); return }
      const body = await readJsonBody(req)
      const code = String(body?.code ?? '')
      if (!code.trim()) { sendJson(res, 400, { error: '缺少 code' }); return }
      const result = await bridge('eval', code, Number(body?.timeoutMs) || 60000)
      sendJson(res, 200, result)
    })
  })
}

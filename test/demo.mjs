// 分级自检：走插件的真实工具接口，全部在 CE 自身进程内完成，不改动任何外部程序。
//
//   node test/demo.mjs
//
// 前提：CE 已经启动，且 bridge 已加载（main.lua 里的钩子，或手动 dofile 过）。
// 全程只碰 CE 自己新分配的临时内存，不会动 CE 的已有数据，也不会附加到别的进程。
import { execSync } from 'node:child_process'

const tools = new Map()
const fakeCtx = {
  get tools () { return { register (t) { tools.set(t.name, t) } } },
  effect (fn) { fn(); return () => {} },
  inject (_d, cb) { cb({ effect: (f) => { f(); return () => {} }, get webServer () { return { register () { return () => {} } } } }) },
  logger () { return { info () {}, warn () {}, error () {} } },
}
const mod = await import('../index.js')
mod.apply(fakeCtx)

let pass = 0
let fail = 0
async function step (label, name, args, show) {
  const t0 = Date.now()
  try {
    const r = await tools.get(name).execute(args)
    const ms = Date.now() - t0
    console.log(`  [OK] ${label.padEnd(26)} ${String(ms).padStart(4)}ms  ${show(r)}`)
    pass++
    return r
  } catch (e) {
    console.log(`  [!!] ${label.padEnd(26)}        ${String(e?.message ?? e).slice(0, 120)}`)
    fail++
    return null
  }
}

function findCePid () {
  try {
    const out = execSync('tasklist /FI "IMAGENAME eq cheatengine-x86_64.exe" /FO CSV /NH', { encoding: 'latin1' })
    const pid = Number(out.split('\n')[0].split(',')[1]?.replace(/"/g, ''))
    return Number.isFinite(pid) && pid > 0 ? pid : null
  } catch {
    return null
  }
}

const cePid = findCePid()
if (!cePid) {
  console.error('找不到 cheatengine-x86_64.exe。先启动 Cheat Engine 再来。')
  console.error('如果 CE 明明开着，可能是 32 位版本 —— 把下面的 IMAGENAME 换成 cheatengine-i386.exe 自己跑一遍。')
  process.exit(1)
}

console.log(`目标：CE 自身 pid=${cePid}\n`)

console.log('① 连通')
const st = await step('ce_status', 'ce_status', {}, (r) => `online=${r.online} ce=${r.ce ?? '?'}`)
if (st && st.online === false) {
  console.log('\n桥没上线。先按 README「一、接入 CE」把 main.lua 钩子装上（或跑 ce_install），再重启 CE。')
  process.exit(1)
}

console.log('\n② 进程与附加')
await step('ce_ps filter=cheat', 'ce_ps', { filter: 'cheat', limit: 10 }, (r) => `命中 ${(r.list ?? r.processes ?? []).length} 个`)
await step('ce_attach 到 CE 自身', 'ce_attach', { pid: cePid }, (r) => `attached pid=${r.pid ?? cePid}`)

console.log('\n③ 读内存与模块')
const mods = await step('ce_modules', 'ce_modules', {}, (r) => `${r.total ?? 0} 个模块`)
const m0 = mods?.modules?.[0]
const base = m0 ? `0x${Number(m0.base).toString(16)}` : '0x0'
console.log(`       首模块 ${m0?.name} @ ${base}`)
await step('ce_read MZ 头', 'ce_read', { address: base, type: 'bytes', count: 4 }, (r) => r.hex ?? JSON.stringify(r.bytes))
await step('ce_disasm 3 条', 'ce_disasm', { address: base, count: 3 }, (r) => String((r.list ?? r.instructions ?? []).slice(0, 2).map((x) => x.text ?? x).join(' | ')))

console.log('\n④ 写内存（在 CE 里新分配一块临时内存，不碰任何已有数据）')
const alloc = await step('ce_lua allocateMemory', 'ce_lua', {
  code: 'local a = allocateMemory(4096) writeInteger(a, 4242) return { addr = string.format("%X", a) }',
}, (r) => `addr=0x${r.value?.addr ?? r.addr}`)
const addr = `0x${alloc?.value?.addr ?? alloc?.addr}`
await step('ce_read 初始值', 'ce_read', { address: addr, type: 'dword' }, (r) => `${r.value}`)
await step('ce_write 改成 9999', 'ce_write', { address: addr, type: 'dword', value: '9999' }, (r) => `ok=${r.ok ?? true}`)
await step('ce_read 回读', 'ce_read', { address: addr, type: 'dword' }, (r) => `${r.value}`)

console.log('\n⑤ CE 式扫描收敛')
await step('scan_start exact=9999', 'ce_scan_start', { type: 'dword', mode: 'exact', value: '9999' }, (r) => `首次命中 ${r.count}`)
await step('scan_next exact=9999', 'ce_scan_next', { mode: 'exact', value: '9999' }, (r) => `收敛到 ${r.count}`)
const targetHex = String(alloc?.value?.addr ?? '0')
await step('目标地址是否在结果里', 'ce_lua', {
  code: `local ms = _G.__DSH_SCAN and _G.__DSH_SCAN.ms
  if not ms then return { found = false, reason = 'no session' } end
  local fl = createFoundList(ms)
  fl.initialize()
  local want = tonumber('${targetHex}', 16)
  local found = false
  for i = 0, fl.Count - 1 do
    if tonumber(fl.getAddress(i), 16) == want then found = true break end
  end
  fl.deinitialize()
  return { found = found, count = fl.Count }`,
}, (r) => `我们写入的 0x${targetHex} ${r.value?.found ? '在结果中 ✓' : '不在结果中'}`)
await step('scan_reset', 'ce_scan_reset', {}, () => 'done')

console.log('\n⑥ 特征码与自动汇编')
await step('ce_aob 扫 MZ 头附近', 'ce_aob', { pattern: '4D 5A 90 00', protection: '', limit: 5 }, (r) => `${(r.list ?? r.addresses ?? []).length} 处`)
await step('ce_aa 空脚本', 'ce_aa', { script: '[ENABLE]\n\n[DISABLE]\n' }, (r) => `enabled=${r.enabled}`)

console.log('\n⑦ 内存区域 / 多值扫描 / 反查引用 / 指针扫描')
await step('ce_regions 可写区域', 'ce_regions', { writable: true, limit: 5 }, (r) => `${r.total} 个 / ${((r.totalBytes ?? 0) / 1048576).toFixed(0)}MB`)
await step('ce_scan_multi 三个值', 'ce_scan_multi', { values: '4242 9999 0x5A5A', limitPerValue: 3 }, (r) => {
  const g = r.groups ?? []
  return g.map((x) => `${x.value}:${x.count}`).join('  ')
})
// 下面两步只验证「能跑通、返回结构对」，不验证命中：
// 目标是我们刚分配的一块堆内存，没有静态代码引用它、也没有静态指针指向它，
// 所以 0 条引用 / 0 条链是**预期结果**。要看到真实命中，用 README 第四节 C 的靶子。
await step('ce_xref 反查数据地址', 'ce_xref', { target: addr, includeRipRelative: false, limit: 10 }, (r) => {
  const n = r.count ?? 0
  return `${n} 条引用 / 候选 ${r.candidates ?? '?'} / ${r.elapsedMs}ms${n === 0 ? '（新分配的堆没人引用，预期如此）' : ''}`
})
await step('ce_ptrscan 2 层', 'ce_ptrscan', { target: addr, maxLevel: 2, maxOffset: 0x200, maxResults: 3, maxBytes: 24 << 20 }, (r) => {
  const c = r.chains ?? []
  const ok = c.filter((x) => x.verified === true).length
  const scan = `扫 ${((r.scannedBytes ?? 0) / 1048576).toFixed(0)}MB / ${r.elapsedMs}ms`
  return c.length ? `${c.length} 条链 / 已验证 ${ok} / ${scan}` : `0 条链 / ${scan}（临时内存无静态指针，预期如此）`
})

console.log(`\n合计：通过 ${pass}，失败 ${fail}`)
if (fail > 0) process.exit(1)

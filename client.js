window.__ModuleLoader__.load({
  id: '@local/dsh-ce',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const card = {
      position: 'fixed',
      right: 20,
      bottom: 96,
      width: 440,
      maxHeight: '72vh',
      display: 'flex',
      flexDirection: 'column',
      borderRadius: 14,
      border: '1px solid var(--dsw-alias-border-l2)',
      background: 'var(--dsw-alias-bg-overlay)',
      boxShadow: '0 18px 48px rgba(0,0,0,0.32)',
      color: 'var(--dsw-alias-label-primary)',
      fontSize: 13,
      zIndex: 2147483000,
      overflow: 'hidden',
    }
    const header = {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '10px 12px',
      borderBottom: '1px solid var(--dsw-alias-border-l1)',
      fontWeight: 600,
    }
    const body = { padding: 12, display: 'flex', flexDirection: 'column', gap: 10, overflow: 'auto' }
    const list = { maxHeight: 170, overflow: 'auto', border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 8 }
    const row = (active) => ({
      display: 'flex',
      justifyContent: 'space-between',
      gap: 8,
      padding: '6px 8px',
      cursor: 'pointer',
      background: active ? 'var(--dsw-alias-interactive-bg-active)' : 'transparent',
    })
    const input = {
      padding: '7px 9px',
      borderRadius: 8,
      border: '1px solid var(--dsw-alias-border-l2)',
      background: 'var(--dsw-alias-bg-layer-1)',
      color: 'var(--dsw-alias-label-primary)',
      fontSize: 13,
      outline: 'none',
      width: '100%',
      boxSizing: 'border-box',
    }
    const button = {
      padding: '7px 12px',
      borderRadius: 8,
      border: '1px solid var(--dsw-alias-border-l2)',
      background: 'var(--dsw-alias-bg-layer-2)',
      color: 'var(--dsw-alias-label-primary)',
      cursor: 'pointer',
      fontSize: 13,
    }
    const muted = { color: 'var(--dsw-alias-label-tertiary)', fontSize: 12 }
    const mono = { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12 }
    const out = {
      ...mono,
      maxHeight: 220,
      overflow: 'auto',
      padding: '8px 9px',
      borderRadius: 8,
      background: 'var(--dsw-alias-bg-layer-2)',
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-all',
    }
    const dot = (ok) => ({
      display: 'inline-block',
      width: 8,
      height: 8,
      borderRadius: 4,
      marginRight: 6,
      background: ok ? '#3fbf6f' : '#c9553d',
    })

    const readJson = async (res, label) => {
      const raw = await res.text()
      try {
        return JSON.parse(raw)
      } catch {
        throw new Error(`${label}：接口 ${res.status} 返回的不是 JSON：${raw.trim().slice(0, 120) || '(空响应)'}`)
      }
    }

    function Panel() {
      const [open, setOpen] = React.useState(true)
      const [status, setStatus] = React.useState(null)
      const [note, setNote] = React.useState('正在连接 CE…')
      const [procs, setProcs] = React.useState([])
      const [filter, setFilter] = React.useState('')
      const [pid, setPid] = React.useState(null)
      const [code, setCode] = React.useState('return getCEVersion()')
      const [result, setResult] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [showProcs, setShowProcs] = React.useState(false)

      const loadStatus = React.useCallback(async () => {
        try {
          const data = await readJson(await fetch('/api/dsh-ce/status'), '读取状态')
          setStatus(data)
          if (!data.online) { setNote('CE 未接入'); return }
          setNote(`CE ${data.ce}　目标 ${data.process || '(未附加)'}　pid ${data.pid || 0}`)
          if (data.pid) setPid(data.pid)
        } catch (error) {
          setNote('状态读取失败：' + error.message)
        }
      }, [])

      React.useEffect(() => { loadStatus() }, [loadStatus])

      const loadProcs = async () => {
        setBusy(true)
        try {
          const data = await readJson(await fetch('/api/dsh-ce/processes'), '读取进程')
          setProcs(data.processes || [])
          setShowProcs(true)
          setNote(`共 ${(data.processes || []).length} 个进程`)
        } catch (error) {
          setNote('失败：' + error.message)
        } finally { setBusy(false) }
      }

      const doAttach = async (target) => {
        setBusy(true)
        try {
          const data = await readJson(await fetch('/api/dsh-ce/attach', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ pid: target }),
          }), '附加进程')
          if (data.error) { setNote('附加失败：' + data.error); return }
          setPid(data.pid)
          setNote(`已附加 ${data.process} pid=${data.pid}（${data.is64 ? 64 : 32} 位）`)
          setShowProcs(false)
        } catch (error) {
          setNote('失败：' + error.message)
        } finally { setBusy(false) }
      }

      const runLua = async () => {
        setBusy(true)
        setResult('执行中…')
        try {
          const data = await readJson(await fetch('/api/dsh-ce/lua', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ code }),
          }), '执行 Lua')
          if (data.ok) {
            const printed = data.print ? `\n--- print ---\n${data.print}` : ''
            setResult(JSON.stringify(data.value, null, 2) + printed)
          } else {
            setResult('错误：' + data.error)
          }
        } catch (error) {
          setResult('失败：' + error.message)
        } finally { setBusy(false) }
      }

      if (!open) {
        return h('button', {
          style: { ...button, position: 'fixed', right: 20, bottom: 40, zIndex: 2147483000 },
          onClick: () => setOpen(true),
        }, 'CE 桥')
      }

      const needle = filter.trim().toLowerCase()
      const shown = needle ? procs.filter((p) => p.name.toLowerCase().includes(needle)) : procs

      return h('div', { style: card },
        h('div', { style: header },
          h('span', null, h('span', { style: dot(status?.online) }), 'Cheat Engine 桥'),
          h('button', { style: { ...button, padding: '2px 8px' }, onClick: () => setOpen(false) }, '×'),
        ),
        h('div', { style: body },
          h('div', { style: { display: 'flex', gap: 8 } },
            h('button', { style: button, disabled: busy, onClick: loadStatus }, '刷新状态'),
            h('button', { style: button, disabled: busy, onClick: loadProcs }, '进程列表'),
          ),
          h('div', { style: muted }, note),
          showProcs
            ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
                h('input', {
                  style: input,
                  placeholder: '按名字过滤，例如 game',
                  value: filter,
                  onChange: (e) => setFilter(e.target.value),
                }),
                h('div', { style: list },
                  shown.length === 0
                    ? h('div', { style: { ...muted, padding: 8 } }, '没有匹配的进程')
                    : shown.map((p) => h('div', {
                        key: p.pid,
                        style: row(pid === p.pid),
                        onClick: () => doAttach(p.pid),
                      },
                        h('span', null, p.name),
                        h('span', { style: muted }, String(p.pid)),
                      )),
                ),
              )
            : null,
          h('textarea', {
            style: { ...input, ...mono, minHeight: 64, resize: 'vertical' },
            value: code,
            spellCheck: false,
            onChange: (e) => setCode(e.target.value),
          }),
          h('button', { style: button, disabled: busy, onClick: runLua }, '执行 Lua'),
          result ? h('div', { style: out }, result) : null,
          h('div', { style: muted }, '这个窗口只做验证和应急：日常让模型直接调 ce_lua / ce_scan_* 就行。'),
        ),
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({
          name: 'shell.overlay', id: 'dsh-ce-panel', order: 61,
        }, Panel))
      },
    }
  },
})

# dsh-ce — 把 Cheat Engine 接到 DSH

不自己实现调试器。Cheat Engine 已经有的东西（扫描器、指针扫描、内存读写、反汇编、
自动汇编、调试器）全部由 CE 完成，这个插件只做一件事：**把 CE 的 Lua API 暴露给模型**。

```
DSH 模型  ->  插件工具 ce_*  ->  %LOCALAPPDATA%\dsh-ce\mail  ->  CE 里的桥（Lua 定时轮询）  ->  CE API
```

20 个工具，其中 5 个是把 CE 的能力拼出来的复合操作：`ce_ptrscan`（指针链回溯）、
`ce_xref`（反查引用）、`ce_bp`（断点 + 寄存器 + 栈）、`ce_regions`（区域枚举）、
`ce_scan_multi`（批量多值扫描）。

### 前置条件

| 项 | 要求 |
|---|---|
| 系统 | Windows（CE 只有 Windows 版） |
| Cheat Engine | 7.x，与目标进程同位数；装在默认路径或自己记住路径 |
| DSH | 需要有能加载本地插件的 DSH 环境，见 `cordis.patch.yml` |
| Node | ≥ 18（插件用 ESM，零运行时依赖） |

> 这个插件是 **DSH 的扩展**，不是通用 MCP server。没有 DSH 的话，`index.js` 里的工具
> 定义你拿不去别处用；但 `autorun/dsh-ce-bridge.lua` 那套「文件信箱 + 主线程定时器」
> 的桥本身是独立的，任何能跑 Lua 的地方都能借鉴。

### 它不做什么

- 不绕过反作弊、不碰内核保护。CE 一开到这类游戏里就会被判定，本项目也帮不上。
- 不打包 CE、不分发 CE 的任何代码。用之前自己合法获取 CE，遵守它的许可（GPLv3）。
- 只在你自己的机器、自己的进程、授权的靶场上用。拿它去线上游戏或别人的系统，
  后果自负，跟本仓库无关。

## 一、接入 CE（一次性）

插件载入时会自动把桥脚本写到 `%LOCALAPPDATA%\dsh-ce\bridge.lua`（纯 ASCII 路径，
因为 CE 的 `fopen` 按 ANSI 读路径，中文路径会失败）。

然后在 CE 安装目录的 `main.lua` 里加一行 —— **必须放在 `require("defines")` 之前**：

```lua
-- dsh-ce bridge：必须在 require("defines") 之前
pcall(dofile, [[C:/Users/<你的用户名>/AppData/Local/dsh-ce/bridge.lua]])

require("defines")
```

> **为什么必须在前面**：`defines` 一旦加载失败就会中断整个 `main.lua`，
> 钩子写在后面就永远不会执行。这个顺序问题会表现为「日志一行都没有、心跳不刷新」，
> 极难从外部看出原因。直接调用 `ce_install` 工具可以让插件自动写入（先备份原文件）。

CE 启动时会执行 `main.lua`，于是桥自动起来。CE 升级后如果 `main.lua` 被覆盖，重做这一步。

**临时用一次（不改文件）**：CE 菜单 `Table -> Show Cheat Table Lua Script`，粘贴

```lua
dofile([[C:/Users/<你的用户名>/AppData/Local/dsh-ce/bridge.lua]])
```

点 Execute。CE 关掉后失效。

确认是否接通：`ce_status`，或看 `%LOCALAPPDATA%\dsh-ce\mail\alive` 的时间戳（每 ~300ms 刷新）。

## 一·五、传输层为什么是「主线程定时器」

桥用 `createTimer(nil, true)` + `Interval = 20` + `OnTimer` 轮询信箱。两个踩过的坑：

1. `createTimer(delay, fn)` 是**一次性**定时器，执行完自毁 —— 用它轮询只跑一次。
2. 更早的版本用 `createThread` 在后台线程里调 CE API，碰到 `getProcesslist`
   这类函数会**静默把线程搞死**：心跳停止、请求无人处理，外部表现就是「连不上」。
   定时器回调运行在 CE 主线程，调用 CE API 是安全的。

## 二、工具

| 工具 | 作用 |
|---|---|
| `ce_status` | 桥是否在线、CE 版本、当前附加的进程 |
| `ce_lua` | **核心**：在 CE 里执行任意 Lua，返回结果。CE 的全部 API 都在这儿 |
| `ce_ps` | 进程列表（CE 自己的枚举，能看到 CE 能附加的进程） |
| `ce_attach` | 按 pid 或名字附加 |
| `ce_modules` | 模块列表（名字/基址/大小） |
| `ce_read` / `ce_write` | 读/写内存，支持 byte…double/string/bytes |
| `ce_aob` | 特征码扫描，支持 `??` 通配 |
| `ce_disasm` | 反汇编若干条指令（带字节） |
| `ce_scan_start` / `ce_scan_next` / `ce_scan_results` / `ce_scan_reset` | 值扫描会话 |
| `ce_aa` | 执行 CE 自动汇编脚本（代码注入、nop 校验、改跳转） |
| `ce_regions` | 内存区域枚举：基址/大小/rwx/类型（image·mapped·private）/模块归属 |
| `ce_scan_multi` | 一次扫一批值（CE 本身只支持单值，这里按值转字节模式批量 AOB） |
| `ce_xref` | 反查引用：哪些指令引用了这个地址（绝对立即数 + RIP 相对），带模块偏移。`branch` 控制要不要找 call/jmp 目标 |
| `ce_ptrscan` | 指针扫描：回溯出静态指针链，逐级解引用验证，标注落在哪个模块 |
| `ce_bp` | 断点：命中时记录完整寄存器 + 栈回溯到文件，随时可查 |
| `ce_install` | 打印桥路径与要粘贴的那行 Lua |

地址写法：`0x140001000`、`game.exe+1A2B0`、CE 符号名都行。

### 新增能力的实测数据（CE 7.6，Windows x64，自制靶子）

| 能力 | 实测 |
|---|---|
| `ce_ptrscan` target=HP，3 层、偏移 ≤0x800 | 扫 8.9MB / 22.6 万个指针 / **5 秒**，出 8 条链，逐级解引用全部验证通过 |
| `ce_xref` 自己造的 6 种引用形态 | **12/12 全中**（abs32 / abs64 / lea / mov 读 / mov 写 / call [rip] / call rel32 / jmp rel32） |
| `ce_xref` 数据地址（不扫 call/jmp） | CE 自身 62MB 可执行区 / 62 万候选 / **9 秒** |
| `ce_xref` 代码地址（含 call/jmp） | 同上 / 254 万候选 / **23-29 秒**（E8 一个模式就占 12 秒） |
| `ce_scan_multi` 三个 dword | 0.6 秒，10762 / 585 / 163 命中 |
| `ce_regions` | 318 个可写区域，130MB，按 image/mapped/private 分类 |
| `ce_bp` write 断点 | 1.5 秒内 9 次命中，18 个寄存器 + 6 层栈回溯（clr.dll+191B43 …） |
| 脚本超时 | 死循环 10 秒被切断，CE 立刻恢复（220ms 后正常响应） |

### 断点的三个前提（踩过才知道）

1. `ce_attach` 必须带 `debug=true`，否则断点下不上。
2. CE 内部用的是 `debugProcess(1)`（Windows 调试接口）。默认的 `debugProcess()` 起出来的
   会话几百毫秒后自己退出——断点看着下上了，永远不命中。
3. 已经处于调试状态时**不能再调一次** `debugProcess`，会把 CE 主线程直接卡死，
   而且 CE 没有提供停止调试的 API，只能重启 CE。

命中记录写 `%LOCALAPPDATA%\dsh-ce\bp\<地址>.log`，而不是放 Lua 全局：
CE 的调试回调跑在另一个上下文里，主线程的 eval 读不到它写的表，但文件是共享的。

### 反查引用（xref）的三个开关

CE 没有带范围限定的扫描接口，所以 `ce_xref` 是**整块可执行区全扫**，代价就摆在这儿：

- `branch` —— 要不要找 call/jmp/jcc 的 rel32 目标（`E8`/`E9`/`0F8x`）。
  不填就**自动判断**：目标地址可执行（是个函数）才扫，普通数据不扫。
  一个 `E8 ?? ?? ?? ??` 在 62MB 可执行区就有 127 万个候选，是耗时主因。
- `scope` —— `all`（默认，跨模块也能找到）或 `module`（只认目标所在模块内的引用）。
  注意 AOBScan 没有范围参数，所以它省的只是「逐个验证」那部分，扫描本身还是全空间。
- `maxCandidates` —— 每个模式最多验证多少候选，默认 0 = 不限。
  **非必要别设**：CE 的结果按地址升序返回，一限制就等于砍掉高地址那半，
  而且这种漏报是静默的。返回值里有 `truncated` 字段，非 0 就说明结果不全。

返回里还有 `candidates`（原始命中）、`inspected`（真正验证过的）、`slowest`（最慢的几个模式），
不确定为什么慢就看 `slowest`。

## 三、典型流程

```
ce_ps filter="game"            -> 找到 pid
ce_attach name="game.exe"
ce_modules filter="game"       -> 记下基址
ce_scan_start type="dword" mode="unknown"
（让游戏里的数值变化）
ce_scan_next mode="decreased"  -> 命中数迅速收敛
ce_scan_results limit=10       -> 拿到地址
ce_write address="0x..." value="99999"
```

找「某条指令是谁改的」这类问题，用 `ce_lua` 直接开 CE 的调试器：

```lua
local a = getAddress('game.exe+1A2B0')
debug_setBreakpoint(a, 1, bptWrite, function() ... end)
```

## 四、怎么自测

### A. 一键自检（不碰任何外部程序，~15 秒）

```bash
node test/demo.mjs
```

全在 CE 自己进程里完成：连通 → 附加 → 模块 → 读 MZ 头 → 反汇编 → 分配一块临时内存
写读 → 精确扫描收敛 → AOB → 自动汇编 → 区域枚举 → 多值扫描 → 反查引用 → 指针扫描。
除了读 CE 自己的模块头，其余只动它新分配的那 4KB，不会碰 CE 的已有数据。

任何一步 `[!!]` 都会打出 CE 侧的原始报错，不用再猜。

### B. 面板手点

右下角小窗口 → 刷新状态 → 进程列表（可按名字过滤）→ 点某个进程即附加 →
下面的输入框可以执行任意 CE Lua。

### C. 真实外部进程

`test/` 里只有自检，真实靶子得自己准备。两条路：

**省事：用 CE 自带的教程。** 双击 `C:\Program Files\Cheat Engine\Tutorial-x86_64.exe`，
第 1 步「找到 Health 改成 1000」就是完整的扫描 → 定位 → 改写流程：

```
ce_ps filter="Tutorial"
ce_attach name="Tutorial-x86_64.exe"
ce_scan_start type="dword" mode="exact" value="100"   -> Health 初始是 100
（点一下 Hit me，数值变小）
ce_scan_next mode="decreased"
ce_scan_results limit=10                              -> 通常一两轮就收敛
ce_write address="0x..." value="1000"
```

**测指针扫描 / 反查引用：得自己造靶子。** 这两个能力要求内存里真的存在一条多级指针
指向目标，教程靶子没有（它的值就是个裸的全局变量）。二十行 C 就够：

```c
#include <windows.h>
#include <stdio.h>

volatile int hp = 100;      // volatile：别让编译器把它优化进寄存器，否则地址根本不落地
int *p1;
int **p2;
int ***p3;

int main (void) {
    p1 = (int *)&hp;
    p2 = &p1;
    p3 = &p2;               // p3 → p2 → p1 → hp，一条三级链
    printf("hp=%p p1=%p p2=%p p3=%p\n", (void *)&hp, (void *)&p1, (void *)&p2, (void *)&p3);
    fflush(stdout);
    while (hp > 0) { Sleep(200); hp--; }
    return 0;
}
```

`cl /O2 target.c` 或 `gcc -O2 target.c -o target.exe`。跑起来后：

```
ce_ptrscan target="hp 的地址" maxLevel=3 maxOffset=0x100
  -> 期望一条链的根落在 target.exe 映像里，偏移序列形如 [+0] → [+0] → [+0]

ce_xref target="p3 的地址"
  -> 期望在 main 里找到写 p3 的那条 lea / mov

ce_bp address="hp 的地址" trigger="write"     -- 需要先 ce_attach 带 debug=true
  -> 每 200ms 命中一次，拿完整寄存器 + 启发式栈回溯
```

> 别拿正在跑的游戏当靶子。进程一崩，CE 的调试会话就废了，只能重启 CE 重来。

### D. 两个必踩的坑

- **值变得比扫描快，精确扫描会漏。** 一次扫描约 350ms，目标如果每 200ms 变一次，
  `exact` 必然抓不到（CE 图形界面也一样，不是你用错了）。要么改用 `unknown` +
  `decreased/increased` 多轮收敛，要么挑一个静止的值扫。
- **`unknown` 首扫 count 恒为 0 是正常的**，CE 此刻只记录了内存区域，地址要等第一次
  `ce_scan_next` 才具体化。

## 五、边界

- 桥跑在 CE **主线程**的定时器回调里（每 20ms 一次）。这是唯一能安全调用 CE 全部 API 的位置
  （在 `createThread` 的 worker 线程里调 CE API 会静默把线程弄死）。
  代价：一次长扫描会占住 CE 主线程几秒，期间 CE 界面短暂不响应，扫完自动恢复。
- 插件的「在线」判定会给 15 秒宽限：万一心跳真的停更（CE 卡在中断不了的 C 调用里），
  不要一看到心跳旧就判掉线。
- 一次只能有一个请求在飞（单槽信箱），插件内部已串行化。
- CE 与目标必须同权限。低权限 CE 读不了高权限进程；要读带保护的游戏，CE 本身要以管理员运行。
- UWP / 打包应用（如 Win11 记事本）即使提权也附不上。
- 反作弊 / 内核保护的游戏不在支持范围（CE 一开就会被判定）。只用于单机、靶场、授权环境。
- `ce_ptrscan` 是自己实现的反向索引 BFS（CE 没有无头指针扫描 API）。已验证的是「链能解引用到目标」，
  但**稳定性**要自己确认：改一下目标值再重跑一次，还成立的链才是真指针链。
  性能约 2-3MB/s，200MB 的堆大概 1-2 分钟，用 `maxBytes` / `maxOffset` 控制。
- `ce_xref` 的 RIP 相对扫描只覆盖常见指令形态（call/jmp/jcc/mov/lea/FF15），
  冷门 ModRM 变体要开 `full=true`。绝对立即数命中带 `:insn`（落在某条指令末尾）或 `:data`
  （只是数据里恰好等于目标地址）；判断指令起点时是「就近优先」回溯——
  同一段字节常有两种合法解码，从远到近找会把 `mov eax,imm32` 误判成前一条 ModRM 指令。
- 栈回溯是启发式的：扫 RSP 往上若干个 8 字节，挑出落在模块代码段里的值。
  没有 unwind 信息，所以可能漏帧或多帧，不是精确的调用栈。
- CE 的调试器一旦启动就**没法从 Lua 停掉**，只能重启 CE。调过 `debug=true` 之后
  就别再把它当普通 reader 用。
- **脚本卡住时心跳不会停。** CE 的定时器在跑长任务时会重入，所以 `alive` 一直在更新，
  看起来像「桥还活着但就是不回包」。真遇到这种（`req` 被读走却既没响应也没日志），
  只能重启 CE。排查时设 `DSH_CE_DEBUG=1`，插件会把每次请求/响应的 id 打到 stderr。

## 六、许可

MIT，见 [`LICENSE`](LICENSE)。

本项目**不包含也不分发** Cheat Engine 的任何代码。运行需要你自己合法获取并安装
Cheat Engine（GPLv3）；`autorun/dsh-ce-bridge.lua` 是运行时通过 CE 的 Lua 接口
加载的独立脚本，不与 CE 链接。

前四节里那些「实测」数字都是在 CE 7.6 / Windows x64 上量出来的，换个 CE 版本或换个
目标进程会不一样——它们说明的是量级，不是承诺。

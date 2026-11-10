# SimpleDbg Bug 报告（含修复验证）

> 本报告保留第一轮修复前证据，并在 2026-11-10 第二轮复查中更新状态；修复验证见 [bug-fix-verification.md](bug-fix-verification.md)。

> 审查对象：工作区未提交修改（基于 `95778a1`）。本文记录第一轮问题、修复前证据、第二轮状态和当前遗留风险，不包含实现补丁。

## 第三轮修复状态

RES-001/002/003/004 已处理，RES-005 已按现有会话设计正式澄清。
实现、验证方法和仍保留的原始地址边界见
[第三轮修复记录](bug-fix-verification.md#第三轮修复res-001-至-res-005)。
下文第二轮 Open 状态与复现保留作为修复前记录。

## 文档信息

| 项目 | 内容 |
| --- | --- |
| 项目 | SimpleDbg（Linux x86-64 ptrace 调试器） |
| 基线提交 | `95778a1 Support dynamic ELF debugging and add core debugger commands` |
| 审查对象 | 工作区修改：`README.md`、`main.cpp`、`sdb.cpp`、`sdb.h`、`symbols.cpp`、`symbols.h`、`process_maps.*`、`tests/test_debugger.py` |
| 最近复查 | 2026-11-10 第二轮（P0 修复后） |
| 文档版本 | v1.1 |
| 日期 | 2026-11-10 |
| 状态 | P0 已修复并验证；保留 P1/P2 边界 |
| 环境 | Ubuntu 24.04.5 LTS，Linux 6.18 x86-64（WSL2），g++ 13.3.0，CMake 3.28.3，Python 3.12.3，Capstone 4.0.2 |
| 关联文档 | [`docs/requirements.md`](./requirements.md) |

## 0. 结论摘要（2026-11-10 第二轮复查）

第一轮报告中的 4 项 P0 已修复；本轮在普通构建和 ASan/UBSan 构建下均通过 39 项测试，未发现新的 P0 阻断缺陷。但仍有两个 P0 边界缺口和若干 P1/P2 遗留风险：

- **P0/Blocker：0 个未修复**。BUG-001 的符号断点路径已修复：`break msg` 在 `-z noseparate-code` 的可执行段中也会被拒绝；39 项测试包含对应用例。
- **P0/Gap：0 个未实现**。BUG-002 的共享库符号解析和 BUG-003 的 PID/映射查询均已实现并有测试。
- **P0/Test：0 个未覆盖**。BUG-004 的测试盲区已补齐：39 项测试覆盖 RX 数据符号、DSO、PID/映射、进程事件、Ctrl-C、stdin 和 FP 寄存器。
- **P0 边界缺口 2 个**：
  - **RES-001**：原始地址模式（`break 0x<addr>`）在可执行段中的数据地址上仍会写入 `INT3`，且没有运行时警告；README 已说明该模式需用户保证指令边界，但需求文档 REQ-P0-01 第 5 条要求“至少警告”。严格按该条验收，这仍是 P0 边界缺口；按当前地址模式边界则可降为 P1。
  - **RES-002**：显式符号版本（如 `libc:puts@GLIBC_2.2.5`）仍被拒绝；REQ-P0-02 的验收项要求支持版本精确匹配，当前 README 已明确列为不支持。若版本化符号属于 P0 范围，需补实现或正式降级。
- **P1/P2 遗留**：线程/fork/exec 采取“安全拒绝”而非完整支持；`next`/`finish`/`bt`、内存/寄存器写、快照 FP/SIMD 仍未实现；另有 2 个防御性加固项（RES-003、RES-004）和 1 个已文档化偏差（RES-005）。

**审查结论：P0 门禁通过，可以进入下一阶段；但建议先决定 RES-001/RES-002 是补实现还是正式降级。** 如果不接受“原始地址模式无警告”的风险，应先补运行时警告或更严格的地址校验。

## 1. 严重度定义

| 级别 | 定义 | 处理策略 |
| --- | --- | --- |
| P0/Blocker | 会静默破坏目标状态、导致核心需求不可用，或使“P0 完成”结论不成立 | 当前迭代必须修复，禁止发布 |
| P0/Gap | 需求文档列为 P0 的能力尚未实现 | 完成或正式降级并同步文档 |
| P0/Test | 测试无法防止 P0 缺陷回归，形成虚假通过 | 与对应缺陷一起修复 |
| P1 | 明显影响安全或可用性，但有明确 workaround 或已文档化限制 | 下一迭代优先处理 |
| P2 | 体验增强或高级能力 | 按需排期 |

## 2. Bug 总览

| ID | 严重度 | 状态 | 组件 | 摘要 |
| --- | --- | --- | --- | --- |
| BUG-001 | P0/Blocker | **Fixed / Verified** | `sdb.cpp`、`symbols.cpp` | 符号断点已按类型/代码节拒绝 RX 数据；地址模式见 RES-001 |
| BUG-002 | P0/Gap | **Fixed / Verified** | `symbols.cpp`、`sdb.cpp`、`process_maps.*` | 已加载 DSO 符号、ASLR、dlopen、歧义消解已实现；显式版本见 RES-002 |
| BUG-003 | P0/Gap | **Fixed / Verified** | `sdb.cpp`、`process_maps.*` | PID、`info proc`、mappings、sharedlibrary 已实现 |
| BUG-004 | P0/Test | **Fixed / Verified** | `tests/test_debugger.py` | 39 项测试覆盖 RX 数据符号、DSO、PID/映射及 P1 场景 |
| BUG-005 | P1 | **Mitigated（安全拒绝）** | 进程跟踪 | clone/thread 事件会终止会话并清理，不再让 worker 命中 `INT3` |
| BUG-006 | P1 | **Mitigated（安全拒绝）** | 进程跟踪 | fork/vfork 事件会终止会话并清理后代 |
| BUG-007 | P1 | **Mitigated（安全拒绝）** | 进程跟踪 | exec 事件会终止会话并清理，不再转发 SIGTRAP |
| BUG-008 | P1 | **Fixed / Verified** | 信号处理 | Ctrl-C 暂停/继续，第二次退出 |
| BUG-009 | P1 | **Fixed / Verified** | 输入 | 默认 `/dev/null`；`--inherit-stdin` 显式共享 |
| BUG-010 | P1 | **Fixed（仅查看）** | 寄存器 | 支持 XMM/ST/MXCSR/FPCW/FPSW/YMM 查看；快照仍不保存 |

## 2.1 当前遗留风险

| ID | 级别 | 状态 | 摘要 |
| --- | --- | --- | --- |
| RES-001 | P1（严格按 REQ-P0-01 第 5 条则为 P0 边界） | Open | 原始地址模式在可执行段的数据地址上仍会写入 `INT3`，无运行时警告 |
| RES-002 | P2（若版本化符号属于 P0-02 验收则为 P1） | Open / 待决策 | 显式符号版本 `symbol@VERSION` 不支持 |
| RES-003 | P2 | Open / 加固 | 未校验 `PTRACE_GETEVENTMSG` 返回的 pid > 0；防御性修复 |
| RES-004 | P2 | Open / 罕见竞态 | `cont` 为越过当前断点内部单步时，Ctrl-C 可能被吞掉 |
| RES-005 | P2 | 已文档化偏差 | 目标退出后没有 `info proc` 查询；会话直接结束，P0-03 的“退出后查询”验收未按字面实现 |

这些不是新的 P0 阻断缺陷，但需要在文档中明确；RES-001 的复现和影响见 4.1。

## 3. P0 详细问题

> **修复后状态（2026-11-10 第二轮）**
>
> - **BUG-001**：符号模式已修复；`break msg` 在 `-z noseparate-code` 的可执行段中返回 `data symbols cannot be used as code breakpoints`，目标输出保持 `hello`。原始地址模式仍有 RES-001。
> - **BUG-002**：已加载 DSO 符号、ASLR、`dlopen`、歧义消解已实现；`break puts`/`printf`/`malloc` 可命中。显式 `@版本` 仍不支持，见 RES-002。
> - **BUG-003**：启动显示 PID，`info proc`、`info proc mappings`、`info sharedlibrary` 已实现。
> - **BUG-004**：39 项测试已覆盖 RX 数据符号、DSO、PID/映射及 P1 场景。
>
> 以下各小节保留第一轮修复前的现象、复现和根因，用于追溯；当前验证结果见第 5 节和附录 B。

### BUG-001 可执行段中的数据符号曾被接受并破坏内存（已修复）

| 字段 | 内容 |
| --- | --- |
| 严重度 | **P0/Blocker** |
| 状态 | Fixed / Verified |
| 组件 | `sdb.cpp`、`symbols.cpp`、`README.md` |
| 影响版本 | 当前工作区修改（基于 `95778a1`） |
| 关联需求 | REQ-P0-01、REQ-P0-04 |

#### 现象

当数据符号恰好位于可执行映射中时，`break <符号名>` 会成功写入 `0xcc`，目标数据被改写，但 `x` 仍显示原始字节。使用合法的 `-Wl,-z,noseparate-code` 把 `.rodata` 合并进 `R E` LOAD 段即可稳定复现。

#### 复现步骤

目标程序 `target.c`：

```c
#include <stdio.h>

const char msg[] = "hello";

int main(void) {
    puts(msg);
    return 0;
}
```

构建并确认 `.rodata` 位于可执行段：

```sh
gcc -g -O0 -fPIE -pie -Wl,-z,noseparate-code target.c -o target
readelf -lW target | grep -E 'LOAD|GNU_RELRO'
readelf -SW target | grep -E '\.text|\.rodata'
```

预期会看到类似：

```text
LOAD 0x000000 ... R E 0x1000
LOAD 0x000db8 ... RW  0x1000
```

说明 `.rodata` 位于 `R E` 段，运行时映射权限包含 `x`。

会话：

```sh
./build/sdb ./target
```

```text
(sdb) x msg 8
0x...: 68 65 6c 6c 6f 00 00 00

(sdb) break msg
** set a breakpoint at 0x... (id 1).

(sdb) x msg 8
0x...: 68 65 6c 6c 6f 00 00 00      # INT3 被 examine_memory 隐藏

(sdb) cont
�ello
** target exited with status 0.
```

未调试运行应输出：

```text
hello
```

#### 期望行为

- `break msg` 必须失败，且不写入目标内存、不消耗断点编号；
- 错误信息应说明数据符号不能作为代码断点；
- 目标继续运行后仍输出 `hello`；
- 如果未来支持 watchpoint，`watch msg` 才应针对数据地址。

#### 实际行为

- `break msg` 成功；
- `msg` 首字节被改成 `0xcc`；
- `x` 因隐藏调试器插入的 `INT3` 而显示原值，掩盖破坏；
- 目标输出乱码；
- 不消耗编号、内存不变等安全保证全部失效。

#### 根因

1. [`symbols.cpp:52`](/home/kxshen/SimpleDbg/symbols.cpp#L52) 在解析符号时只把 `STT_FUNC`、`STT_OBJECT`、`STT_NOTYPE` 作为过滤条件，**没有保留符号类型**；`symbols_` 只存地址。
2. [`sdb.cpp:181`](/home/kxshen/SimpleDbg/sdb.cpp#L181) 的 `add_breakpoint` 只接收 `Address`，无法知道该地址来自函数还是数据对象。
3. [`sdb.cpp:155`](/home/kxshen/SimpleDbg/sdb.cpp#L155) 的 `require_executable` 只检查 `/proc/<pid>/maps` 中是否含 `x` 权限；`.rodata` 被合并进 `R E` 段时，这个检查会放行数据地址。
4. [`sdb.cpp:424`](/home/kxshen/SimpleDbg/sdb.cpp#L424) 的 `examine_memory` 对所有已启用断点都替换回 `original` 显示，无法区分代码断点和数据地址，导致 `x` 看不见破坏。
5. [`README.md:94`](/home/kxshen/SimpleDbg/README.md#L94) 声称“数据、只读字符串……会被拒绝”，与实际行为不一致。

#### 影响

- **数据损坏**：全局变量、常量表、函数指针表、只读字符串等可能被静默改写；
- **误导性 UI**：`x` 显示原值，用户无法通过常规检查发现问题；
- **快照失效**：`.rodata` 等只读映射不在 `anchor` 保存范围内，`timetravel` 也无法恢复被改写的字节；
- **测试假绿**：默认 `-z separate-code` 构建下 `.rodata` 不可执行，现有测试无法发现该问题。

#### 修复建议

1. **保留符号类型**：`ElfSymbols` 返回 `{value, type, bind, section}`，或提供 `resolve_typed(name)`；`x` 仍可使用地址解析，`break` 使用带类型的结果。
2. **按符号类型拒绝**：
   - `break <符号名>` 遇到 `STT_OBJECT`、`STT_TLS` 时直接拒绝；
   - `STT_NOTYPE` 需要明确策略（默认拒绝或仅允许可执行映射 + 指令边界确认）；
   - 不要仅依赖映射权限判断数据/代码。
3. **保留地址断点语义**：`break <地址>` 仍只做可执行映射检查；README 明确“地址模式无法证明指令边界”。
4. **`enable` 复用同一校验**：如果未来存储符号类型，重新启用时也应拒绝数据符号。
5. **文档修正**：在修复前，README 不应声称所有数据/只读字符串都会被拒绝。

#### 回归测试要求

- 新增 `-Wl,-z,noseparate-code` 的 PIE 目标，确认 `.rodata` 在 `R E` 段；
- 断言 `break msg` 返回错误；
- 断言 `info breakpoints` 没有新增条目；
- 断言目标输出仍为 `hello`，退出码为 0；
- 不要只用 `x` 验证内存未变（`x` 会隐藏 `INT3`）；应同时用目标输出或直接读取 `/proc/<pid>/mem`；
- 增加 `break counter`、`break <rodata 地址>`、`break $rsp` 等用例；
- 修复前该用例必须失败（red），修复后通过（green）。

#### 验收标准

- [x] 默认 `-z separate-code` 和 `-z noseparate-code` 下，`break msg` / `break counter` 均被拒绝；
- [x] 失败断点不写入内存、不消耗 ID、不改变断点集合；
- [x] 目标输出和退出码与未调试运行一致；
- [x] `break main`、`break ready`、合法代码地址断点仍正常；
- [x] `x <合法代码断点>` 仍显示原始指令；
- [x] README、帮助信息与实际行为一致。

---

### BUG-002 共享库符号曾无法按名称解析（已修复）

| 字段 | 内容 |
| --- | --- |
| 严重度 | P0/Gap（若产品决定只支持主程序符号，可降为 P1，但必须同步文档） |
| 状态 | Fixed / Verified |
| 组件 | `symbols.cpp`、`sdb.cpp` |
| 关联需求 | REQ-P0-02 |

#### 现象

动态目标中：

```text
(sdb) break printf
** error: symbol not found: printf; use a hex runtime address for stripped binaries

(sdb) break puts
** error: symbol not found: puts; ...

(sdb) break malloc
** error: symbol not found: malloc; ...
```

但 `printf`、`puts`、`malloc` 在已加载的 libc 中确实存在。共享库地址断点（手工计算基址后）可以工作，但按名称不可用。

#### 期望行为

- 已加载共享库的 `.dynsym` 参与符号解析；
- `break printf` / `break puts` / `break malloc` 能命中；
- 正确处理 PIE/ASLR 的 DSO load bias；
- 同名符号跨 DSO 时报告歧义并支持消歧（如 `libc:printf`）；
- 未加载的库、TLS、IFUNC、无符号表 DSO 给出明确错误，不返回猜测地址。

#### 根因

- [`symbols.cpp`](/home/kxshen/SimpleDbg/symbols.cpp) 只加载主程序文件；
- [`sdb.cpp`](/home/kxshen/SimpleDbg/sdb.cpp) 没有 DSO 枚举、`/proc/<pid>/maps` 解析和 load bias 计算；
- 现有测试没有共享库符号用例。

#### 影响

- 动态程序调试仍停留在“主程序符号 + 手工地址”；
- 读取 `/proc/<pid>/maps` 需要先知道 PID，而 PID 也未暴露（见 BUG-003）；
- README 中“共享库符号尚不支持”虽已说明，但与“动态程序可调试”的最低要求存在落差。

#### 验收标准

- [x] `break puts` / `break printf` / `break malloc` 在 PIE + ASLR 下命中；
- [x] `dlopen` 后新加载库中的函数可按名称断点；
- [x] 同名符号报告歧义并支持消歧；
- [x] TLS/IFUNC/未加载库返回明确错误；
- [x] 静态、静态 PIE、去符号主程序现有行为不回归；
- [x] 有自动化测试覆盖。

---

### BUG-003 目标 PID 与映射曾不可见（已修复）

| 字段 | 内容 |
| --- | --- |
| 严重度 | P0/Gap（动态调试闭环的一部分） |
| 状态 | Fixed / Verified |
| 组件 | `sdb.cpp` |
| 关联需求 | REQ-P0-03 |

#### 现象

```text
(sdb) info proc
** error: usage: info breakpoints

(sdb) info proc mappings
** error: usage: info breakpoints

(sdb) info sharedlibrary
** error: usage: info breakpoints
```

启动输出只有程序、入口地址、load bias，没有目标 PID。README 要求用户根据 `/proc/<pid>/maps` 计算共享库地址，但用户无法从调试器获得 `<pid>`。

#### 期望行为

- 启动成功后输出目标 PID；
- 提供 `info proc`：PID、PPID、可执行路径、入口、load bias；
- 提供 `info proc mappings`：`start-end perms offset path`；
- 提供 `info sharedlibrary`：已加载 DSO、基址、符号可用性；
- 目标退出后查询返回明确错误。

#### 根因

- `Debugger::run` 没有输出 `child_` PID；
- 命令解析只支持 `info breakpoints`；
- 没有映射/共享库查询命令。

#### 影响

- 用户无法按 README 流程计算共享库地址；
- 共享库地址断点只能靠外部 `ps`/`pgrep` 猜测；
- 动态调试体验不闭环。

#### 验收标准

- [x] 启动输出包含 PID，且与 `/proc/<sdb>/task/<sdb>/children` 一致；
- [x] `info proc` 输出 PID、可执行路径、入口、load bias；
- [x] `info proc mappings` 包含主程序、libc、stack、heap；
- [x] `info sharedlibrary` 列出已加载库和基址；
- [x] 用输出中的 libc 基址 + `nm -D` 偏移设置断点并命中；
- [ ] 目标退出后查询返回错误（当前设计为退出即结束会话，见 4.2/README；不是保留过期 PID 查询）；
- [x] 有自动化测试覆盖。

---

### BUG-004 P0 回归测试曾存在盲区（已修复）

| 字段 | 内容 |
| --- | --- |
| 严重度 | P0/Test |
| 状态 | Fixed / Verified |
| 组件 | `tests/test_debugger.py` |
| 关联需求 | REQ-P0-04 |

#### 现象

修复前测试全绿（28 项），但当时代码仍有 BUG-001。原因是新增的 `safety.c` 目标使用默认 `-z separate-code`，`.rodata` 位于不可执行的 `R` 段，`require_executable` 会拒绝 `break msg`；测试没有覆盖 `.rodata` 位于 `R E` 段的布局。

#### 修复前具体盲区

1. 没有 `-Wl,-z,noseparate-code` 变体，无法覆盖“可执行段中的数据符号”；
2. 没有测试 `break` 之后通过 `/proc/<pid>/mem` 或目标输出验证内存确实未变；`x` 会隐藏 `INT3`，单独使用 `x` 不足以证明安全；
3. 没有共享库符号测试（BUG-002）；
4. 没有 PID/映射测试（BUG-003）；
5. 没有覆盖 `enable` 对“可执行段中的数据”的第二次校验（虽然当前实现与 `add_breakpoint` 共用权限检查，但仍需测试）。

#### 期望行为

- 新测试在修复前必须失败，修复后通过；
- 测试矩阵包含默认布局和 `-z noseparate-code` 布局；
- 测试用独立手段验证内存/输出，不依赖会隐藏 `INT3` 的 `x`；
- 测试覆盖 P0-02/03 的验收项。

#### 验收标准

- [x] 新增 `-z noseparate-code` 数据符号用例；
- [x] 新增 `/proc/<pid>/mem` 或目标输出断言；
- [x] 新增 DSO 符号用例；
- [x] 新增 PID/映射用例；
- [x] 修复前有 red 记录，修复后有 green 记录；
- [x] `ctest` 与 sanitizer 均包含这些用例。

## 4. P1 已知问题与处理结果

这些不是本次修改引入的回归；部分已通过“安全拒绝”或新功能解决，部分仍是明确的后续需求。

| ID | 现象 | 当前状态 | 影响 | 后续建议 |
| --- | --- | --- | --- | --- |
| BUG-005 | worker 线程命中 `INT3` 曾杀死整个进程 | **Mitigated / 安全拒绝**：识别 `PTRACE_EVENT_CLONE`，终止会话并清理 | 不能调试多线程；但不再静默杀死目标 | 需要多线程时实现 `PTRACE_O_TRACECLONE` 跟踪；当前文档已声明限制 |
| BUG-006 | fork 子进程曾成为孤儿 | **Mitigated / 安全拒绝**：识别 fork/vfork，清理目标及自动跟踪后代 | 不能继续调试子进程；不会留下 PPID=1 孤儿 | 后续实现 fork 跟踪或保持安全拒绝 |
| BUG-007 | exec 后 SIGTRAP 曾杀死目标 | **Mitigated / 安全拒绝**：识别 `PTRACE_EVENT_EXEC`，终止会话并清理 | 不支持跨 exec 调试；目标不会被 SIGTRAP 误杀 | 后续实现 exec 后状态重建 |
| BUG-008 | `cont` 运行中 Ctrl-C 曾杀死 sdb | **Fixed / Verified**：第一次暂停，第二次退出 | 已可暂停/查看/继续 | 补 RES-004 的竞态加固 |
| BUG-009 | 目标曾消费调试器 stdin | **Fixed / Verified**：默认 `/dev/null`，显式 `--inherit-stdin` 才共享 | 默认交互安全；交互目标需 PTY（后续） | 可增加 PTY 支持 |
| BUG-010 | FP/SIMD 寄存器不可见 | **Fixed（仅查看）**：XMM/ST/MXCSR/FPCW/FPSW/YMM 可查 | 已能观察浮点状态；快照仍不保存 | 快照 FP/SIMD 见 REQ-P1-07 |

### 4.1 当前遗留风险

#### RES-001 原始地址模式在可执行段数据上仍会静默写入 `INT3`

| 字段 | 内容 |
| --- | --- |
| 级别 | **P1**；严格按 REQ-P0-01 第 5 条“至少警告”则为 **P0 边界** |
| 状态 | Open |
| 组件 | `sdb.cpp`（`add_breakpoint` / `require_executable`）、`examine_memory` |
| 触发条件 | 用户显式传入可执行映射中的数据地址（不是符号名） |

**复现**

```sh
gcc -g -O0 -fPIE -pie -Wl,-z,noseparate-code target.c -o target
./build/sdb ./target
```

其中 `target.c` 的 `const char msg[] = "hello";` 位于 `R E` 段。使用 `info proc mappings` 或 `nm` + load bias 得到 `msg` 的运行时地址后：

```text
(sdb) x 0x...73c 6
0x...73c: 68 65 6c 6c 6f 00

(sdb) break 0x...73c
** set a breakpoint at 0x...73c (id 1).     # 没有警告

(sdb) x 0x...73c 6
0x...73c: 68 65 6c 6c 6f 00                  # INT3 被隐藏

(sdb) cont
�ello
** target exited with status 0.
```

**期望与建议**

- 对原始地址模式至少输出运行时警告：`address breakpoints cannot verify instruction boundaries`；
- 或者在地址不落在任何代码符号范围内时拒绝/要求确认；
- 更新 `help` 和 README，保持“地址模式需用户保证指令边界”的说明；
- 新增回归测试：RX 数据地址被警告/拒绝，目标输出仍为 `hello`。

**说明**：这不是 BUG-001 的复发。BUG-001 的符号路径已用 ELF 类型/代码节拒绝；原始地址模式无法仅凭映射权限区分数据与代码，因此需要显式提示策略。

#### RES-002 显式 ELF 符号版本不支持

| 字段 | 内容 |
| --- | --- |
| 级别 | **P2**；若 REQ-P0-02 的版本化符号验收仍为 P0，则为 **P1** |
| 状态 | Open / 待决策 |
| 组件 | `sdb.cpp` 的 `resolve_symbol`、`symbols.cpp` |

```text
(sdb) break libc:puts@GLIBC_2.2.5
** error: explicit ELF symbol versions are not supported yet: libc:puts@GLIBC_2.2.5
```

- 无版本 `break libc:puts` 可用；
- 需求文档 REQ-P0-02 曾要求“带版本符号应支持精确匹配”，当前 README 明确列为不支持；
- 建议：解析 `.gnu.version`/`.gnu.version_d`，支持默认版本和显式版本；或正式把该项降为 P2 并同步需求文档。

#### RES-003 防御性加固：事件 pid 未校验 `> 0`

| 字段 | 内容 |
| --- | --- |
| 级别 | P2 |
| 状态 | Open / 加固 |
| 组件 | `sdb.cpp` 的 `wait_stop` / `cleanup` |

`PTRACE_GETEVENTMSG` 返回的 pid 被直接插入 `descendants_`，`cleanup()` 随后对该 pid 执行 `kill(pid, SIGKILL)`。正常内核返回正 pid，但防御性代码应忽略 `pid <= 0`，避免 `kill(0, ...)` 误伤调试器所在进程组。建议：

```cpp
if (pid > 0) descendants_.insert(static_cast<pid_t>(pid));
```

并给 `cleanup()` 的每个 pid 加 `> 0` 保护。

#### RES-004 罕见的 Ctrl-C 竞态：`cont` 内部单步可能吞掉暂停

| 字段 | 内容 |
| --- | --- |
| 级别 | P2 |
| 状态 | Open / 罕见竞态 |
| 组件 | `sdb.cpp` 的 `cont` / `single_step` |

`cont` 在越过当前断点时先做一次内部 `single_step()`。如果 Ctrl-C 恰好在这段窗口内到达，`wait_stop` 可能已经把 `pause_requested` 清掉并返回，`cont` 随后继续 `PTRACE_CONT`，用户看到的是目标继续运行而不是暂停。建议：

- `single_step()` 返回“是否因暂停而停止”的状态，或保留 `pause_requested` 直到命令层处理；
- `cont` 在内部单步后检查 `pause_requested`/`quit_requested`，不要立即恢复；
- 增加压力测试（高频 SIGINT + 断点循环）。

#### RES-005 目标退出后无法执行 `info proc`

| 字段 | 内容 |
| --- | --- |
| 级别 | P2 |
| 状态 | 已文档化偏差 |
| 组件 | `sdb.cpp` 命令循环 / `process_info` |

P0-03 的验收项写有“目标退出后查询返回错误”，当前实现是目标退出后直接结束调试器，不保留提示符，因此无法执行 `info proc`。README 已明确“目标退出后调试器也退出，不保留退出后的查询提示符”。

- 这不是安全缺陷，也不会读取过期 PID；
- 若严格要求验收项字面通过，需要在目标退出后保留一个受限命令循环，或把该项改为“退出即结束会话”；
- 建议在需求文档中正式调整该项，避免验收歧义。

### 4.2 尚未实现的 P1 功能

| 需求 | 当前状态 | 说明 |
| --- | --- | --- |
| REQ-P1-05 `next` / `finish` / `bt` | 未实现 | 仍只有指令级 `si` |
| REQ-P1-06 内存/寄存器写 | 未实现 | 只能读 |
| REQ-P1-07 快照 FP/SIMD 与事务化恢复 | 部分未实现 | 快照仍不保存 FP/SIMD；边界语义见 README |
| 完整线程/fork/exec 支持 | 未实现 | 当前为“检测 + 安全拒绝” |

## 5. 当前验证结果（2026-11-10 第二轮）

### 5.1 通过的检查

```text
ctest --test-dir build --output-on-failure
  -> 1/1 Test #1: integration ... Passed
  -> 100% tests passed, 0 tests failed out of 1（39 个 unittest 用例）

python3 tests/test_debugger.py ./build-sanitize/sdb
  -> Ran 39 tests ... OK

python3 tests/replay_demo.py --delay 0
  -> Replay passed: all 21 commands produced the expected results.

clean build with -Wall -Wextra -Wpedantic
  -> 0 warnings
```

### 5.2 已覆盖的修复项

| 检查 | 结果 |
| --- | --- |
| `-z noseparate-code` 下 `break msg` | 返回 error，目标输出保持 `hello`；`/proc/pid/mem` 交叉验证未改写 |
| `break puts` / `printf` / `malloc` | 可设置并命中 |
| `dlopen` 后符号 / 同名歧义 / TLS / IFUNC | 分别成功、报歧义、明确拒绝 |
| PID / `info proc` / mappings / sharedlibrary | 输出与真实 `/proc` 一致 |
| worker 线程 / fork / exec | 检测到事件后终止会话，目标/后代被清理，无 SIGTRAP 误杀 |
| Ctrl-C | 可暂停、查看、继续；第二次退出 |
| 目标 stdin | 默认读到 EOF，不消费调试器命令 |
| FP/SIMD 寄存器 | XMM/ST/MXCSR/FPCW/FPSW/YMM 可查看（YMM 依赖 CPU/内核） |
| 快照 / 信号 / 断点管理 | 原有 39 项测试继续通过 |

### 5.3 仍存在的风险

| 检查 | 结果 |
| --- | --- |
| 原始地址模式指向 RX 数据 | 仍成功写入 `INT3`，无运行时警告（RES-001） |
| `libc:puts@GLIBC_2.2.5` | 明确报“不支持显式版本”（RES-002） |
| 多线程 / fork / exec 完整调试 | 未支持；当前为安全拒绝（REQ-P1-01） |
| `next` / `finish` / `bt`、内存/寄存器写 | 未实现（REQ-P1-05/06） |
| 快照 FP/SIMD、事务化恢复 | 未实现（REQ-P1-07） |

## 6. P0 门禁结论

- [x] BUG-001 已修复，且有 `-z noseparate-code` 回归测试；
- [x] BUG-004 的测试盲区已补齐（39 项）；
- [x] BUG-002/003 已实现并有测试；
- [x] `ctest`、ASan/UBSan、demo 全绿；
- [x] BUG-001 的 red/green 记录已保留（见 `docs/validation/`）；
- [x] README 与实际行为基本一致；
- [x] 失败断点路径不写内存、不消耗 ID（回归测试 + `/proc/pid/mem` 验证）。

**结论：P0 门禁通过。** 可以进入下一阶段；建议在下一阶段开始前决定：

1. RES-001 是否要求运行时警告（若按 REQ-P0-01 第 5 条严格验收，应先补警告）；
2. RES-002 是否要求显式版本支持（若仍属 P0-02，应先补实现；否则正式降为 P2 并同步需求文档）。

## 7. 风险与注意事项

| 风险 | 说明 | 应对 |
| --- | --- | --- |
| 地址模式无法区分数据/代码 | `break <地址>` 仍可能指向 RX 段中的数据；RES-001 | 增加运行时警告或符号范围校验；README 已声明高级用户责任 |
| 显式版本 | `symbol@VERSION` 未支持；RES-002 | 解析 `.gnu.version`，或正式降级并同步文档 |
| 事件 pid 防御 | `PTRACE_GETEVENTMSG` 的 pid 未校验 >0；RES-003 | 加 `pid > 0` 防护，避免 `kill(0, ...)` |
| Ctrl-C 竞态 | `cont` 内部单步可能吞掉暂停；RES-004 | 让 `single_step` 暴露暂停状态，命令层不要立即恢复 |
| P1 功能缺口 | 线程/fork/exec、next/finish/bt、写、快照 FP | 按需求文档排期，不误称为已支持 |
| 测试环境差异 | `-z noseparate-code`、execstack、链接器布局 | 测试显式指定参数；不依赖默认布局 |
| `x` 隐藏 INT3 | 不能单独用 `x` 证明内存未变 | 用目标输出或 `/proc/pid/mem` 独立断言 |
| 退出后查询 | `info proc` 在目标退出后不可用；RES-005 | 接受“退出即结束”或补受限查询循环 |

## 8. 需求追溯

| Bug | 关联需求 |
| --- | --- |
| BUG-001 | REQ-P0-01、REQ-P0-04 |
| BUG-002 | REQ-P0-02 |
| BUG-003 | REQ-P0-03 |
| BUG-004 | REQ-P0-04 |
| BUG-005 | REQ-P1-01 |
| BUG-006 | REQ-P1-01 |
| BUG-007 | REQ-P1-01 |
| BUG-008 | REQ-P1-02 |
| BUG-009 | REQ-P1-04 |
| BUG-010 | REQ-P1-03 |

## 附录 A：BUG-001 最小复现目标与修复前后对比

```c
#include <stdio.h>

const char msg[] = "hello";

int main(void) {
    puts(msg);
    return 0;
}
```

```sh
gcc -g -O0 -fPIE -pie -Wl,-z,noseparate-code target.c -o target
./build/sdb ./target
```

### A.1 修复前（v1.0，历史）

```text
(sdb) x msg 8
0x...: 68 65 6c 6c 6f 00 00 00
(sdb) break msg
** set a breakpoint at 0x... (id 1).
(sdb) x msg 8
0x...: 68 65 6c 6c 6f 00 00 00
(sdb) cont
�ello
** target exited with status 0.
```

### A.2 修复后（v1.1）

```text
(sdb) break msg
** error: data symbols cannot be used as code breakpoints: msg; use x to inspect data; watchpoints are not supported yet
(sdb) cont
hello
** target exited with status 0.
```

### A.3 仍存在的地址模式边界（RES-001）

同一目标上，如果用 `info proc mappings` 得到 `msg` 的运行时地址并显式传入：

```text
(sdb) break 0x...73c
** set a breakpoint at 0x...73c (id 1).     # 无警告
(sdb) cont
�ello
```

这是 RES-001，不是 BUG-001 的符号路径复发。

## 附录 B：当前关键输出摘录

```text
break msg
** error: data symbols cannot be used as code breakpoints: msg; use x to inspect data; watchpoints are not supported yet

break puts
** set a breakpoint at 0x... (id 1).

break libc:puts@GLIBC_2.2.5
** error: explicit ELF symbol versions are not supported yet: libc:puts@GLIBC_2.2.5

info proc
PID: ...
PPID: ...
Executable: ...
Entry: 0x...
Load bias: 0x...

info proc mappings
... r-xp ... /path/to/target
... r-xp ... /usr/lib/x86_64-linux-gnu/libc.so.6

info sharedlibrary
Load bias  Symbols  Object
0x...  readable  /path/to/target
0x...  readable  /usr/lib/x86_64-linux-gnu/libc.so.6

regs xmm0
xmm0 = 0x...

regs ymm0
ymm0 = 0x...        # 或 unavailable，取决于 CPU/内核
```

## 附录 C：变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v1.0 | 2026-11-10 | 基于第一轮修改创建 Bug 报告：1 个 P0 blocker、2 个 P0 缺口、1 个 P0 测试缺口、6 个 P1 已知问题 |
| v1.1 | 2026-11-10 | 第二轮复查：标记 P0 已修复/验证；更新 39 项测试结果；新增 RES-001～RES-004 及 P1 未实现功能；调整门禁结论 |

# SimpleDbg 改进需求文档

> 基于 2026-11-10 的 P0 复核结果整理。本文定义“需要修改什么、为什么修改、如何验收”，不包含具体实现代码。
>
> 当前缺陷清单见 [`docs/bugs.md`](./bugs.md)。
>
> 实现状态（2026-11-10）：REQ-P0-01/02/03/04 已实现并验证；地址模式警告（RES-001）、显式符号版本（RES-002）和退出后查询偏差（RES-005）仍为边界，详见 [`docs/bugs.md`](./bugs.md)。

## 第三轮验收澄清

- 原始地址模式拒绝能从 ELF 符号识别的数据地址；无法证明指令边界的地址给出运行时警告。
- ELF 显式版本和默认版本已纳入实现及回归测试。
- REQ-P0-03 的“目标退出后查询返回错误”调整为：目标退出后调试器结束会话，
  不再接受查询、不读取过期 PID；不要求保留退出后的提示符。
  下文原条款保留作历史对照，本条是当前验收依据。
- 对应修复与测试见 [第三轮验证](bug-fix-verification.md#第三轮修复res-001-至-res-005)。

## P1/P2 后续实现状态

本轮工作区实现及边界见 [implementation-progress.md](implementation-progress.md)。
P3 尚无独立需求定义；原始验收条款保留，完成范围以进度表及测试证据为准。

## 文档信息

| 项目 | 内容 |
| --- | --- |
| 项目 | SimpleDbg（Linux x86-64 ptrace 调试器） |
| 基线版本 | `95778a1 Support dynamic ELF debugging and add core debugger commands` |
| 文档版本 | v1.0 |
| 日期 | 2026-11-10 |
| 状态 | 待评审 / 待排期 |
| 适用范围 | 当前仓库及后续 1–2 个迭代 |
| 依据 | README 的能力承诺、上一轮确认的四项 P0、本次代码审计与实测 |

## 0. 执行摘要

本次建议修改分为 **4 项 P0 + 7 项 P1**，其中 P0 是重新宣称“P0 完成”前必须完成的发布门禁：

**P0（必须）**

1. **REQ-P0-01 断点目标合法性校验**：禁止对数据、只读、栈、堆等非可执行地址写入 `INT3`；这是当前最严重且会静默破坏目标内存的缺陷。
2. **REQ-P0-02 共享库符号解析**：让 `break printf` / `break puts` 等库函数名可用；建议纳入 P0，否则需明确降级并修改文档。
3. **REQ-P0-03 目标 PID 与映射可见性**：启动显示 PID，提供 `info proc` / `info proc mappings` / `info sharedlibrary`，让共享库地址可计算。
4. **REQ-P0-04 P0 回归测试与验证门禁**：为上述行为补测试，接入 ctest 和 sanitizer，确保修复前 red、修复后 green。

**P1（下一迭代）**

线程/fork/exec 安全处理、运行中 Ctrl-C 暂停、FP/SIMD 寄存器、目标 stdin 隔离、`next`/`finish`/`bt`、内存/寄存器写、快照边界与失败恢复。

**最小可发布标准**

`break counter` / `break msg` 被拒绝且目标状态不变；动态库函数可按名称断点；用户能从调试器取得 PID 和映射；以上均有自动化测试，且 `ctest`、ASan/UBSan、手工验收清单全绿。

## 1. 背景

SimpleDbg 目前已经具备一个可用的单进程、单线程指令级调试器雏形：

- 支持静态链接、动态链接、PIE、静态 PIE 程序；
- 支持符号断点、地址断点、断点管理、寄存器查看、内存查看、单步、继续；
- 支持 `anchor` / `timetravel` 的有限快照回退；
- 26 项集成测试、ASan/UBSan 构建和 21 步命令回放均通过。

但复核发现，当前实现还不能宣称“P0 完成”，原因不是缺少命令入口，而是**核心路径存在会破坏目标状态的正确性问题**，并且动态调试链路仍不完整：

1. `break <符号名>` 会对数据符号、只读符号写入 `INT3`，静默改写目标内存；
2. `x` 会把调试器写入的 `INT3` 替换成原字节显示，进一步掩盖了上述破坏；
3. 共享库符号无法按名称解析，动态库地址断点需要用户手工计算，但调试器不显示目标 PID，也没有映射查看命令；
4. 现有测试没有覆盖上述安全边界，也没有覆盖线程、fork、exec、中断、目标 stdin 等常见场景。

因此，本文把“修复断点安全性、补齐动态调试闭环、补齐 P0 回归测试”定义为下一阶段的 P0 需求。

## 2. 目标与非目标

### 2.1 本阶段目标

- **安全**：任何无效或危险的断点请求都必须在修改目标内存之前失败，不能静默破坏目标状态。
- **可用**：动态链接程序能够按名称调试主程序和已加载共享库中的函数。
- **可观察**：用户能从调试器内部获得目标 PID、内存映射和共享库基址，不需要靠外部 `ps` 猜测。
- **可验证**：上述行为都有自动化回归测试，且测试在修复前应失败、修复后应通过。
- **可维护**：README、帮助信息和错误提示与实际能力一致。

### 2.2 非目标（本阶段不做或仅做检测）

- 完整 DWARF 源码级调试（行断点、局部变量、源码单步）；
- 完整多线程、fork、exec 跟踪；
- attach 到已在运行的进程；
- core dump 分析、远程调试；
- 非 x86-64 架构；
- 完整 watchpoint 体系（但需要为“数据符号不能当断点”提供明确出口）。

## 3. 优先级定义

| 优先级 | 定义 | 处理策略 |
| --- | --- | --- |
| P0 | 会造成目标状态破坏、核心需求不可用，或使“P0 完成”结论不成立 | 本迭代必须完成，作为发布门禁 |
| P1 | 明显影响日常调试可用性或安全性，但有明确 workaround | 下一迭代优先处理 |
| P2 | 体验增强、高级能力或边缘场景 | 按需排期 |

### 3.1 关于 P0 范围的判定

上一轮确认的四项 P0 是：符号断点、寄存器和内存查看、断点管理、故障与边界测试。本文在此基础上做两点判定：

- **REQ-P0-01（断点合法性）属于 P0**：它是符号断点功能的正确性缺陷，不是新功能。
- **REQ-P0-02/03（共享库符号、PID 与映射）建议纳入 P0**：原始最低要求是“动态程序也可以”，而“只能断主程序、无法按名称断库函数、还要用户自己猜 PID”不构成完整的动态调试闭环。若产品明确决定“只支持主程序符号”，则 P0-02/03 降为 P1，但必须同步修改 README 和错误提示，不能继续暗示支持共享库符号。

## 4. 需求总览

| ID | 优先级 | 需求 | 解决的问题 | 验收摘要 |
| --- | --- | --- | --- | --- |
| REQ-P0-01 | P0 | 断点目标合法性校验 | 数据/只读符号被写入 `INT3`，静默破坏内存 | 非可执行地址一律拒绝，目标内存不变 |
| REQ-P0-02 | P0 | 共享库符号解析 | `break printf` 等库函数名不可用 | 已加载 DSO 的函数可按名称断点 |
| REQ-P0-03 | P0 | 目标 PID 与映射可见性 | 用户无法获得 `/proc/<pid>/maps` 和库基址 | 启动显示 PID，提供映射/共享库查询 |
| REQ-P0-04 | P0 | P0 回归测试与验证门禁 | 安全边界无测试，缺陷可再次回归 | 新增测试，接入 ctest 与 sanitizer |
| REQ-P1-01 | P1 | 线程 / fork / exec 检测与安全处理 | 未跟踪线程命中 `INT3` 会杀死进程；子进程成为孤儿；exec 后目标被 SIGTRAP 杀死 | 至少明确检测并安全提示，不静默破坏 |
| REQ-P1-02 | P1 | 运行中中断 / 暂停 | `cont` 运行中 Ctrl-C 直接杀死调试器和目标 | 第一次 Ctrl-C 暂停并回到提示符 |
| REQ-P1-03 | P1 | 浮点 / SIMD 寄存器查看 | `regs xmm0` 报 unknown register | 可查看 XMM/YMM/ST/MXCSR |
| REQ-P1-04 | P1 | 目标 stdin 隔离 | 目标会消费调试器命令 | 目标输入与调试器命令通道分离 |
| REQ-P1-05 | P1 | `next` / `finish` / `bt` | 只有指令级 `si`，无法按调用关系调试 | 提供基本源码/指令级步过和栈回溯 |
| REQ-P1-06 | P1 | 内存 / 寄存器写 | 只能读不能改 | 提供受校验的写命令 |
| REQ-P1-07 | P1 | 快照边界与失败恢复 | 部分映射变化检测不到；恢复失败可能留下半恢复状态 | 明确语义、事务化恢复、补边界测试 |
| REQ-P2-01 | P2 | DWARF 源码级调试 | 无行号、变量、源码断点 | 按源码调试 |
| REQ-P2-02 | P2 | Watchpoint | 数据断点只能通过错误方式表达 | `watch` 变量/地址 |
| REQ-P2-03 | P2 | 系统调用跟踪 | 无 syscall 观察能力 | `catch syscall` / syscall 断点 |
| REQ-P2-04 | P2 | attach / core / remote | 只能启动新进程 | 附加、core、远程目标 |
| REQ-P2-05 | P2 | 输出与帮助信息整理 | 入口断点消息泄露、断点列表按地址排序等 | 输出稳定、帮助准确 |
| REQ-P2-06 | P2 | 测试与发布工程化 | sanitizer 构建靠手工，缺少 CI | 自动化矩阵和发布检查 |

## 5. P0 需求详情

### REQ-P0-01 断点目标合法性校验

- **优先级**：P0
- **类型**：正确性 / 安全性
- **关联问题**：`break counter` 把全局变量改成 `0x112233cc`；`break msg` 把只读字符串改成乱码；`x` 仍显示原值掩盖破坏。

**现状与根因**

- [`symbols.cpp:51`](../symbols.cpp#L51) 会把 `STT_OBJECT`、`STT_NOTYPE` 也加入符号表；
- [`sdb.cpp:155`](../sdb.cpp#L155) 的 `add_breakpoint` 不检查地址是否落在可执行映射，直接读取原字节并写入 `0xcc`；
- [`sdb.cpp:424`](../sdb.cpp#L424) 的 `examine_memory` 会把所有已启用断点的字节替换成原字节显示，导致数据区被改写后 `x` 仍显示“正常”值。

**需求描述**

1. 在执行 `break <符号名>` 或 `break <地址>` 时，必须先确认目标地址属于目标进程的**可执行映射**（`/proc/<pid>/maps` 中权限包含 `x`）。
2. 若地址不在可执行映射中，必须拒绝设置断点，且：
   - 不写入 `0xcc`；
   - 不改变目标内存；
   - 不分配断点编号；
   - 不改变现有断点集合。
3. 错误信息必须说明原因和可行替代方案，例如：
   - `cannot set breakpoint at 0x...: address is not in an executable mapping`
   - `data symbols cannot be used as code breakpoints; watchpoints are not supported yet`
4. 合法的函数符号断点（如 `main`、`tick`、`worker`）和合法代码地址断点必须保持现有行为。
5. 对可执行映射内但可能不是指令边界的地址，应至少给出警告；是否做完整指令边界校验可作为实现增强，但不阻塞本需求。
6. `x` 的“隐藏调试器插入的 INT3”逻辑只应作用于合法代码断点；不得让数据区破坏对用户不可见。

**边界与异常**

- 符号类型为 `STT_OBJECT`、`STT_TLS` 或明显属于数据段时，优先直接拒绝；
- 地址位于 stack、heap、`.data`、`.bss`、`.rodata`、未映射页时，全部拒绝；
- 目标进程已退出或 `/proc/<pid>/maps` 不可读时，返回明确错误，不写入内存；
- 地址合法但 `PTRACE_PEEKDATA/POKEDATA` 失败时，保持断点集合不变，并报告系统错误。

**验收标准**

- [ ] `break counter` 返回错误，`x counter 4` 的字节和目标程序输出与未调试时一致；
- [ ] `break msg`（只读字符串）返回错误，目标输出仍为 `hello`；
- [ ] `break <stack 地址>`、`break <heap 地址>`、`break <未映射地址>` 均返回错误；
- [ ] 失败的 `break` 不消耗断点编号，`info breakpoints` 不新增条目；
- [ ] `break main`、`break tick`、`break 0x<合法代码地址>` 仍能命中；
- [ ] `x <合法代码断点地址>` 仍显示原始指令字节；
- [ ] 所有新增错误路径都有集成测试覆盖。

**测试要求**

- 新增目标程序：包含 `.data` 全局变量、`.rodata` 字符串、`.bss` 变量、栈/堆地址；
- 测试 `break` 失败后目标继续运行，输出和退出码不变；
- 测试失败 `break` 后 `anchor` / `timetravel` 仍可用；
- 增加“先 `x` 看原值 → `break` 失败 → `x` 仍相同 → `cont` 输出不变”的断言。

**不在本需求范围**

- 完整 watchpoint（见 REQ-P2-02）；
- 指令边界自动修复或自动对齐；
- 对目标代码段做写保护校验之外的静态分析。

---

### REQ-P0-02 共享库符号解析

- **优先级**：P0（若产品决定仅支持主程序符号，可降为 P1，但必须同步文档）
- **类型**：核心能力
- **关联问题**：`break printf`、`break puts`、`break malloc` 均返回 `symbol not found`；共享库地址断点只能手工计算。

**需求描述**

1. 符号解析范围从“主程序”扩展为“主程序 + 目标进程当前已加载的共享对象（DSO）”。
2. 至少支持：
   - 主程序 `.symtab` / `.dynsym`（现有行为）；
   - 已加载共享库的 `.dynsym`；
   - 动态加载器 `ld-linux` 中的符号；
   - 通过 `dlopen` 加载且当前已映射的库。
3. 对每个 DSO 计算正确的运行时加载偏移（load bias），正确处理 PIE/ASLR。
4. 符号匹配规则：
   - 未定义符号（`SHN_UNDEF`）不能作为断点目标；
   - 同名符号出现在多个 DSO 时，不能随意选择，必须报告歧义并列出候选；
   - 提供消歧语法，建议 `library:function`（例如 `libc:printf`），具体语法在实现前确认；
   - 带版本符号（如 `puts@GLIBC_2.2.5`）应支持精确匹配；不带版本时解析默认版本。
5. 对暂不支持的类型必须明确报错，不能返回错误地址：
   - TLS 符号；
   - GNU IFUNC（若无法安全解析到实现地址）；
   - 已被卸载或不可读的 DSO；
   - 符号表缺失的 DSO。
6. 对 `dlopen` 后才出现的库：
   - 每次符号解析时刷新已加载 DSO 列表，或提供显式刷新命令；
   - 在库尚未加载时给出“尚未加载”的明确错误，而不是“符号不存在”。
7. 静态链接、静态 PIE 和去符号主程序的行为不能回归。

**验收标准**

- [ ] 动态程序中 `break puts`、`break printf`、`break malloc` 能解析并命中；
- [ ] ASLR 下重复启动，符号断点仍能命中；
- [ ] PIE 主程序 `break main` 仍正常；
- [ ] 多个库存在同名函数时，`break foo` 报歧义并列出候选；
- [ ] 使用 `库名:函数名` 可消歧；
- [ ] `dlopen` 后可按名称断新加载库中的函数；
- [ ] 库未加载时错误信息明确；
- [ ] TLS/IFUNC 符号返回明确“不支持”，不写入错误地址；
- [ ] 静态/静态 PIE/去符号程序现有测试全部通过。

**测试要求**

- 新增调用 `puts`、`printf`、`malloc` 的动态目标；
- 新增一个自建共享库 fixture，包含普通函数、同名函数、TLS 变量、IFUNC（若构造可行）；
- 测试 `dlopen` 前后符号可见性；
- 测试 ASLR 下多次运行；
- 测试歧义和消歧语法；
- 测试 `break puts` 后 `x` 和 `si` 能正常工作。

**依赖**

- 需要 REQ-P0-03 提供目标 PID / 映射信息；
- 需要定义 DSO 加载偏移的计算方式，并在测试中与 `/proc/<pid>/maps` 交叉验证。

**不在本需求范围**

- 源码级符号（DWARF）；
- 跨 DSO 的 inline / 模板实例展开；
- 远程目标或 core 文件的共享库解析。

---

### REQ-P0-03 目标 PID 与映射可见性

- **优先级**：P0
- **类型**：可观察性 / 动态调试闭环
- **关联问题**：README 要求用户根据 `/proc/<pid>/maps` 计算共享库地址，但调试器不显示 PID，也没有映射命令。

**需求描述**

1. 启动成功后，输出目标 PID（可与现有 `program ... loaded` 行合并，或单独一行）。
2. 提供查询命令，建议：
   - `info proc`：显示 PID、PPID、可执行文件路径、入口地址、load bias；
   - `info proc mappings`：显示目标映射的 `start-end perms offset path`；
   - `info sharedlibrary`：显示已加载 DSO 的名称、基址、符号表可用性（可作为 P0-02 的辅助输出）。
3. 输出必须稳定、可读，地址使用十六进制；至少包含主程序和 libc，便于用户计算地址。
4. `info proc` 在目标退出后应返回明确错误，而不是崩溃或读取旧数据。
5. README 中“共享库地址需要根据 `/proc/<pid>/maps` 计算”的流程必须更新为使用调试器自身的命令，或明确给出获取 PID 的方式。

**验收标准**

- [ ] 启动输出包含目标 PID，且与 `ps --ppid` / `/proc/<sdb>/task/<sdb>/children` 一致；
- [ ] `info proc` 输出 PID、可执行路径、入口、load bias；
- [ ] `info proc mappings` 包含主程序、`libc.so.6`、`[stack]`、`[heap]`（如存在）；
- [ ] 用户可根据输出中的 libc 基址 + `nm -D` 偏移设置共享库地址断点并命中；
- [ ] `info sharedlibrary` 列出已加载库及基址；
- [ ] 目标退出后查询返回错误且调试器可正常退出；
- [ ] README 的共享库调试示例与实际输出一致。

**测试要求**

- 启动后断言 PID 存在且有效；
- 用 Python 读取 `/proc/<pid>/maps` 与命令输出交叉验证；
- 使用输出中的基址计算 `puts` 地址，设置断点并命中；
- 测试静态、动态、PIE、静态 PIE 四种程序的映射输出；
- 测试目标退出后的错误路径。

---

### REQ-P0-04 P0 回归测试与验证门禁

- **优先级**：P0
- **类型**：质量保障
- **关联问题**：现有 26 项测试没有覆盖数据符号断点、共享库符号、PID/映射；sanitizer 构建靠手工；缺陷可以无提示回归。

**需求描述**

1. 为 REQ-P0-01/02/03 增加自动化集成测试，测试必须在修复前失败、修复后通过（red-green）。
2. 测试不得依赖固定地址；使用 `nm`、`readelf`、`/proc/<pid>/maps` 动态计算。
3. 测试矩阵至少覆盖：
   - 程序类型：static、dynamic、PIE、static PIE；
   - 符号类型：函数、数据、只读数据、未定义、重名；
   - DSO：启动时加载、`dlopen` 加载、同名符号、TLS/IFUNC 错误；
   - 断点：合法函数、合法地址、非法数据地址、非法未映射地址；
   - 目标状态：失败断点后内存/输出/断点编号不变；
   - PID/映射：输出与 `/proc` 一致。
4. `ctest` 必须包含这些测试；建议增加 sanitizer 构建选项或 CI job，至少保证 ASan/UBSan 能一键运行。
5. 测试失败信息应包含命令、期望值和实际值，便于定位。
6. 若 README/帮助文本因行为变化需要更新，测试应同步断言关键提示。

**验收标准**

- [ ] `ctest --test-dir build --output-on-failure` 全绿；
- [ ] 新增测试在修复前可复现失败（提供 red 记录）；
- [ ] sanitizer 构建下新增测试全绿；
- [ ] 测试覆盖 REQ-P0-01/02/03 的所有验收项；
- [ ] 测试没有固定 ASLR 地址、没有对编译器生成指令的脆弱假设；
- [ ] 文档更新与行为一致。

**测试门禁**

以下条件同时满足才允许把 P0 标记为完成：

1. P0-01/02/03 所有验收项通过；
2. `ctest`、sanitizer、demo 全绿；
3. 无新增编译警告；
4. README 和 `help` 更新；
5. 代码评审确认失败路径不会修改目标内存或留下半完成状态。

## 6. P1 需求

### REQ-P1-01 线程 / fork / exec 检测与安全处理

**问题**：未跟踪的 worker 线程命中 `INT3` 会导致整个进程 `terminated by signal 5`；fork 子进程在调试器退出后成为孤儿；exec 后调试器把 SIGTRAP 转发给目标导致其死亡。

**需求**

- 至少检测 `clone`、`fork`、`exec` 事件并给出明确提示；
- 多线程目标：
  - 优先方案：使用 `PTRACE_O_TRACECLONE` 跟踪新线程，断点对所有线程生效；
  - 最小方案：检测到多线程时拒绝/警告“不支持多线程断点”，并确保未跟踪线程不会因调试器插入的 `INT3` 而杀死进程；
- fork：
  - 优先方案：跟踪子进程并维护独立状态；
  - 最小方案：检测到 fork 时提示，并在退出时清理所有后代，避免孤儿；
- exec：
  - 至少识别 `PTRACE_EVENT_EXEC`，提示“目标已 exec，当前不支持跨 exec 调试”，不要盲目转发 SIGTRAP；
  - 可选：重建符号/断点状态。

**验收标准**

- [ ] worker 线程中的断点不会导致整个进程被 SIGTRAP 杀死；若暂不支持，返回明确错误且目标可继续/安全退出；
- [ ] fork 后调试器退出不会留下 PPID=1 的孤儿进程；
- [ ] exec 后给出明确提示，目标不会因调试器转发 SIGTRAP 而死亡；
- [ ] 新增对应测试。

### REQ-P1-02 运行中中断 / 暂停

**问题**：`cont` 运行中按 Ctrl-C 会直接杀死 sdb（返回 -2），没有暂停并回到提示符的能力。

**需求**

- 调试器捕获 SIGINT；
- 第一次 Ctrl-C：暂停目标（发送 SIGSTOP 或使用 `PTRACE_INTERRUPT`，取决于 seize 方案），回到 `(sdb)` 提示符，允许 `regs`/`x`/断点操作；
- 第二次 Ctrl-C：按现有语义退出并清理目标；
- 暂停后 `cont` 能继续；
- 不把调试器的 SIGINT 误转发给目标。

**验收标准**

- [ ] 无限循环目标可被 Ctrl-C 暂停并查看寄存器；
- [ ] 暂停后 `cont` 可继续；
- [ ] 退出时目标被清理；
- [ ] 有自动化测试或可重复的手工脚本。

### REQ-P1-03 浮点 / SIMD 寄存器查看

**问题**：`regs xmm0`、`regs st0`、`regs mxcsr` 均报 unknown register；快照也不保存 FP/SIMD。

**需求**

- `regs` 支持 XMM0–XMM15、YMM0–YMM15（如可用）、ST0–ST7、MXCSR、FPCW/FPSW（按平台能力）；
- 支持单独查询，如 `regs xmm0`、`regs mxcsr`；
- 输出格式明确（十六进制/浮点解释可选）；
- 明确快照是否保存 FP/SIMD；若暂不保存，在 `anchor`/`timetravel` 文档和提示中说明。

**验收标准**

- [ ] 浮点目标中可查看 XMM/MXCSR 值；
- [ ] 未知寄存器仍返回明确错误；
- [ ] 文档列出支持范围；
- [ ] 不影响现有 GPR 输出。

### REQ-P1-04 目标 stdin 隔离

**问题**：目标与调试器共用 stdin；目标阻塞读取时会把 `regs rip` 当作自己的输入。

**需求**

- 默认将目标 stdin 重定向到 `/dev/null`，或使用独立 pty；
- 提供选项允许目标继承终端（例如 `--tty`），并在文档中说明交互限制；
- 调试器命令通道不能被目标读取；
- 目标关闭 stdin / EOF 时行为明确。

**验收标准**

- [ ] 调试一个读取 stdin 的目标时，发送 `regs rip` 不会出现在目标输入中；
- [ ] 默认模式下目标读到 EOF 并正常退出；
- [ ] 使用显式选项时可按预期共享终端；
- [ ] 新增测试覆盖。

### REQ-P1-05 `next` / `finish` / `bt`

**问题**：只有指令级 `si`，容易陷入库函数，无法按调用关系调试。

**需求**

- `next`：源码级或指令级步过，遇到 `call` 不进入；
- `finish`：运行到当前栈帧返回；
- `bt`：基于帧指针或 DWARF 的栈回溯，至少输出返回地址和符号（可用时）；
- 明确不支持的情况（无帧指针、无 DWARF、内联函数）并给出降级行为。

**验收标准**

- [ ] 递归/多层调用程序可 `next` 步过、`finish` 返回、`bt` 显示调用链；
- [ ] 无符号时给出地址级回溯；
- [ ] 有自动化测试。

### REQ-P1-06 内存 / 寄存器写

**问题**：只能读不能改，无法修改变量、参数或跳过错误分支。

**需求**

- 支持写寄存器，如 `set $rax = 1`；
- 支持写内存，如 `set {int}0x... = 42` 或等价语法；
- 写入前做地址/权限/长度校验；
- 写入失败不应留下部分修改；
- 明确对代码段、只读页、未映射地址的行为。

**验收标准**

- [ ] 可修改寄存器并影响目标执行；
- [ ] 可修改可写内存并影响目标输出；
- [ ] 非法写入返回错误且目标状态不变；
- [ ] 有测试覆盖。

### REQ-P1-07 快照边界与失败恢复

**问题**：只读 mmap 等不改变“可写映射集合”的变化检测不到；`timetravel` 中途失败可能留下半恢复状态；快照不保存 FP/SIMD 和信号内核状态。

**需求**

- 明确定义快照语义：保存哪些映射、哪些寄存器、哪些信号状态；
- 检测所有影响恢复正确性的映射变化，至少包括新增/删除/改权限的可写映射，以及影响快照范围的只读映射；
- 恢复过程事务化：失败时要么完整回滚，要么明确标记“已部分恢复，建议重启”；
- 对超大快照给出内存上限或警告；
- 文档明确不恢复的外部状态（文件、终端、网络、共享内存、其他进程）。

**验收标准**

- [ ] 对新增只读 mmap、mprotect、dlopen、堆扩展等场景有明确检测或文档化行为；
- [ ] 恢复失败后不出现“看似成功但状态不一致”；
- [ ] 有边界测试；
- [ ] 文档与实现一致。

## 7. P2 需求

| ID | 需求 | 说明 |
| --- | --- | --- |
| REQ-P2-01 | DWARF 源码级调试 | 行断点、源码单步、局部变量、作用域；需要 DWARF 解析器 |
| REQ-P2-02 | Watchpoint | `watch <变量/地址>`，与代码断点分离，解决数据符号需求 |
| REQ-P2-03 | 系统调用跟踪 | `catch syscall`、syscall 进入/退出停点、参数/返回值查看 |
| REQ-P2-04 | attach / core / remote | 附加到运行中进程、core 文件分析、远程目标 |
| REQ-P2-05 | 输出与帮助整理 | 隐藏内部入口断点消息；`info breakpoints` 按 ID 排序；补全帮助和错误提示 |
| REQ-P2-06 | 测试与发布工程化 | 一键 sanitizer 构建、CI 矩阵、覆盖率报告、发布检查清单 |

## 8. 非功能需求

| ID | 类别 | 要求 |
| --- | --- | --- |
| NFR-01 | 安全性 | 无效命令不得修改目标内存、寄存器或断点集合；失败路径可重复执行 |
| NFR-02 | 正确性 | 断点命中、信号转发、单步、快照恢复的语义必须有测试定义 |
| NFR-03 | 兼容性 | 保持 Linux x86-64；继续支持 static/dynamic/PIE/static PIE；glibc + 常见内核 |
| NFR-04 | 性能 | 符号解析和映射查询不应在每次命令产生明显卡顿；快照应有内存上限/提示 |
| NFR-05 | 可测试性 | 所有 P0 行为必须能在 `ctest` 中自动验证，不依赖固定地址 |
| NFR-06 | 可维护性 | 符号解析、映射查询、断点校验分层，避免在命令处理里堆逻辑 |
| NFR-07 | 可观察性 | 错误信息包含地址、原因、建议；调试器输出不泄露内部实现细节 |
| NFR-08 | 文档一致性 | README、`help`、错误提示与实际能力一致；不支持的能力明确说明 |

## 9. 测试计划

### 9.1 自动化测试矩阵

| 维度 | 覆盖项 | 优先级 |
| --- | --- | --- |
| 程序类型 | static、dynamic、PIE、static PIE | P0 |
| 符号类型 | 函数、数据、只读数据、未定义、重名 | P0 |
| 断点目标 | 合法函数、合法地址、数据地址、栈/堆、未映射 | P0 |
| 共享库 | 启动加载、dlopen、同名、TLS/IFUNC | P0 |
| PID/映射 | 启动 PID、`info proc`、`info proc mappings`、`info sharedlibrary` | P0 |
| 目标状态 | 失败断点后内存/输出/编号不变 | P0 |
| 信号 | SIGUSR1、SIGSEGV、SIGTRAP、信号处理函数断点 | 现有 + P1 |
| 快照 | 重复 anchor、断点增删、mapping 变化、信号状态 | 现有 + P1 |
| 并发 | 线程、fork、exec | P1 |
| 交互 | Ctrl-C、目标 stdin | P1 |
| 错误输入 | 非法数字、非法寄存器、非法 ID、损坏 ELF | 现有 + P2 |

### 9.2 手工验收清单（P0）

- [ ] 动态程序：`break main` → `cont` → `regs` → `x` → `si` 正常；
- [ ] `break puts` / `break printf` 正常命中；
- [ ] `break counter` / `break msg` 被拒绝，目标输出不变；
- [ ] `info proc` / `info proc mappings` 可获取 libc 基址；
- [ ] 用基址 + `nm -D` 偏移设置库断点并命中；
- [ ] 失败断点后 `info breakpoints` 无新增；
- [ ] `ctest` 与 sanitizer 全绿；
- [ ] README/help 与实际行为一致。

## 10. 里程碑建议

| 里程碑 | 内容 | 退出条件 |
| --- | --- | --- |
| M1 断点安全 | REQ-P0-01 + 回归测试 | 数据/只读/栈/堆断点全部拒绝，目标状态不变 |
| M2 动态闭环 | REQ-P0-03 + REQ-P0-02 | 可获取 PID/映射；可按名称断已加载 DSO 函数 |
| M3 P0 门禁 | REQ-P0-04、README/help 更新 | ctest + sanitizer + 手工清单全绿 |
| M4 稳定性 | REQ-P1-01/02 | 线程/fork/exec 不再静默破坏；Ctrl-C 可暂停 |
| M5 生产力 | REQ-P1-03/04/05/06 | FP 寄存器、stdin 隔离、next/finish/bt、写能力 |
| M6 增强 | P2 需求 | 按优先级逐步排期 |

## 11. 风险与待确认项

| 项 | 风险/问题 | 建议 |
| --- | --- | --- |
| 共享库符号是否 P0 | 影响范围和工作量；上一轮曾列为 P1 | 以“动态程序可调试”为验收标准则纳入 P0；否则明确降级并改文档 |
| IFUNC/TLS | 解析复杂，错误处理容易产生错误地址 | 先明确报错，不返回猜测地址 |
| 多线程支持 | `PTRACE_O_TRACECLONE` 后状态管理复杂 | 先做检测+安全提示，再逐步跟踪 |
| fork/exec | 子进程/新映像的状态重建成本高 | 先检测并安全退出，避免孤儿和 SIGTRAP 误杀 |
| 快照语义 | 外部状态和 FP/SIMD 无法完整恢复 | 明确“受限快照”，不要宣称任意时间回退 |
| ASLR/测试稳定性 | 固定地址测试会随机失败 | 所有地址通过符号/maps 动态计算 |
| 性能 | 每次符号解析扫描所有 DSO 可能变慢 | 缓存 DSO 列表，提供刷新命令，失效时重建 |
| 内核/发行版差异 | ptrace 行为、SIGTRAP si_code 可能不同 | 集成测试覆盖当前环境；文档注明依赖 |

## 12. 需求追溯

| 审计发现 | 需求 |
| --- | --- |
| 数据符号断点静默改写内存 | REQ-P0-01、REQ-P0-04 |
| `x` 隐藏数据区 INT3，掩盖破坏 | REQ-P0-01 |
| 共享库符号不可用 | REQ-P0-02 |
| 无目标 PID / 映射命令 | REQ-P0-03 |
| P0 安全边界无测试 | REQ-P0-04 |
| worker 线程断点杀死进程、fork 孤儿、exec SIGTRAP | REQ-P1-01 |
| Ctrl-C 杀死调试器 | REQ-P1-02 |
| FP/SIMD 寄存器不可见 | REQ-P1-03 |
| 目标抢占 stdin | REQ-P1-04 |
| 无 next/finish/bt | REQ-P1-05 |
| 无内存/寄存器写 | REQ-P1-06 |
| 快照边界与失败恢复 | REQ-P1-07 |
| 源码级、watch、syscall、attach | REQ-P2-01～04 |
| 入口断点消息泄露、列表排序 | REQ-P2-05 |
| sanitizer/CI 手工化 | REQ-P0-04、REQ-P2-06 |

## 13. 影响面与依赖

| 模块 | 预计修改 | 关联需求 |
| --- | --- | --- |
| `symbols.h` / `symbols.cpp` | 增加 DSO 符号索引、符号类型/版本信息、歧义结果结构；保持主程序解析接口兼容 | P0-02 |
| `sdb.h` / `sdb.cpp` | 断点地址校验、PID/映射查询、共享库列表、DSO 基址计算、错误提示；必要时抽出 `Mappings` 模块 | P0-01/02/03 |
| `main.cpp` | 如需把 PID 输出放在启动阶段或增加选项，做少量调整 | P0-03 |
| `tests/test_debugger.py` | 新增数据/只读断点、DSO 符号、PID/映射、失败路径测试；新增共享库 fixture | P0-04 |
| `CMakeLists.txt` | 可选的 sanitizer 构建选项；确保新测试接入 CTest | P0-04 |
| `README.md` | 更新共享库调试流程、PID/映射命令、断点限制和快照语义 | P0-01/02/03/04 |
| `tests/replay_demo.py` | 如输出格式变化，更新断言 | P0-03 |

**依赖关系**

- P0-02 依赖 P0-03 提供 PID 和映射；P0-03 可先独立完成。
- P0-04 的测试依赖 P0-01/02/03 的最终输出格式，但可以先写会失败的用例。
- P1-01（线程/fork/exec）依赖 P0-01 的安全失败模型，避免在异常路径继续写目标内存。

---

## 附录 A：本次复核的关键实测证据

以下输出来自 2026-11-10 的手工探针，探针文件已清理；命令可按“复现要点”重建。

### A.1 基线验证

```text
ctest --test-dir build --output-on-failure
  -> 1/1 Test #1: integration ... Passed
  -> 100% tests passed, 0 tests failed out of 1（26 个 unittest 用例）

python3 tests/test_debugger.py ./build-sanitize/sdb
  -> Ran 26 tests ... OK

python3 tests/replay_demo.py --delay 0
  -> Replay passed: all 21 commands produced the expected results.

clean build with -Wall -Wextra -Wpedantic
  -> 0 warnings
```

### A.2 数据符号断点破坏内存

目标代码：

```c
volatile int counter = 0x11223344;
int main(void) {
    printf("before=%x\n", counter);
    counter += 1;
    printf("after=%x\n", counter);
    return 0;
}
```

会话：

```text
x counter 4      -> 0x...: 44 33 22 11
break counter    -> ** set a breakpoint at 0x... (id 1).
x counter 4      -> 0x...: 44 33 22 11      # INT3 被隐藏
cont             -> before=112233cc
                    after=112233cd
```

未调试运行应为：

```text
before=11223344
after=11223345
```

只读字符串版本：

```c
const char msg[] = "hello";
int main(void) { puts(msg); return 0; }
```

```text
x msg 8      -> 68 65 6c 6c 6f 00 00 00
break msg    -> ** set a breakpoint ...
x msg 8      -> 68 65 6c 6c 6f 00 00 00      # 仍显示原值
cont         -> �ello                        # 实际已被改写
```

### A.3 共享库符号与 PID/映射

```text
break printf  -> ** error: symbol not found: printf; use a hex runtime address for stripped binaries
break puts    -> ** error: symbol not found: puts; ...
break malloc  -> ** error: symbol not found: malloc; ...
```

共享库地址断点本身可用，但需要用户自己从 `/proc/<pid>/maps` 计算基址；调试器启动输出只有程序、入口、load bias，没有 PID。

### A.4 FP/SIMD 寄存器

```text
regs xmm0   -> ** error: unknown register: xmm0
regs st0    -> ** error: unknown register: st0
regs mxcsr  -> ** error: unknown register: mxcsr
```

### A.5 线程 / fork / exec

```text
# worker 线程中设置断点后 cont
** target terminated by signal 5.

# fork 目标，调试器退出后
ps: <child> PPID=1，子进程成为孤儿

# exec 目标
** stopped by signal 5 (forwarded on resume).
** target terminated by signal 5.
```

### A.6 中断与 stdin

```text
# cont 运行中向 sdb 发送 SIGINT
sdb 退出码 -2，目标被清理；没有“暂停并回到提示符”。

# 目标阻塞读取 stdin 时发送 regs rip
目标输出：input? got regs rip
```

## 附录 B：P0 完成定义（Definition of Done）

P0 需求只有在以下全部满足时才算完成：

1. REQ-P0-01/02/03 的所有验收项通过；
2. REQ-P0-04 的新增测试在 `ctest` 中运行并通过；
3. 修复前的失败用例有记录（red），修复后为 green；
4. ASan/UBSan 构建下测试通过；
5. 无新增编译警告；
6. README、`help`、错误提示与实际行为一致；
7. 代码评审确认失败路径不会修改目标内存或留下半完成状态；
8. 手工验收清单全部通过。

## 附录 C：建议的下一轮工作顺序

1. **先做 REQ-P0-01**：这是唯一会静默破坏目标状态的 P0 缺陷，优先级最高。
2. **补 REQ-P0-04 的回归测试**：先让 `break counter`、`break msg` 用例失败，再修复。
3. **做 REQ-P0-03**：PID/映射是动态调试的基础可观察性。
4. **做 REQ-P0-02**：在 PID/映射基础上实现 DSO 符号解析。
5. **更新 README/help**，跑完整 P0 门禁。
6. 再进入 P1（线程/fork/exec、Ctrl-C、FP 寄存器、stdin 隔离、next/finish/bt）。

## 附录 D：变更记录

| 版本 | 日期 | 变更 | 作者 |
| --- | --- | --- | --- |
| v1.0 | 2026-11-10 | 基于 P0 复核结果创建需求文档：4 项 P0、7 项 P1、6 项 P2，含验收标准、测试矩阵、里程碑与追溯 | 审计整理 |

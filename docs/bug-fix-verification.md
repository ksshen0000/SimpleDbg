# bugs.md 修复验证（2026-11-10）

原报告：[bugs.md](bugs.md)。以下记录对应修复后的工作区，不改写原始审计证据。

| 问题 | 验证与处理 |
| --- | --- |
| BUG-001 | 已复现并修复（符号模式）。保留 ELF 类型、大小、代码节属性；数据符号在 RX 映射内也被拒绝。允许代码节内的无类型汇编标签；原始地址模式见 RES-001。 |
| BUG-002 | 已实现当前已加载 ELF 对象的符号查找、每次解析刷新、ASLR 加载偏移、库名消歧。puts/printf/malloc、dlopen、重名、TLS/IFUNC 拒绝路径均测试。 |
| BUG-003 | 启动显示 PID，新增 info proc、info proc mappings、info sharedlibrary；测试交叉验证真实 PID 和 /proc/maps。 |
| BUG-004 | 增加 noseparate-code 目标，确认字符串实际位于 RX 映射；通过 /proc/pid/mem 和目标输出独立验证未被修改。新增 DSO、进程控制、输入和 FP 测试。 |
| BUG-005/006/007 | 采用最小安全方案。识别 clone/fork/vfork/exec ptrace 事件，明确终止会话；清理并回收目标和自动跟踪的后代，不将事件 SIGTRAP 转交目标。未实现多线程、子进程或跨 exec 的继续调试。 |
| BUG-008 | Ctrl-C 暂停运行目标、抑制调试器产生的 SIGSTOP，并可继续；暂停后再按 Ctrl-C 退出。 |
| BUG-009 | 默认 stdin=/dev/null；提供 --inherit-stdin 兼容选项，共享模式有明确警告。 |
| BUG-010 | 支持查看 XMM、ST、MXCSR、FPCW/FPSW、按 CPU/内核能力读取 YMM。已验证全 1 的 XMM0 和 x87 的 1.0 原始表示。快照仍不保存 FP/SIMD。 |

## 第二轮复查（2026-11-10）

- 普通构建与 ASan/UBSan 构建下均为 **39 项测试通过**；21 步 demo 通过；无编译警告。
- BUG-001 的符号模式已修复；`-Wl,-z,noseparate-code` 下 `break msg` 被拒绝，`/proc/pid/mem` 和程序输出均确认未被改写。
- BUG-002/003 已实现并通过 DSO、dlopen、歧义、PID/映射测试。
- 未发现新的 P0 阻断缺陷；P0 门禁通过。

### 遗留边界

| ID | 级别 | 说明 |
| --- | --- | --- |
| RES-001 | P1（严格按 REQ-P0-01 第 5 条为 P0 边界） | 原始地址模式 `break 0x<addr>` 仍可指向 RX 段数据并写入 `INT3`，没有运行时警告；符号模式已修复 |
| RES-002 | P2（若版本化符号仍属 P0-02 则为 P1） | 显式 `symbol@VERSION` 不支持，README 已声明 |
| RES-003 | P2 | `PTRACE_GETEVENTMSG` 的 pid 未校验 `>0`，建议加固 |
| RES-004 | P2 | `cont` 内部单步时 Ctrl-C 可能被吞掉，罕见竞态 |
| RES-005 | P2 | 目标退出后没有 `info proc` 查询；当前设计为退出即结束会话，README 已说明 |
| P1 功能 | — | `next`/`finish`/`bt`、内存/寄存器写、快照 FP/SIMD、完整线程/fork/exec 支持尚未实现 |

详细复现、影响和建议见 [bugs.md](bugs.md) 的 4.1 节。

## 修复前证据

- [bugs-red.txt](validation/bugs-red.txt)：在修改符号类型前，新增测试对数据符号、PID、共享库符号和 FP 寄存器失败。
- [baseline-process-bugs.txt](validation/baseline-process-bugs.txt)：重新编译 95778a1 后验证线程/exec 被 SIGTRAP 杀死、Ctrl-C 返回 -2、目标读取到 regs rip。
- 默认 stdin 的旧版测试可能因 stdio 预读而偶然通过；修复后测试先只发送 cont，要求目标无需输入即可读到 EOF，避免这种假绿。

## 验证命令

```sh
cmake -S . -B build
cmake --build build -j2
ctest --test-dir build --output-on-failure
cmake -S . -B build-sanitize -DSDB_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j2
ctest --test-dir build-sanitize --output-on-failure
python3 tests/replay_demo.py --delay 0
```

39 项集成测试在普通和 ASan/UBSan 构建下通过；21 步演示回放通过。

## 明确保留的边界

- 原始地址断点仅检查映射执行权限，调用者必须确认指令边界；无法保证识别无符号嵌入数据。符号模式明确拒绝数据类型。
- 第二轮时显式符号版本暂不支持；第三轮已补齐，见下方修复记录。TLS/IFUNC 仍明确报错。
- 共享库需要可读取的 ELF 文件及符号表；尚未加载和不存在的符号只能统一提示“当前已加载对象中未找到”。
- 目标退出即结束调试器，因此不提供退出后 info proc 查询；这不是保留过期 PID 继续查询。
- 线程/fork/exec 采取检测并终止策略，不能宣称已支持这些调试场景。
- 快照仍有原 README 声明的映射和外部副作用限制；FP/SIMD 查看不代表快照已覆盖。

## 第三轮修复（RES-001 至 RES-005）

本节更新第二轮“Open/遗留边界”的状态，第二轮文字保留作历史记录。

- RES-001：原始地址及 `$寄存器` 断点拒绝 ELF 符号能识别的数据地址；其他地址显示
  `address breakpoints cannot verify instruction boundaries` 警告。RX 字符串地址被拒绝，
  目标仍输出 hello，失败不消耗编号。仍不能识别所有无符号嵌入数据。
- RES-002：解析 GNU versym/verdef/verneed，支持 `symbol@VERSION`、默认版本以及
  仅匹配默认版本的 `symbol@@VERSION`。自建剥离符号的双版本 DSO 验证精确命中、
  默认选择及未知版本错误；libc:puts@GLIBC_2.2.5 命中。带 copy relocation 的主程序也覆盖。
- RES-003：事件 PID 必须在正 pid_t 范围内；无效事件终止会话。cleanup 所有 kill/wait
  路径拒绝非正 PID，避免进程组信号。正常 clone/fork 清理回归通过。
- RES-004：内部单步保留暂停停止原因，cont 检查该原因及待处理中断，不自动恢复。
  通过在带断点的阻塞 read 系统调用上发送 SIGINT，确定性验证返回提示符并可查看寄存器。
- RES-005：正式明确会话契约：目标退出即结束调试器，不保留退出后查询入口。
  需求中的相关验收改为确认会话结束且不读取过期 PID，原条款保留为历史对照。

新增四项集成测试，合计 43 项；普通构建、ASan/UBSan 以及 21 步 demo 均通过。

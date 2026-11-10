# 优化交付记录（2026-11-10）

本记录对应 `ea6d09d` 之后的一轮本地优化，目标是修复阻断性问题、消除可测量的性能
瓶颈，并补齐回归测试与文档。命令语义、单进程/单线程范围和对外行为边界不变。

## 1. 交付内容

| # | 问题 | 改动 | 主要文件 |
| --- | --- | --- | --- |
| 1 | 容器/btrfs 下 `/proc/<pid>/maps` 的 dev 与 `stat().st_dev` 不一致，所有符号功能被拒绝 | 文件身份只比较 inode；符号缓存仍按设备、inode、大小、时间校验 | [process_maps.cpp](../process_maps.cpp) |
| 2 | 缺少静态 libc 时集成测试在 `setUpClass` 直接报错，整组不执行 | 静态目标改为可选；构建失败时跳过相关用例并打印原因 | [test_debugger.py](../tests/test_debugger.py) |
| 3 | GCC 16 对链式 volatile 赋值产生 `-Wvolatile` | 拆成三条赋值 | [sdb.cpp](../sdb.cpp) |
| 4 | 单步/继续抛异常时，被临时恢复的 `INT3` 不会装回 | `ReArm` RAII 守卫；装回失败时禁用该断点并告警 | [sdb.h](../sdb.h)、[sdb.cpp](../sdb.cpp) |
| 5 | `timetravel` 每 8 字节一次 `PTRACE_POKEDATA` | 64 KiB 块 `process_vm_writev`；`ENOSYS/EPERM/EACCES` 或部分写入时回退 ptrace | [state.cpp](../state.cpp) |
| 6 | 源码行断点每次 spawn `readelf`，`step` 每条指令 spawn `addr2line` | decodedline 行表按对象缓存；常驻 `addr2line` 按地址查询 | [source_tools.cpp](../source_tools.cpp) |
| 7 | 每条命令重复读 `/proc/pid/maps`、ELF 头和 `stat` | 停止期间缓存映射与已加载对象，resume 前失效；可写映射/执行权限检查复用同一解析 | [process_maps.cpp](../process_maps.cpp)、[sdb.cpp](../sdb.cpp) |
| 8 | 小段内存也逐机器字 `PTRACE_PEEKDATA` | 所有大小先试 `process_vm_readv`，失败回退 ptrace | [sdb.cpp](../sdb.cpp) |
| 9 | 写已关闭管道可能被 SIGPIPE 终止；目标也可能误继承该处置 | 调试器忽略 SIGPIPE，目标 exec 前恢复 `SIG_DFL`；新增目标处置回归测试 | [main.cpp](../main.cpp)、[sdb.cpp](../sdb.cpp)、[test_features.py](../tests/test_features.py) |
| 10 | 快照批量写缺少故障注入覆盖 | 测试链接新增 `--wrap=process_vm_writev`，支持 `vm`（EIO）和 `e`（ENOSYS 回退）模式 | [ptrace_fault.cpp](../tests/ptrace_fault.cpp)、[CMakeLists.txt](../CMakeLists.txt) |

同时新增 [tests/bench.py](../tests/bench.py)：生成带 32 MiB 匿名堆的 `-g` 目标，打印
各命令耗时，便于复现下面的数据（不加入 ctest，避免把机器相关的计时变成断言）。

## 2. 性能数据

环境：Linux x86-64、GCC 16.2.1、Release 构建；被测目标 `-g -O0 -fPIE -pie`，快照
使用 32 MiB 匿名堆。优化前数据使用“仅放宽符号校验”的 `-O2` 版本，保证与优化后
都处于符号可用状态。

| 场景 | 优化前 | 优化后 | 说明 |
| --- | --- | --- | --- |
| `timetravel`（32 MiB 堆） | 3.75 s | ≈33 ms（重复测量 32–54 ms） | 约 110 倍；由约 419 万次 `PTRACE_POKEDATA` 变为约 512 次批量写 |
| `step` 前进一行 | 10–58 ms | 0.1–2 ms | 每行不再 spawn 多个 `addr2line` |
| `break <文件>:<行>`（重复） | 155–215 ms | 0.1 ms | 行表缓存；首次约 70 ms（符号解析 + `readelf` + 启动 `addr2line`） |
| `info sharedlibrary` | 33 ms | 13–30 ms 首次 / 0.1 ms 重复 | 首次包含 libc 约 1.1 万符号解析 |
| `bt` | 2.0 ms | 1.3–1.5 ms | 映射/对象缓存 |
| `where` | 5.3 ms | 2–2.6 ms 首次 / 0.2 ms 重复 | 常驻 `addr2line` |
| `regs` | 0.16 ms | 0.06 ms | 小段内存批量读 |
| 5 次 `step` 的 `addr2line` 进程数 | 34 | 1 | 会话内复用常驻进程 |

复现：

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j2
python3 tests/bench.py --sdb build-release/sdb
```

## 3. 行为与兼容性

- **符号身份**：映射中的 dev 与 `stat(2)` 不同不再被拒绝；文件被替换仍可通过
  inode（以及缓存的设备、大小、mtime/ctime）发现。已有的库替换回归测试保持通过。
- **映射缓存**：仅在目标停止时有效；`cont`/`si`/内部 syscall 恢复前失效，因此
  `dlopen`/`munmap`/`mprotect` 之后会重新读取。`info proc mappings` 与
  `info sharedlibrary` 在同一个停止点重复执行不再产生文件 I/O。
- **快照写回**：写入内容与失败语义不变；`process_vm_writev` 的 `ENOSYS`/`EPERM`/
  `EACCES` 或部分写入会回退到逐机器字 ptrace 写，其他错误仍触发原有回滚/终止事务。
- **源码工具**：每个对象最多一个常驻 `addr2line`（缓存上限 4 个），单次查询 5 秒超时，
  超时/进程退出会重启一次；decodedline 行表按对象身份缓存（上限 8 个）。一次性工具
  仍保持 15 秒、16 MiB 输出限制。
- **测试**：静态目标（`static`、`static-pie`、`safety-static*`）在无法链接静态 libc
  时跳过并打印原因；PIE/动态目标、故障注入目标仍强制构建。
- **故障注入**：包装函数只链接到 `sdb-fault`，生产 `sdb` 不包含任何注入入口。

## 4. 验证

- Debug 构建（`-DBUILD_TESTING=ON`）：`ctest` 3/3 通过；86 项测试
  （集成 53、工作流 25、故障注入 8）。
- Release 构建：`ctest` 3/3 通过。
- 回放：`python3 tests/replay_demo.py --extended` 31/31 通过。
- 本机缺少静态 libc，静态目标被自动跳过；46 项集成测试仍全部执行。
- 本机无法运行 ASan/UBSan：系统只有 38 字节的 `libasan.so` linker script，目标
  `/usr/lib64/libasan.so.8.0.0` 不存在，属于环境问题；CI 矩阵仍包含 ASan+UBSan。
- 手工验证：32 MiB 快照恢复、源码行断点/`where`/`list`/`step`、符号断点与 `bt`。

## 5. 未覆盖与后续

- 快照仍是全量写回，未做 soft-dirty/脏页跟踪。
- ELF 符号仍一次解析整张符号表（libc 约 1.1 万符号，Release 首次约 15 ms）。
- 命令分发、帮助和别名仍是 if/else；readline 历史/补全未实现。
- attach、core、remote 与完整多线程仍按 README 的边界未实现。

## 6. 后续增量（持续优化）

### 批次 1：命令行可用性

- `help [command]` 提供单条命令帮助；未知主题给出明确错误。
- 命令别名：`b`=break、`c`=cont、`s`=step、`n`/`ni`=next、`f`=finish、`i`=info、`h`=help、
  `del`=delete、`q`=quit。解析后先把命令字规范化，保证 `i breakpoints` 这类完整参数匹配
  仍然生效。
- `delete all` 批量删除断点并尽量恢复原始字节；恢复失败时给出计数告警。
- `info breakpoints` 追加 ELF 符号描述（如 `work+0`），不改变原有列格式。
- 新增集成测试覆盖别名、单命令帮助、`delete all` 与符号描述；测试总数 75。

### 批次 2：断点生命周期与信号可读性

- 目标 `munmap`/`dlclose` 解除映射后，`delete`/`disable` 只更新调试器元数据并提示
  “no longer mapped”，不再因 `PTRACE_POKEDATA` 失败而无法删除；`delete all` 同样跳过
  已解除映射的地址。
- 信号停止/终止信息附加常见信号名（如 `stopped by signal 11 (SIGSEGV)`），保留原有
  数字文本以兼容脚本和测试。
- 新增回归：RWX 代码页解除映射后删除断点；信号名断言。测试总数 76。

### 批次 3：源码感知回溯与 addr2line 输出校验

- `bt` 在可解析时为每一帧追加 ` at 文件:行`；无 DWARF 的对象保持原符号格式，不再
  打印 `:?` 之类的占位符。
- `source_location` 要求非空文件名和正的行号，统一拒绝 `??:0`、`??:?`、`:?`、`:0`。
- 增加 `.debug_line` 可用性缓存（按文件身份失效），无调试信息的对象（如 libc）不会
  再为逐帧回溯启动 `addr2line`；`bt` 在本机从 6.8 ms 降到 3.4 ms。
- 回归：递归回溯断言帧内包含 `features.c:`。测试总数保持 76。

### 批次 4：源码列表与命令行入口

- `list [行号]` 可查看当前文件中的指定行；请求超出文件范围时给出提示而不是静默输出。
- `sdb --help` / `-h` 输出用法并以 0 退出；`break *0x地址` 支持 GDB 风格前缀。
- 新增集成测试覆盖 `*` 地址语法与 `--help`，源码流程增加指定行与越界断言；
  测试总数 78。

### 批次 5：反汇编开关与寄存器入口

- `set disasm on|off` 控制每条命令后的自动反汇编（默认开），便于安静地查看状态或执行
  脚本化工作流；非法参数报用法错误。
- `info registers [名字]` 作为 `regs` 的等价入口，方便 GDB 习惯。
- 新增集成测试覆盖开关的前后行为与非法参数；测试总数 79。

### 批次 6：地址偏移表达式

- `resolve_address` 支持 `符号`、`$寄存器`、`0x` 地址后追加 `+N`/`-N`（十进制或 `0x`），
  例如 `break main+4`、`x $rsp+16 8`、`x 0x1000-8`；溢出/下溢给出明确错误。
- 符号查询保持原有“不打印地址边界警告”的行为；只有原始地址、寄存器和偏移表达式才提示
  无法验证指令边界。
- 新增集成测试覆盖偏移、下溢与未知寄存器；测试总数 80。

### 批次 7：读/访问监视点

- 新增 `rwatch`/`awatch`：使用 x86 调试寄存器 RW=11b（读写）编码；`watch` 保持 RW=01b
  （只写）。x86 没有只读数据监视点，因此读访问配置在写时也会命中。
- 监视点记录模式，命中消息与 `info watchpoints` 显示 `(write)`/`(read)`。
- 新增回归：读监视点在读取时命中、写监视点忽略后续读取；测试总数 82。

### 批次 8：syscall 名称与断点源码标注

- `catch syscall` 的入口/出口信息附带常见 x86-64 syscall 名称（如 `entry 39 (getpid)`），
  保留原有数字与返回值文本，兼容现有脚本。
- `info breakpoints` 在符号描述后追加可用源码位置（`at 文件:行`）。
- 扩展回归断言；测试总数保持 82。

### 批次 9：批量读回退故障注入

- 测试链接新增 `--wrap=process_vm_readv`；`r 1 0` 用 `ENOSYS` 模拟不支持批量读的内核，
  验证启动反汇编、`x` 和断点流程仍能通过 ptrace 回退工作。
- 测试总数 83。

### 批次 10：字符串查看

- 新增 `x/s <address|symbol|$register>[+/-N] [max]`：按 NUL 结尾打印字符串，转义换行/
  制表/反斜杠/引号与非可打印字节；默认 128 字节，上限 4096；未找到 NUL 时明确标注。
- 新增集成测试覆盖正常字符串、缺参、0 与越界参数；测试总数 84。

### 批次 11：批量启用/停用

- `enable all` / `disable all` 批量管理软件断点；`unwatch all` 一次释放全部硬件槽位。
- 部分失败单独计数告警，不掩盖已成功或失败的断点。
- 新增集成测试覆盖全部启用/停用与监视点清空；测试总数 86。

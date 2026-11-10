# SimpleDbg

用于学习 `ptrace` 的 Linux x86-64 命令行调试器，源自 APUE 课程项目。
支持静态、动态、PIE、静态 PIE 程序及 ASLR；目前以单进程、单线程调试为范围。

## 构建与测试

Ubuntu / Debian：

```sh
sudo apt install g++ libcapstone-dev cmake make python3 binutils
cmake -S . -B build
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

静态测试目标还需要静态 C 库（Debian/Ubuntu 通常由 `libc6-dev` 提供，Fedora/RHEL 为
`glibc-static`）。缺少时 `static`/`static-pie` 用例会跳过并打印原因，其余测试照常运行。
测试需要允许父进程跟踪自己的子进程。容器可能需要相应的 ptrace/seccomp 配置。
三个测试组（53/25/8 项）覆盖核心行为、调试工作流，以及真实 ptrace 错误注入后的事务恢复。
错误注入只链接到测试程序 `sdb-fault`，生产程序 `sdb` 不包含注入入口。

仅构建 Release 程序，不构建测试工具：

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build-release -j2
```

也可以直接编译：

```sh
g++ -std=c++17 -Wall -Wextra -Wpedantic main.cpp sdb.cpp symbols.cpp process_maps.cpp execution.cpp state.cpp source_tools.cpp source_commands.cpp -lcapstone -o sdb
```

## 启动与命令

```sh
./build/sdb ./your-program argument1 argument2
./build/sdb --help
```

动态程序经过链接器后停在主程序 ELF 入口（通常是 `_start`，并非 `main`），显示目标
PID、入口地址和加载偏移。反汇编直接读取运行内存，不要求调试符号或 ELF 节表。
空行继续等待，目标退出后调试器也结束，不保留退出后的查询提示符。

| 命令 | 功能 |
| --- | --- |
| `break main` / `break libc:puts` | 函数符号断点；共享库支持库名消歧 |
| `break 0x地址` / `break *0x地址` / `break $rip` | 运行时地址断点（`*` 为 GDB 风格），调用者必须确认指令边界 |
| `break 文件名:行号` | DWARF 源码行断点，要求 `-g` 和 binutils |
| `cont` | 继续，遇到断点、监视点、捕获的 syscall、信号或退出时停止 |
| `si` | 单步一条指令 |
| `next` / `ni` | 指令级步过；当前是 call 时运行到返回位置 |
| `finish` | 运行到当前函数返回；依赖可识别的栈帧 |
| `bt [帧数]` | 帧指针调用栈，默认最多 64 层（可指定 1–256），显示地址、ELF 符号与可用源码位置 |
| `where` / `list [行号]` | 当前源码位置 / 附近源码（可指定行号） |
| `step` | 源码行步进，最多执行 256 条指令 |
| `regs [寄存器名或fp]` | 通用寄存器或 FP/SIMD 原始值 |
| `x 地址/符号/$寄存器[±偏移] [字节数]` | 十六进制查看内存，默认 16 字节，范围 1–4096 |
| `x/s 地址/符号 [最大字节数]` | 按 NUL 结尾打印字符串并转义不可见字符，默认 128（上限 4096） |
| `set $rdi = 40` | 修改通用寄存器，整数为十进制或 `0x` 十六进制 |
| `set mem counter 2a000000` | 按原始字节修改内存（示例为小端 int 42） |
| `set disasm on|off` | 开关每条命令后的 5 条自动反汇编（默认开） |
| `watch counter [大小]` | 硬件写监视点，默认 4 字节，大小支持 1/2/4/8 |
| `rwatch` / `awatch counter [大小]` | 硬件读 / 访问监视点；x86 没有只读数据监视点，读配置在写时也会触发 |
| `unwatch 编号` / `unwatch all` | 删除单个或全部硬件监视点 |
| `catch syscall [all/off/编号[,编号...]]` | 捕获 syscall 入口和出口；编号为十进制 Linux x86-64 syscall 号 |
| `info breakpoints` / `info watchpoints` | 查看断点 / 监视点 |
| `info registers [名字]` | 与 `regs` 相同的寄存器查看入口 |
| `info proc` | PID、PPID、可执行路径、入口和加载偏移 |
| `info proc mappings` / `info sharedlibrary` | 映射 / 已加载 ELF 对象、加载偏移及符号状态 |
| `delete 编号` / `delete all` | 删除软件断点（all 删除全部并恢复原始字节） |
| `enable/disable 编号` / `enable all` / `disable all` | 启用 / 暂停单个或全部软件断点 |
| `anchor` / `timetravel` | 保存 / 恢复最近的受限快照 |
| `help [命令]` / `quit` / `q` / EOF | 总帮助或单条命令帮助 / 退出并清理目标 |

地址参数支持 `符号`、`$寄存器`、`0x地址` 以及可选的 `+N`/`-N` 偏移（如 `main+4`、
`$rsp+16`、`0x1000-8`），也接受 GDB 风格的 `*0x地址`；溢出/下溢会直接报错。
命令参数目前按空白切分；包含空格的源码路径可先使用不含空格且无歧义的文件名。
常用别名：`b`=break、`c`=cont、`s`=step、`n`=next、`f`=finish、`i`=info、`h`=help、`del`=delete；
`help <命令>` 查看单条命令用法，`info breakpoints` 在可解析时附带 ELF 符号和源码位置。

## 常用调试流程

建议目标程序使用 `-g -O0 -fno-omit-frame-pointer` 编译：

```text
break main
cont
where
list
regs
x $rsp 32
next
bt
finish
cont
```

`next` 是**指令级**步过，不承诺一次跨过一整行源码；`step` 按源码行变化停止。
步过和 finish 遇到用户断点、监视点、信号、syscall 捕获或 Ctrl-C 时会提前停止。
临时断点自动清理，不消耗用户断点编号，不删除或改变已有断点的最终启用状态。

`bt` 和 `finish` 支持常见 x86-64 栈帧、函数入口和返回位置。优化、省略帧指针、
内联、手写特殊栈布局时可能无法恢复，届时提示截断或不可用；不会猜测完整调用栈。
无符号时 bt 仍可显示地址；finish 对无法确认已建立帧指针的函数体会拒绝，避免跳过调用者。

源码工具使用 binutils 的 `addr2line`/`readelf` 解析 DWARF 行信息，以参数数组执行，
不通过 shell。`addr2line` 在会话内常驻复用，decodedline 行表按对象缓存，因此 `step`
不再为每条指令启动新进程；一次性工具仍限制 15 秒和 16 MiB 输出，常驻查询超时为 5 秒。
缺失 DWARF、源码文件或工具时会提示错误。未实现局部变量、类型表达式、完整作用域或内联帧分析。
源码行断点选择匹配行的第一个地址；跨 ELF 对象重名时要求绝对源码路径消歧。

## 符号和地址安全

主程序和当前已加载的共享对象支持 `.symtab` / `.dynsym`，不依赖 DWARF。
映射和已加载对象在目标停止期间缓存，继续运行后自动刷新，因此 `dlopen`/`dlclose` 仍可感知。
符号缓存最多 64 个 ELF 文件，按设备、inode、大小和修改/变更时间失效。文件身份以 inode
为准：容器、btrfs 子卷或挂载命名空间下映射的 dev 可能与 `stat(2)` 不同，此时不拒绝路径。
文件已被替换且不再对应映射时不复用旧符号。

- `break libc:puts`：库名前缀或完整库名消歧，也可使用完整库路径。
- `break libc:puts@GLIBC_2.2.5`：GNU 符号版本精确匹配。
- `symbol@@VERSION`：只匹配默认版本；不带版本时选择默认版本。
- C++ 使用原始 ELF 修饰名；TLS、GNU IFUNC 明确报不支持，不返回猜测地址。
- 找不到符号只能说明当前可读取的已加载对象中没有匹配，不能证明未加载库里不存在。

符号断点拒绝数据对象，即使其位于 RX 映射（例如 `-Wl,-z,noseparate-code`）。
无类型汇编标签只允许代码节。原始地址模式会拒绝 ELF 符号能识别的数据地址，其余
地址显示指令边界警告；无法可靠识别无符号嵌入数据。设置/重新启用断点前检查执行权限。
失败请求不修改目标内存、不消耗编号。断点编号从 1 递增，删除后不复用。
内存查看会隐藏调试器插入的 `INT3`，显示原始指令字节。目标解除映射（`munmap`/`dlclose`）后，
`delete`/`disable` 仍可移除断点元数据并提示地址已不再映射，避免断点无法管理。

手工设置地址断点时：

```text
运行时地址 = ELF 虚拟地址 + 对应对象的 load bias
```

主程序偏移在启动时显示；共享库偏移见 `info sharedlibrary`，映射权限及文件偏移见
`info proc mappings`。ASLR 下每次启动的偏移可能不同。

## 修改状态、监视点与 syscall

只允许修改列出的通用整数寄存器；段寄存器、flags、orig_rax 和 FP/SIMD 目前只读。
写 RIP 前校验可执行映射；其他通用寄存器允许任意无符号 64 位值。

`set mem` 最多写 4096 字节，要求完整十六进制字节串，不带 `0x`。
写入前检查整个范围必须为私有、可写、非可执行映射，拒绝与软件断点重叠。
不可写/只读/共享/代码/未映射范围整体拒绝；执行中途出错会回滚已写机器字。
如果连回滚也失败，会明确终止目标，避免继续执行部分修改的状态。

硬件 watchpoint 在**目标执行匹配访问后**停止：`watch` 只匹配写，`rwatch`/`awatch` 匹配
读写（x86 调试寄存器不提供只读数据监视点，因此读配置在写时也会停止）。最多四个槽位，地址必须按大小对齐。
`info watchpoints` 与命中消息会标出 write/read 模式。
调试器自身的 ptrace 内存修改不会触发 CPU 写监视点。监视点与软件断点分开编号。
目前不提供只读/读写监视点或条件表达式。

`catch syscall 39` 可观察 getpid，`catch syscall 1` 观察 write，`catch syscall 0,1,59`
可一次过滤多个编号；输出入口的六个原始
参数和出口的有符号返回值，并附常见 x86-64 syscall 名称（如 `getpid`）。`catch syscall off` 关闭捕获，模式保留到主动关闭。
程序退出类 syscall 没有返回，所以只会看到入口及目标退出。
入口/出口识别要求 Linux 5.3+ 的 GET_SYSCALL_INFO；请求失败时明确关闭捕获，
保留继续执行能力，不把调试器合成的 SIGTRAP 标记转交给目标。

## 快照语义

快照保存：通用寄存器、FP 寄存器与内核可用的 XSAVE 状态、全部私有可写映射内容，
以及用于检查一致性的完整映射布局（范围、权限、偏移、文件身份等）。
目标私有可写内存总量超过 **128 MiB** 时拒绝创建/备份快照；失败的 anchor 保留旧快照。

恢复前拒绝映射新增/删除/权限/文件身份变化，包括只读 mmap、mprotect、dlopen。
恢复过程先备份当前停止状态；内存或寄存器恢复失败时尝试回滚，回滚失败则终止目标。
内存批量写回优先使用 `process_vm_writev`，内核或安全模块不允许时回退到 ptrace 逐字写入，
失败语义不变。当前的软件断点及硬件监视点集合保留，软件断点会重新布置。

只允许在无待转交信号、无 syscall 捕获停止、无 Ctrl-C 暂停状态的用户态断点/单步点
创建或备份快照。这避免把内核信号投递/在途 syscall 误当成可恢复的寄存器状态。

快照不回退文件、文件偏移、终端、网络、共享内存、其他进程及内核信号队列。
不能检测所有同范围、同权限的匿名映射替换，也不能恢复只读文件内容的外部变更；
不支持自修改代码、任意时间回退。恢复后外部副作用可能再次发生。

## 中断与目标输入

目标运行中第一次 Ctrl-C 暂停并返回提示符，可查看状态后继续。信号停止/终止会显示编号和
常见名称（例如 `stopped by signal 11 (SIGSEGV)`）。
暂停/空闲时再次 Ctrl-C 退出并清理。目标在独立进程组中，调试器中断不会误投给目标。

默认目标 stdin 为 `/dev/null`，读取时得到 EOF，避免消费调试器命令。
`./build/sdb --inherit-stdin ./your-program` 显式共享输入，有警告且受缓冲和终端进程组
影响，不提供独立 PTY；交互式目标的独立终端支持仍待实现。

当前仍不支持完整多线程、fork/vfork、跨 exec 调试。检测到这些事件会明确报告，
终止会话并杀死、回收自动跟踪的目标和后代；这是安全拒绝，不是完整并发调试支持。
attach、core 文件分析及远程调试暂未实现。

## 回放、sanitizer 和覆盖率

一键配置、编译、测试，并执行普通及扩展回放：

```sh
./scripts/validate.sh
./scripts/validate.sh --sanitize --build-dir build-sanitize
./scripts/validate.sh --coverage --build-dir build-coverage
```

回放默认无延迟；需要慢速观看时可指定 `--delay 1`。也可以分别执行：

```sh
python3 tests/replay_demo.py
python3 tests/replay_demo.py --extended
python3 tests/replay_demo.py --delay 0 --record build/demo-session.txt
cmake -S . -B build-sanitize -DSDB_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j2
ctest --test-dir build-sanitize --output-on-failure
cmake -S . -B build-coverage -DSDB_ENABLE_COVERAGE=ON
cmake --build build-coverage -j2
ctest --test-dir build-coverage --output-on-failure
```

CI 配置包含普通/ASan+UBSan 矩阵、测试和回放日志归档；本地验证不代表远端 CI 已运行。
覆盖率构建产生 `.gcda`，可用 `gcov`/`gcovr` 生成报告。旧问题证据保留在 `docs/validation`。

## 性能测量

`tests/bench.py` 会生成带可配置匿名堆的 `-g` 目标，打印各命令的本机耗时（只测量，
不做断言）：

```sh
python3 tests/bench.py --sdb build-release/sdb
python3 tests/bench.py --sdb build/sdb --heap-mib 32
```

本轮优化前后的对照数据、验证范围和兼容性说明见 [优化交付记录](docs/optimization-pass.md)。

## 代码结构与进度

- `main.cpp`：入口与 ELF 校验。
- `sdb.h` / `sdb.cpp`：Debugger 状态、进程/信号/断点与命令分发。
- `execution.cpp`：临时断点、步过、返回和帧指针回溯。
- `state.cpp`：状态修改、快照事务、硬件监视点、syscall 配置。
- `symbols.*` / `process_maps.*`：ELF 符号/版本、映射、加载偏移与缓存。
- `source_tools.*` / `source_commands.cpp`：binutils 进程隔离与源码行功能。
- `tests/`：集成、工作流、故障注入和演示。

需求状态、验证结果及后续工作见 [实现进度](docs/implementation-progress.md)；
本轮性能与交付性改动见 [优化交付记录](docs/optimization-pass.md)。

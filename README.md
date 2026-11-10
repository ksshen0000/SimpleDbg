# SimpleDbg

一个用于学习 `ptrace` 的 Linux x86-64 命令行调试器，源自 APUE 课程项目。
支持静态链接、动态链接、PIE 和静态 PIE 可执行文件，以及开启 ASLR 的环境。

## 构建与测试

Ubuntu / Debian 依赖：

```sh
sudo apt install g++ libcapstone-dev cmake make python3 binutils
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

集成测试会用 `gcc` 编译测试程序，实际启动被调试进程，验证不同链接方式、
符号和地址断点、断点管理、寄存器及内存读取、单步、信号处理、快照和错误输入。
同时覆盖 SIGSEGV、信号处理函数断点、启动失败、符号裁剪、缺失节表和损坏 ELF。环境需要允许父进程对自己的子进程使用
`ptrace`；容器中可能需要配置 `SYS_PTRACE` 和对应的 seccomp 策略。

也可以直接编译：

```sh
g++ -std=c++17 -Wall -Wextra -Wpedantic main.cpp sdb.cpp symbols.cpp -lcapstone -o sdb
```

## 使用

```sh
./build/sdb ./your-program argument1 argument2
```

启动后自动经过动态链接器，停在主程序的 ELF 入口（通常是 `_start`，并非 `main`），
打印入口运行时地址和加载偏移 `load bias`。反汇编直接读取进程内存，因此可以在
共享库中单步和设置断点，也不依赖 ELF 节表或调试符号。

| 命令 | 功能 |
| --- | --- |
| `break <符号名或十六进制运行时地址>` | 例如 `break main`，地址支持 `0x` 前缀 |
| `info breakpoints` | 列出断点编号、启用状态和地址 |
| `delete <编号>` | 删除断点，恢复原始指令 |
| `enable <编号>` / `disable <编号>` | 启用或禁用断点 |
| `regs [寄存器名]` | 查看全部通用寄存器，或指定寄存器，如 `regs rip` |
| `x <地址或符号名或$寄存器> [字节数]` | 以十六进制查看内存，例如 `x $rsp 32` |
| `cont` | 继续运行到断点、信号或退出 |
| `si` | 执行一条机器指令 |
| `anchor` | 保存寄存器与私有可写映射，覆盖之前的快照 |
| `timetravel` | 恢复最近的快照，保留当前断点集合 |
| `help` | 显示命令 |
| `quit` / `q` / EOF | 退出并清理被调试进程 |

执行命令后显示当前位置的最多五条指令。空行会继续等待命令。
目标收到的信号会显示出来，并在下次 `cont` 或 `si` 时转交给目标。

### 常用流程与符号

```text
break main
cont
regs
x $rsp 32
info breakpoints
si
delete 1
cont
```

主程序保留 ELF 符号表时，可直接使用 `break main`、`break my_function`，
PIE 加载偏移会自动处理，不要求 DWARF 调试信息。C++ 使用 ELF 中的原始符号名
（通常是修饰后的名称）；重名且地址不同的符号会提示歧义，需要改用地址。
共享库符号、TLS 和 GNU IFUNC 解析尚不支持。
去除符号或节表的程序仍可使用运行时地址；找不到符号会提示错误。

断点编号从 1 开始递增，删除后不复用。禁用断点保留编号；快照恢复保留当前的
断点集合和启用状态。可以在命中断点后直接删除或禁用，再继续执行。

`regs` 显示通用寄存器、指令和栈指针、标志及段寄存器，不包含浮点/SIMD 状态。
`x` 中地址按十六进制解析，符号名自动重定位，`$rip`、`$rsp` 等引用当前寄存器值。
字节数按十进制解析，默认 16，范围 1–4096；跨不可读映射或地址溢出会提示错误。
显示的内存隐藏调试器插入的 `INT3`，保留目标的原始指令字节。

### PIE 断点地址

`nm -n ./your-program` 或 `objdump -d ./your-program` 显示的是 ELF 虚拟地址。
主程序的断点地址应使用：

```text
运行时地址 = ELF 虚拟地址 + 启动时打印的 load bias
```

非 PIE 程序的加载偏移通常为零。开启 ASLR 时，每次启动 PIE 程序的加载偏移可能不同。
共享库地址需要根据该库在 `/proc/<pid>/maps` 中的实际加载位置计算。
使用地址断点时，应将断点设在已知的指令边界。

### 快照范围

快照用于单进程、单线程程序的内存状态回退，保存通用寄存器和私有可写映射。
恢复前检查这些映射的地址范围和权限；若发生变化（例如扩展堆、`mmap` 或 `dlopen`），
拒绝恢复。相同范围内映射被替换的情况无法检测。

快照不回退文件、终端输出、文件偏移、网络、内核信号状态、共享内存或其他进程，
也不保存浮点/SIMD 寄存器。已经发生的外部副作用可能在继续执行后再次发生。
当前不支持多线程、子进程跟踪或目标在调试期间再次 `exec`。

## 代码结构

- `main.cpp`：命令行入口、ELF 格式校验和顶层错误处理。
- `sdb.h`：`Debugger` 类声明及其断点、快照状态。
- `sdb.cpp`：进程跟踪、反汇编、断点、快照和调试命令实现。
- `symbols.h` / `symbols.cpp`：主程序 ELF 符号表解析和符号查找。
- `tests/test_debugger.py`：集成测试。

## 命令行演示回放

构建后运行以下脚本，可以看到每条命令及其真实输出：

```sh
python3 tests/replay_demo.py
```

脚本临时编译一个 PIE 程序，演示 `break main`、寄存器和内存查看、断点管理，
以及将 `counter` 从 1 回退到 0 的快照恢复。每步会检查结果，结束后自动清理目标程序。

```sh
# 无延迟执行并保存文本记录
python3 tests/replay_demo.py --delay 0 --record build/demo-session.txt
# 指定调试器路径或放慢演示
python3 tests/replay_demo.py --sdb ./build/sdb --delay 1
```

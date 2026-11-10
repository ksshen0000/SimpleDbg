# 本轮 P1/P2 验证记录

本轮结束后按用户要求暂停。本轮按用户要求提交，未推送。
需求完成范围与保留限制见 [实现进度](../implementation-progress.md)。

## 测试结果

| 构建 | 结果 |
| --- | --- |
| Debug | 71 项测试通过（核心 46、工作流 19、故障注入 6），CTest 13.00 秒 |
| ASan/UBSan | 同一组 71 项全部通过，CTest 52.18 秒，无 sanitizer 错误 |
| GCC coverage | 同一组 71 项全部通过，CTest 14.84 秒 |
| Release / BUILD_TESTING=OFF | 编译通过，31 步扩展回放通过 |
| 回放 | Debug、ASan/UBSan、coverage 下普通 21 步与扩展 31 步均通过 |

计时仅为本环境当次结果，不作为性能承诺。编译日志没有新增警告。
回放默认无延迟；仅显式指定 --delay 时等待。

## gcov 行覆盖率

以下只统计项目 .cpp 的可执行行，包含测试及回放累计结果，不代表分支覆盖率：

| 文件 | 已执行 / 可执行行 | 比例 |
| --- | --- | --- |
| execution.cpp | 132 / 148 | 89.2% |
| process_maps.cpp | 88 / 94 | 93.6% |
| sdb.cpp | 566 / 588 | 96.3% |
| source_commands.cpp | 59 / 60 | 98.3% |
| source_tools.cpp | 61 / 71 | 85.9% |
| state.cpp | 185 / 203 | 91.1% |
| symbols.cpp | 159 / 178 | 89.3% |

## 复验

```sh
./scripts/validate.sh
./scripts/validate.sh --sanitize --build-dir build-sanitize
./scripts/validate.sh --coverage --build-dir build-coverage
```

本地回放文件：build/demo-session.txt、build/demo-extended-session.txt。
CTest 详细记录分别位于各 build 目录的 Testing/Temporary/LastTest.log。
CI 工作流已配置，但本轮未推送或触发远端 CI。

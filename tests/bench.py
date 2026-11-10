#!/usr/bin/env python3
"""Measure per-command latency of SimpleDbg on a generated debug target.

This is a manual tuning aid, not part of ctest: wall-clock numbers depend on the
host, so the script only prints measurements and never asserts thresholds.

    python3 tests/bench.py --sdb build-release/sdb
    python3 tests/bench.py --sdb build/sdb --heap-mib 32
"""
import argparse
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

SOURCE = '''#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
volatile int ticks;
char pad[64];
__attribute__((noinline)) int leaf(int x) { ticks += x; return ticks; }
__attribute__((noinline)) int work(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += leaf(i);
    return total;
}
int main(void) {
    size_t size = {heap}UL << 20;
    char *heap = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (heap == MAP_FAILED) return 90;
    memset(heap, 0xa5, size);
    int value = work(4);
    printf("%d %zu\\n", value, strlen("bench"));
    return heap[0] == (char)0xa5 ? 0 : 2;
}
'''


class Session:
    def __init__(self, sdb, target):
        self.process = subprocess.Popen([sdb, str(target)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.buffer = b""
        self.read()

    def read(self, timeout=60, allow_exit=False):
        deadline = time.monotonic() + timeout
        while b"(sdb) " not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError(f"debugger timed out: {self.buffer[-400:]!r}")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                if allow_exit:
                    result, self.buffer = self.buffer, b""
                    return result.decode(errors="replace")
                raise RuntimeError("debugger closed the session")
            self.buffer += chunk
        result, self.buffer = self.buffer.split(b"(sdb) ", 1)
        return result.decode(errors="replace")

    def command(self, command, timeout=60, allow_exit=False):
        start = time.perf_counter()
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()
        output = self.read(timeout, allow_exit=allow_exit)
        return (time.perf_counter() - start) * 1000.0, output

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)


def build_target(directory, heap_mib):
    source = Path(directory) / "bench.c"
    target = Path(directory) / "bench"
    source.write_text(SOURCE.replace("{heap}", str(heap_mib)))
    subprocess.run(["gcc", "-g", "-O0", "-fno-omit-frame-pointer", "-fPIE", "-pie",
                    str(source), "-o", str(target)], check=True)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sdb", type=Path, default=Path(__file__).resolve().parents[1] / "build" / "sdb",
                        help="debugger binary (default: build/sdb)")
    parser.add_argument("--heap-mib", type=int, default=32,
                        help="anonymous heap size used for anchor/timetravel (default: 32, max 120)")
    parser.add_argument("--target", type=Path, help="use an existing PIE binary compiled with -g instead of generating one")
    args = parser.parse_args()
    if not 0 <= args.heap_mib <= 120:
        parser.error("--heap-mib must be between 0 and 120 (snapshot limit is 128 MiB)")
    sdb = args.sdb.resolve()
    if not sdb.exists():
        parser.error(f"{sdb} does not exist; build the debugger first")

    with tempfile.TemporaryDirectory(prefix="sdb-bench-") as directory:
        target = args.target.resolve() if args.target else build_target(directory, args.heap_mib)
        session = Session(sdb, target)
        timings = []
        try:
            def run(command, allow_exit=False):
                elapsed, output = session.command(command, allow_exit=allow_exit)
                timings.append((command, elapsed))
                detail = next((line for line in output.splitlines() if "error:" in line), "")
                print(f"{elapsed:9.2f} ms  {command}{'  ' + detail.strip() if detail else ''}")

            run("regs")
            run("info sharedlibrary")
            run("info sharedlibrary")
            run("info proc mappings")
            run("break work")
            run("break leaf")
            run("cont")
            run("bt")
            run("where")
            run("list")
            run("x $rsp 64")
            for _ in range(5):
                run("step")
            run("anchor")
            run("timetravel")
            run("delete 2")
            run("cont", allow_exit=True)
        finally:
            session.close()

    print(f"\nsum of command latency: {sum(elapsed for _, elapsed in timings):.1f} ms")
    print("note: `cont` includes the target's own work (touching the heap), not only debugger cost.")


if __name__ == "__main__":
    sys.exit(main())

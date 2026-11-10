"""Replay a visible debugging session against a temporary, compiled C program."""
import argparse
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdb", type=Path, default=Path(__file__).resolve().parents[1] / "build/sdb")
    parser.add_argument("--delay", type=float, default=0.4, help="seconds between commands (default: 0.4)")
    parser.add_argument("--record", type=Path, help="save the displayed session as UTF-8 text")
    args = parser.parse_args()
    if args.delay < 0:
        parser.error("--delay must be nonnegative")
    transcript = []

    def display(text):
        print(text, end="", flush=True)
        transcript.append(text)

    with tempfile.TemporaryDirectory(prefix="sdb-demo-") as directory:
        source = Path(directory) / "demo.c"
        target = Path(directory) / "demo"
        source.write_text('''volatile int counter = 0;
__attribute__((noinline)) void tick(void) { ++counter; }
int main(void) {
    for (int i = 0; i < 3; ++i) tick();
    return counter;
}
''')
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(source), "-o", str(target)], check=True)
        display("Demo: PIE program calls tick() three times; counter goes from 0 to 3.\n")
        process = subprocess.Popen([str(args.sdb.resolve()), str(target)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        pending = b""

        def receive():
            nonlocal pending
            deadline = time.monotonic() + 10
            while b"(sdb) " not in pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise RuntimeError("debugger did not respond within 10 seconds")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    result, pending = pending, b""
                    return result.decode("utf-8", errors="replace")
                pending += chunk
            result, pending = pending.split(b"(sdb) ", 1)
            return result.decode("utf-8", errors="replace") + "(sdb) "

        commands = [
            ("break main", "(id 1)"),
            ("cont", "hit a breakpoint"),
            ("regs rip", "rip = 0x"),
            ("x $rsp 16", ":"),
            ("break tick", "(id 2)"),
            ("info breakpoints", "enabled"),
            ("cont", "hit a breakpoint"),
            ("anchor", "dropped an anchor"),
            ("x counter 4", ": 00 00 00 00"),
            ("cont", "hit a breakpoint"),
            ("x counter 4", ": 01 00 00 00"),
            ("timetravel", "go back to the anchor"),
            ("x counter 4", ": 00 00 00 00"),
            ("disable 2", "breakpoint 2: disable"),
            ("info breakpoints", "disabled"),
            ("enable 2", "breakpoint 2: enable"),
            ("delete 1", "breakpoint 1: delete"),
            ("cont", "hit a breakpoint"),
            ("cont", "hit a breakpoint"),
            ("delete 2", "breakpoint 2: delete"),
            ("cont", "exited with status 3"),
        ]
        try:
            output = receive()
            display(output)
            if "loaded. entry point" not in output:
                raise RuntimeError("target failed to load")
            for command, expected in commands:
                time.sleep(args.delay)
                display(command + "\n")
                process.stdin.write((command + "\n").encode())
                process.stdin.flush()
                output = receive()
                display(output)
                if expected not in output:
                    raise RuntimeError(f"{command!r}: expected {expected!r}")
            process.wait(timeout=5)
            if process.returncode != 0:
                raise RuntimeError(f"debugger exited with status {process.returncode}")
            display("\nReplay passed: all 21 commands produced the expected results.\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            if args.record:
                args.record.write_text("".join(transcript), encoding="utf-8")


if __name__ == "__main__":
    main()

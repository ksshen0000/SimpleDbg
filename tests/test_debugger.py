"""Real ptrace integration tests; only Python's standard library is required."""
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import shutil
import struct
import tempfile
import time
import unittest

SDB = str(Path(sys.argv.pop(1)).resolve())


class Session:
    def __init__(self, target, *args):
        self.process = subprocess.Popen([SDB, str(target), *args], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.buffer = b""
        self.initial = self.read()

    def read(self):
        deadline = time.monotonic() + 10
        while b"(sdb) " not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError(f"debugger timed out: {self.buffer!r}")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                result, self.buffer = self.buffer.decode(), b""
                return result
            self.buffer += chunk
        result, self.buffer = self.buffer.split(b"(sdb) ", 1)
        return result.decode()

    def command(self, command):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()
        return self.read()

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            self.process.wait(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


class DebuggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        source = cls.root / "target.c"
        source.write_text('''#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
volatile int counter;
__attribute__((noinline)) void tick(void) { counter++; }
static void handler(int sig) { (void)sig; counter = 8; }
int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 's') {
        signal(SIGUSR1, handler); raise(SIGUSR1); return counter;
    }
    if (argc > 1 && argv[1][0] == 'b') {
        tick(); signal(SIGUSR1, handler); raise(SIGUSR1); tick(); return counter;
    }
    if (argc > 1 && argv[1][0] == 'c') { *(volatile int *)0 = 1; }
    if (argc > 1 && argv[1][0] == 't') { raise(SIGTRAP); return 99; }
    if (argc > 1 && argv[1][0] == 'm') {
        tick();
        void *p = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return 100;
        tick();
        munmap(p, 8192); return counter;
    }
    for (int i = 0; i < 3; i++) tick();
    return counter;
}
''')
        for name, flags in (("pie", ["-fPIE", "-pie"]), ("dynamic", ["-fno-pie", "-no-pie"]),
                            ("static", ["-static", "-fno-pie", "-no-pie"]),
                            ("static-pie", ["-static-pie"])):
            subprocess.run(["gcc", "-g", "-O0", *flags, str(source), "-o", str(cls.root / name)], check=True)
        assembly = cls.root / "adjacent.s"
        assembly.write_text('''.global _start, second
.text
_start:
 nop
second:
 nop
 mov $60, %eax
 mov $7, %edi
 syscall
.section .note.GNU-stack,"",@progbits
''')
        subprocess.run(["gcc", "-nostdlib", "-static", "-no-pie", str(assembly), "-o", str(cls.root / "adjacent")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name="pie", *args):
        session = Session(self.root / name, *args)
        self.addCleanup(session.close)
        self.assertIn("loaded. entry point", session.initial)
        self.assertNotIn("cannot disassemble", session.initial)
        return session

    def address(self, session, name, symbol):
        symbols = subprocess.check_output(["nm", str(self.root / name)], text=True)
        offset = int(re.search(r"^([0-9a-f]+) \w " + symbol + r"$", symbols, re.M)[1], 16)
        bias = int(re.search(r"load bias 0x([0-9a-f]+)", session.initial)[1], 16)
        return offset + bias

    def test_program_types_and_repeated_breakpoints(self):
        for name in ("pie", "dynamic", "static", "static-pie"):
            with self.subTest(name=name):
                s = self.session(name)
                address = self.address(s, name, "tick")
                self.assertIn("set a breakpoint", s.command(f"break {address:x}"))
                for _ in range(3):
                    self.assertIn(f"hit a breakpoint at 0x{address:x}", s.command("cont"))
                self.assertIn("exited with status 3", s.command("cont"))

    def test_single_step_at_breakpoint(self):
        s = self.session()
        address = self.address(s, "pie", "tick")
        s.command(f"break {address:x}")
        s.command("cont")
        output = s.command("si")
        self.assertNotIn("stopped by signal", output)
        self.assertNotIn(f"  0x{address:x}:", output)
        self.assertIn("hit a breakpoint", s.command("cont"))

    def test_adjacent_breakpoints_and_exit_during_step(self):
        s = self.session("adjacent")
        first = self.address(s, "adjacent", "_start")
        second = self.address(s, "adjacent", "second")
        s.command(f"break {first:x}")
        s.command(f"break {second:x}")
        # Stepping the first breakpoint must preserve the neighbouring trap.
        self.assertIn(f"0x{second:x}:", s.command("si"))
        s.command("si")
        s.command("si")
        s.command("si")
        self.assertIn("exited with status 7", s.command("si"))

    def test_snapshot_repeated_anchor_and_restore(self):
        s = self.session()
        address = self.address(s, "pie", "tick")
        s.command(f"break {address:x}")
        s.command("cont")
        self.assertIn("dropped an anchor", s.command("anchor"))
        self.assertIn("dropped an anchor", s.command("anchor"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("go back to the anchor", s.command("timetravel"))
        # Rewind counter and loop index, while retaining the breakpoint.
        for _ in range(2):
            self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("exited with status 3", s.command("cont"))

    def test_breakpoint_added_after_anchor(self):
        s = self.session()
        self.assertIn("dropped an anchor", s.command("anchor"))
        address = self.address(s, "pie", "tick")
        s.command(f"break {address:x}")
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("go back to the anchor", s.command("timetravel"))
        for _ in range(3):
            self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("exited with status 3", s.command("cont"))

    def test_snapshot_rejects_changed_mappings(self):
        s = self.session("pie", "mappings")
        address = self.address(s, "pie", "tick")
        s.command(f"break {address:x}")
        s.command("cont")
        s.command("anchor")
        s.command("cont")
        self.assertIn("memory mappings changed", s.command("timetravel"))
        self.assertIn("exited with status 2", s.command("cont"))

    def test_commands_and_errors(self):
        s = self.session()
        for command in ("break", "break xyz", "break -1", "break 0junk", "break 0", "si extra", "unknown", "timetravel"):
            with self.subTest(command=command):
                self.assertIn("error:", s.command(command))
        self.assertEqual("", s.command(" \t "))
        self.assertIn("break <symbol|hex runtime address>", s.command("help"))
        address = self.address(s, "pie", "tick")
        s.command(f"break {address:x}")
        self.assertIn("already exists", s.command(f"break {address:x}"))
        self.assertIn("hit a breakpoint", s.command("cont"))

    def test_signal_delivery_and_arguments(self):
        s = self.session("pie", "signal")
        self.assertIn("stopped by signal 10", s.command("cont"))
        self.assertIn("exited with status 8", s.command("cont"))

    def test_target_sigtrap_is_forwarded(self):
        s = self.session("pie", "trap")
        self.assertIn("stopped by signal 5", s.command("cont"))
        self.assertIn("terminated by signal 5", s.command("cont"))

    def test_symbol_breakpoints_all_program_types(self):
        for name in ("pie", "dynamic", "static", "static-pie"):
            with self.subTest(name=name):
                s = self.session(name)
                address = self.address(s, name, "main")
                self.assertIn("(id 1)", s.command("break main"))
                self.assertIn(f"hit a breakpoint at 0x{address:x}", s.command("cont"))
                self.assertIn("exited with status 3", s.command("cont"))

    def test_registers_and_memory(self):
        s = self.session()
        original = s.command("x tick 1").splitlines()[0]
        s.command("break tick")
        s.command("cont")
        address = self.address(s, "pie", "tick")
        self.assertIn(f"rip = 0x{address:016x}", s.command("regs rip"))
        output = s.command("regs")
        for name in ("rax", "rbp", "rsp", "eflags", "fs_base"):
            self.assertRegex(output, name + r" = 0x[0-9a-f]{16}")
        self.assertIn(": 00 00 00 00", s.command("x counter 4"))
        # Read logical instruction bytes even after the breakpoint is rearmed.
        instruction = s.command("x tick 1")
        self.assertEqual(original, instruction.splitlines()[0])
        s.command("si")
        self.assertEqual(original, s.command("x tick 1").splitlines()[0])
        self.assertRegex(s.command("x $rsp 8"), r"0x[0-9a-f]+:(?: [0-9a-f]{2}){8}")
        s.command("cont")
        self.assertIn(": 01 00 00 00", s.command("x counter 4"))

    def test_breakpoint_management(self):
        s = self.session()
        self.assertIn("no breakpoints", s.command("info breakpoints"))
        s.command("break main")
        s.command("break tick")
        self.assertRegex(s.command("info breakpoints"), r"2  enabled +0x")
        s.command("disable 2")
        self.assertRegex(s.command("info breakpoints"), r"2  disabled +0x")
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 1")  # Delete while stopped at that breakpoint.
        s.command("enable 2")
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("disable 2")  # Disable while stopped at the breakpoint.
        self.assertIn("exited with status 3", s.command("cont"))

    def test_delete_rearmed_adjacent_breakpoint(self):
        s = self.session("adjacent")
        s.command("break _start")
        s.command("break second")
        s.command("si")
        s.command("delete 1")
        s.command("delete 2")
        self.assertIn("no breakpoints", s.command("info breakpoints"))
        self.assertIn("exited with status 7", s.command("cont"))

    def test_disabled_breakpoint_survives_snapshot(self):
        s = self.session()
        s.command("break tick")
        s.command("cont")
        s.command("anchor")
        s.command("cont")
        s.command("disable 1")
        s.command("timetravel")
        self.assertRegex(s.command("info breakpoints"), r"1  disabled +0x")
        self.assertIn("exited with status 3", s.command("cont"))

    def test_breakpoint_and_signal_interleaving(self):
        s = self.session("pie", "between")
        s.command("break tick")
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("stopped by signal 10", s.command("cont"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("exited with status 9", s.command("cont"))

    def test_breakpoint_in_signal_handler(self):
        s = self.session("pie", "signal")
        s.command("break handler")
        self.assertIn("stopped by signal 10", s.command("cont"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertNotIn("stopped by signal", s.command("si"))
        s.command("delete 1")
        self.assertIn("exited with status 8", s.command("cont"))

    def test_breakpoint_ids_and_idempotent_enable_disable(self):
        s = self.session()
        self.assertIn("(id 1)", s.command("break tick"))
        self.assertIn("already exists", s.command("break tick"))
        for command in ("disable 1", "disable 1", "enable 1", "enable 1"):
            self.assertNotIn("error:", s.command(command))
        s.command("delete 1")
        self.assertIn("(id 2)", s.command("break tick"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 2")
        self.assertIn("exited with status 3", s.command("cont"))

    def test_sigsegv_keeps_faulting_rip(self):
        s = self.session("pie", "crash")
        self.assertIn("stopped by signal 11", s.command("cont"))
        before = re.search(r"rip = 0x([0-9a-f]+)", s.command("regs rip"))[1]
        # Observing state must neither rewind RIP nor consume the pending signal.
        self.assertIn(before, s.command("regs rip"))
        self.assertIn("terminated by signal 11", s.command("cont"))

    def test_new_command_errors_are_recoverable(self):
        s = self.session()
        commands = ("break no_such_symbol", "regs bogus", "regs rip extra", "x", "x 0", "x $bogus",
                    "x counter 0", "x counter 4097", "x counter -1", "x counter 4junk",
                    "x ffffffffffffffff 2", "delete 0", "enable 999", "disable -1", "delete 4294967296",
                    "info", "info unknown", "delete", "enable 1 extra")
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("error:", s.command(command))
        self.assertIn("exited with status 3", s.command("cont"))

    def test_stripped_binary_address_fallback(self):
        path = self.root / "stripped"
        shutil.copyfile(self.root / "pie", path)
        path.chmod(0o755)
        subprocess.run(["strip", "--strip-all", str(path)], check=True)
        s = self.session("stripped")
        self.assertIn("symbol not found", s.command("break main"))
        address = self.address(s, "pie", "main")
        s.command(f"break {address:x}")
        self.assertIn("hit a breakpoint", s.command("cont"))

    def test_sectionless_binary_still_accepts_addresses(self):
        contents = bytearray((self.root / "pie").read_bytes())
        struct.pack_into("<Q", contents, 40, 0)
        struct.pack_into("<HHH", contents, 58, 0, 0, 0)
        path = self.root / "sectionless"
        path.write_bytes(contents)
        path.chmod(0o755)
        s = self.session("sectionless")
        self.assertIn("symbol not found", s.command("break main"))
        address = self.address(s, "pie", "main")
        s.command(f"break 0x{address:x}")
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("exited with status 3", s.command("cont"))

    def test_symbols_work_without_dwarf(self):
        path = self.root / "no-debug"
        shutil.copyfile(self.root / "pie", path)
        path.chmod(0o755)
        subprocess.run(["strip", "--strip-debug", str(path)], check=True)
        s = self.session("no-debug")
        self.assertIn("set a breakpoint", s.command("break main"))
        self.assertIn("hit a breakpoint", s.command("cont"))

    def test_non_executable_and_broken_loader(self):
        noexec = self.root / "noexec"
        shutil.copyfile(self.root / "pie", noexec)
        noexec.chmod(0o644)
        broken = self.root / "broken-loader"
        contents = (self.root / "pie").read_bytes()
        # Preserve ELF structure while making PT_INTERP refer to a missing file.
        contents = contents.replace(b"/lib64/ld-linux-x86-64.so.2", b"/nope_/ld-linux-x86-64.so.2")
        broken.write_bytes(contents)
        broken.chmod(0o755)
        for path in (noexec, broken):
            with self.subTest(path=path):
                result = subprocess.run([SDB, str(path)], capture_output=True, text=True, timeout=5)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("target failed to start", result.stderr)

    def test_malformed_elf_section_table(self):
        contents = bytearray((self.root / "pie").read_bytes())
        struct.pack_into("<Q", contents, 40, 0xfffffffffffffff0)  # e_shoff
        path = self.root / "bad-sections"
        path.write_bytes(contents)
        path.chmod(0o755)
        result = subprocess.run([SDB, str(path)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("malformed ELF", result.stderr)

    def test_bad_programs(self):
        invalid = self.root / "invalid"
        invalid.write_bytes(b"not an ELF")
        for args in ([], [str(invalid)], [str(self.root / "missing")]):
            with self.subTest(args=args):
                result = subprocess.run([SDB, *args], capture_output=True, text=True, timeout=5)
                self.assertNotEqual(0, result.returncode)
                self.assertTrue("Usage:" in result.stderr or "error:" in result.stderr)

    def test_quit_and_eof(self):
        for commands in ("quit\n", ""):
            result = subprocess.run([SDB, str(self.root / "pie")], input=commands,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

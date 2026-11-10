"""Real ptrace integration tests; only Python's standard library is required."""
import os
from pathlib import Path
import re
import select
import signal
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
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


class DebuggerTests(unittest.TestCase):
    # Static targets need the static C library (glibc-static); skip them when
    # the host cannot link -static instead of failing the whole suite.
    OPTIONAL_TARGETS = {"static", "static-pie", "safety-static", "safety-static-pie"}

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.programs = set()
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
            cls.build(name, ["gcc", "-g", "-O0", *flags, str(source), "-o", str(cls.root / name)])
        safety = cls.root / "safety.c"
        safety.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
volatile unsigned counter = 0x11223344;
volatile unsigned zero;
const char msg[] = "hello";
char *heap_ptr;
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
int main(void) {
    heap_ptr = malloc(16);
    if (!heap_ptr) return 99;
    strcpy(heap_ptr, "heap");
    ready();
    printf("counter=%x msg=%s zero=%u heap=%s\\n", counter, msg, zero, heap_ptr);
    int ok = counter == 0x11223344 && zero == 0 && !strcmp(msg, "hello") && !strcmp(heap_ptr, "heap");
    free(heap_ptr);
    return ok ? 0 : 9;
}
''')
        for name, flags in (("safety-pie", ["-fPIE", "-pie"]), ("safety-dynamic", ["-no-pie"]),
                            ("safety-static", ["-static", "-no-pie"]), ("safety-static-pie", ["-static-pie"])):
            cls.build(name, ["gcc", "-g", "-O0", *flags, str(safety), "-o", str(cls.root / name)])
        permissions = cls.root / "permissions.c"
        permissions.write_text('''#include <sys/mman.h>
#include <unistd.h>
__attribute__((section(".victim"), aligned(4096), noinline))
void victim(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    unsigned char original = *(volatile unsigned char *)victim;
    if (page != 4096 || mprotect((void *)victim, page, PROT_READ | PROT_WRITE)) return 99;
    ready();
    int ok = *(volatile unsigned char *)victim == original;
    if (mprotect((void *)victim, page, PROT_READ | PROT_EXEC)) return 98;
    return ok ? 0 : 11;
}
''')
        subprocess.run(["gcc", "-O0", "-fPIE", "-pie", str(permissions), "-o", str(cls.root / "permissions")], check=True)
        merged = cls.root / "merged.c"
        merged.write_text('#include <stdio.h>\nconst char msg[]="hello";\nint main(void){puts(msg);return 0;}\n')
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", "-Wl,-z,noseparate-code",
                        str(merged), "-o", str(cls.root / "merged")], check=True)
        bug_source = cls.root / "bugs.c"
        bug_source.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
const char msg[] = "hello";
volatile int counter = 0x11223344;
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
static void *worker(void *p) { ready(); return p; }
int main(int argc, char **argv) {
    char mode = argc > 1 ? argv[1][0] : 'n';
    if (mode == 't') { pthread_t t; pthread_create(&t, 0, worker, 0); pthread_join(t, 0); }
    else if (mode == 'f') { if (fork() == 0) { sleep(30); _exit(0); } wait(0); }
    else if (mode == 'e') { execl("/bin/true", "true", (char *)0); return 90; }
    else if (mode == 'v') { __asm__ volatile("pcmpeqd %%xmm0, %%xmm0; fld1" ::: "xmm0"); ready(); }
    else if (mode == 'l') { for (;;) __asm__ volatile("nop"); }
    else if (mode == 'r') { char b[64]; if (fgets(b, sizeof(b), stdin)) printf("INPUT:%s", b); else puts("EOF"); }
    else { puts(msg); printf("counter=%x\\n", counter); void *p = malloc(23); ready(); free(p); }
    return 0;
}
''')
        subprocess.run(["gcc", "-g", "-O0", "-fno-builtin", "-fPIE", "-pie", "-pthread",
                        "-Wl,-z,noseparate-code", str(bug_source), "-o", str(cls.root / "bugs")], check=True)
        library = cls.root / "library.c"
        library.write_text('''__thread int tls_value;
int shared_hit(void) { return 1; }
static int implementation(void) { return 2; }
static int (*resolver(void))(void) { return implementation; }
int indirect(void) __attribute__((ifunc("resolver")));
''')
        for name in ("one", "two"):
            subprocess.run(["gcc", "-shared", "-fPIC", "-g", str(library), "-o", str(cls.root / ("lib" + name + ".so"))], check=True)
        loader = cls.root / "loader.c"
        loader.write_text('''#include <dlfcn.h>
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
int main(int argc, char **argv) {
    ready();
    void *one = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *two = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!one || !two) return 91;
    ready();
    int (*hit)(void) = (int (*)(void))dlsym(one, "shared_hit");
    int result = hit();
    dlclose(two); dlclose(one);
    return result == 1 ? 0 : 92;
}
''')
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(loader), "-ldl", "-o", str(cls.root / "loader")], check=True)
        version_library = cls.root / "versions.c"
        version_library.write_text('''int old_api(void) { return 1; }
int new_api(void) { return 2; }
__asm__(".symver old_api,api@V1");
__asm__(".symver new_api,api@@V2");
''')
        script = cls.root / "versions.map"
        script.write_text("V1 {}; V2 {} V1;")
        subprocess.run(["gcc", "-shared", "-fPIC", str(version_library), "-Wl,--version-script=" + str(script),
                        "-o", str(cls.root / "libversions.so")], check=True)
        subprocess.run(["strip", "--strip-all", str(cls.root / "libversions.so")], check=True)
        version_target = cls.root / "versioned.c"
        version_target.write_text('''#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
int main(int argc, char **argv) {
    if (!stdout) return 90; /* exercise copy relocation version requirements */
    void *library = dlopen(argv[1], RTLD_NOW);
    if (!library) return 91;
    int (*latest)(void) = dlsym(library, "api");
    int (*old)(void) = dlvsym(library, "api", "V1");
    ready();
    return latest() == 2 && old() == 1 ? 0 : 92;
}
''')
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(version_target), "-ldl",
                        "-o", str(cls.root / "versioned")], check=True)
        blocking = cls.root / "blocking.c"
        blocking.write_text('''#include <unistd.h>
char storage;
__attribute__((naked,noinline)) void blocked(int fd) {
    __asm__("xor %eax,%eax; lea storage(%rip),%rsi; mov $1,%edx;"
            ".global blocked_syscall; blocked_syscall: syscall; ret");
}
int main(void) { int descriptors[2]; if (pipe(descriptors)) return 90; blocked(descriptors[0]); return 0; }
''')
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(blocking), "-o", str(cls.root / "blocking")], check=True)
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
    def build(cls, name, command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            cls.programs.add(name)
            return
        if any(argument.startswith("-static") for argument in command):
            detail = next((line for line in result.stderr.splitlines() if "cannot find" in line), "")
            if not detail:
                detail = (result.stderr.strip().splitlines() or ["link failed"])[-1]
            print(f"skipping {name}: static C library unavailable ({detail.strip()})", file=sys.stderr)
            return
        raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)

    @classmethod
    def available(cls, names):
        present = [name for name in names if name in cls.programs]
        if not present:
            raise unittest.SkipTest("no matching target binaries are available")
        return present

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name="pie", *args):
        if name in self.OPTIONAL_TARGETS and name not in self.programs:
            raise unittest.SkipTest(f"{name} target is unavailable")
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
        for name in self.available(("pie", "dynamic", "static", "static-pie")):
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

    def test_help_topics_aliases_and_delete_all(self):
        s = self.session()
        self.assertIn("Set a software breakpoint", s.command("help b"))
        self.assertIn("no help for", s.command("help nosuch"))
        self.assertIn("set a breakpoint", s.command("b tick"))
        self.assertIn("set a breakpoint", s.command("b main"))
        listing = s.command("i breakpoints")
        self.assertIn("tick", listing)
        self.assertIn("main", listing)
        self.assertIn("deleted 2", s.command("delete all"))
        self.assertIn("no breakpoints", s.command("i breakpoints"))
        self.assertIn("exited with status 3", s.command("c"))

    def test_signal_delivery_and_arguments(self):
        s = self.session("pie", "signal")
        self.assertIn("stopped by signal 10", s.command("cont"))
        self.assertIn("exited with status 8", s.command("cont"))

    def test_target_sigtrap_is_forwarded(self):
        s = self.session("pie", "trap")
        self.assertIn("stopped by signal 5", s.command("cont"))
        self.assertIn("terminated by signal 5", s.command("cont"))

    def test_symbol_breakpoints_all_program_types(self):
        for name in self.available(("pie", "dynamic", "static", "static-pie")):
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

    def test_enable_revalidates_executable_permissions(self):
        s = self.session("permissions")
        original = s.command("x victim 1").splitlines()[0]
        s.command("break victim")
        s.command("disable 1")
        s.command("break ready")
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("not in an executable mapping", s.command("enable 1"))
        self.assertRegex(s.command("info breakpoints"), r"1  disabled +0x")
        self.assertEqual(original, s.command("x victim 1").splitlines()[0])
        self.assertIn("exited with status 0", s.command("cont"))

    def test_non_executable_breakpoints_do_not_modify_target(self):
        for name in self.available(("safety-pie", "safety-dynamic", "safety-static", "safety-static-pie")):
            with self.subTest(name=name):
                s = self.session(name)
                s.command("break ready")
                self.assertIn("hit a breakpoint", s.command("cont"))
                heap_output = s.command("x heap_ptr 8").splitlines()[0]
                heap_bytes = bytes.fromhex(heap_output.split(":", 1)[1])
                heap = int.from_bytes(heap_bytes, "little")
                # Symbols and raw addresses must follow the same validation path.
                requests = ["counter", "zero", "msg", "$rsp", f"{heap:x}", "0"]
                requests += [f"{self.address(s, name, symbol):x}" for symbol in ("counter", "zero", "msg")]
                s.command("anchor")
                for target in requests:
                    before = s.command(f"x {target} 4").splitlines()[0] if target != "0" else None
                    output = s.command(f"break {target}")
                    self.assertTrue("not in an executable mapping" in output or "data symbols cannot" in output, (name, target, output))
                    if before:
                        self.assertEqual(before, s.command(f"x {target} 4").splitlines()[0], target)
                    listing = s.command("info breakpoints")
                    self.assertEqual(1, len(re.findall(r"^\d+  enabled", listing, re.M)), listing)
                self.assertIn("go back to the anchor", s.command("timetravel"))
                self.assertIn("(id 2)", s.command("break main"))
                output = s.command("cont")
                self.assertIn("counter=11223344 msg=hello zero=0 heap=heap", output)
                self.assertIn("exited with status 0", output)

    def test_executable_segment_data_symbol_is_rejected(self):
        s = self.session("bugs")
        pid = int(re.search(r"PID: (\d+)", s.initial)[1])
        address = self.address(s, "bugs", "msg")
        containing = [line for line in Path(f"/proc/{pid}/maps").read_text().splitlines()
                      if int(line.split()[0].split('-')[0], 16) <= address < int(line.split()[0].split('-')[1], 16)]
        self.assertEqual(1, len(containing))
        self.assertIn('x', containing[0].split()[1])
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
            memory.seek(address)
            before = memory.read(6)
        self.assertIn("error:", s.command("break msg"))
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
            memory.seek(address)
            self.assertEqual(before, memory.read(6))
        self.assertIn("error:", s.command("break counter"))
        self.assertIn("no breakpoints", s.command("info breakpoints"))
        self.assertIn("(id 1)", s.command("break main"))
        s.command("delete 1")
        output = s.command("cont")
        self.assertRegex(output, r"(?:^|\n)hello\n")
        self.assertIn("counter=11223344", output)

    def test_small_merged_elf_load_bias_is_unambiguous(self):
        s = self.session("merged")
        self.assertIn("data symbols cannot", s.command("break msg"))
        self.assertIn("(id 1)", s.command("break main"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 1")
        self.assertIn("hello", s.command("cont"))

    def test_pid_and_mappings_visible(self):
        s = self.session("bugs")
        self.assertIn("PID:", s.initial)
        pid = int(re.search(r"PID: (\d+)", s.initial)[1])
        children = Path(f"/proc/{s.process.pid}/task/{s.process.pid}/children").read_text().split()
        self.assertIn(str(pid), children)
        info = s.command("info proc")
        self.assertIn(f"PID: {pid}", info)
        self.assertIn(f"PPID: {s.process.pid}", info)
        mappings = s.command("info proc mappings")
        self.assertIn("[stack]", mappings)
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            self.assertIn(line.split()[0], mappings)
        self.assertIn("libc.so", s.command("info sharedlibrary"))

    def test_shared_library_breakpoint(self):
        s = self.session("bugs")
        self.assertIn("set a breakpoint", s.command("break puts"))
        self.assertIn("hit a breakpoint", s.command("cont"))

    def test_dlopen_ambiguity_and_unsupported_symbols(self):
        s = self.session("loader", str(self.root / "libone.so"), str(self.root / "libtwo.so"))
        self.assertIn("currently loaded objects", s.command("break libone:shared_hit"))
        s.command("break ready")
        s.command("cont")
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("libone.so", s.command("info sharedlibrary"))
        output = s.command("break shared_hit")
        self.assertIn("ambiguous symbol", output)
        self.assertIn("libone.so", output)
        self.assertIn("libtwo.so", output)
        for name in ("tls_value", "indirect"):
            self.assertIn("TLS/IFUNC", s.command("break libone:" + name))
        self.assertIn("(id 2)", s.command("break libone:shared_hit"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 2")
        self.assertIn("exited with status 0", s.command("cont"))

    def test_libc_function_breakpoints_under_aslr(self):
        for function in ("puts", "printf", "malloc"):
            with self.subTest(function=function):
                s = self.session("bugs")
                self.assertIn("set a breakpoint", s.command("break libc:" + function))
                self.assertIn("hit a breakpoint", s.command("cont"))
                self.assertNotIn("stopped by signal", s.command("si"))

    def test_fp_registers_visible(self):
        s = self.session("bugs")
        for register in ("xmm0", "st0", "mxcsr"):
            self.assertIn(register + " = 0x", s.command("regs " + register))

    def test_fp_register_values(self):
        s = self.session("bugs", "vector")
        s.command("break ready")
        s.command("cont")
        self.assertIn("xmm0 = 0xffffffffffffffffffffffffffffffff", s.command("regs xmm0"))
        self.assertIn("st0 = 0x3fff8000000000000000", s.command("regs st0"))
        self.assertIn("mxcsr = 0x", s.command("regs fp"))
        ymm = s.command("regs ymm0")
        self.assertTrue("ymm0 = 0x" in ymm or "unavailable" in ymm, ymm)
        for register in ("xmm16", "ymm16", "st8", "xmm-1"):
            self.assertIn("error:", s.command("regs " + register))

    def test_target_stdin_isolated(self):
        s = self.session("bugs", "read")
        s.process.stdin.write(b"cont\n")
        s.process.stdin.flush()
        # EOF must arrive without supplying target input or a debugger command.
        output = s.read()
        self.assertIn("EOF", output)
        self.assertNotIn("INPUT:", output)

    def test_unsupported_process_events_end_safely(self):
        for mode, event in (("thread", "clone/thread"), ("fork", "fork"), ("exec", "exec")):
            with self.subTest(mode=mode):
                s = self.session("bugs", mode)
                pid = int(re.search(r"PID: (\d+)", s.initial)[1])
                if mode == "thread":
                    s.command("break ready")
                output = s.command("cont")
                self.assertIn("unsupported target event: " + event, output)
                self.assertNotIn("terminated by signal 5", output)
                s.process.wait(timeout=5)
                self.assertFalse(Path(f"/proc/{pid}").exists(), output)
                for descendant in re.findall(r"traced child PID: (\d+)", output):
                    self.assertFalse(Path(f"/proc/{descendant}").exists(), output)

    def test_ctrl_c_pauses_and_resumes(self):
        s = self.session("bugs", "loop")
        pid = int(re.search(r"PID: (\d+)", s.initial)[1])
        for _ in range(2):
            s.process.stdin.write(b"cont\n")
            s.process.stdin.flush()
            time.sleep(0.15)
            os.kill(s.process.pid, signal.SIGINT)
            self.assertIn("paused by Ctrl-C", s.read())
            self.assertIn("rip = 0x", s.command("regs rip"))
        s.command("quit")
        s.process.wait(timeout=5)
        self.assertFalse(Path(f"/proc/{pid}").exists())


    def test_raw_data_address_is_rejected_and_code_warns(self):
        s = self.session("merged")
        address = self.address(s, "merged", "msg")
        self.assertIn("known data address", s.command(f"break {address:x}"))
        self.assertIn("no breakpoints", s.command("info breakpoints"))
        code = self.address(s, "merged", "main")
        output = s.command(f"break {code:x}")
        self.assertIn("cannot verify instruction boundaries", output)
        self.assertIn("(id 1)", output)
        s.command("cont")
        output = s.command("cont")
        self.assertIn("hello", output)
        self.assertIn("exited with status 0", output)

    def test_explicit_symbol_versions_and_default(self):
        s = self.session("versioned", str(self.root / "libversions.so"))
        s.command("break ready")
        s.command("cont")
        self.assertIn("(id 2)", s.command("break libversions:api@V1"))
        self.assertIn("(id 3)", s.command("break libversions:api@@V2"))
        self.assertIn("already exists", s.command("break libversions:api"))
        self.assertIn("error:", s.command("break libversions:api@MISSING"))
        default_address = re.search(r"3  enabled +0x([0-9a-f]+)", s.command("info breakpoints"))[1]
        self.assertIn("hit a breakpoint at 0x" + default_address, s.command("cont"))
        s.command("delete 3")
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 2")
        self.assertIn("exited with status 0", s.command("cont"))

    def test_libc_explicit_symbol_version(self):
        s = self.session("bugs")
        self.assertIn("set a breakpoint", s.command("break libc:puts@GLIBC_2.2.5"))
        self.assertIn("hit a breakpoint", s.command("cont"))

    def test_ctrl_c_during_continue_internal_step(self):
        s = self.session("blocking")
        s.command("break blocked_syscall")
        self.assertIn("hit a breakpoint", s.command("cont"))
        # The next cont must single-step a blocking read syscall: this creates
        # a deterministic interruption window rather than relying on timing a NOP.
        s.process.stdin.write(b"cont\n")
        s.process.stdin.flush()
        time.sleep(0.2)
        os.kill(s.process.pid, signal.SIGINT)
        self.assertIn("Ctrl-C", s.read())
        self.assertIn("rip = 0x", s.command("regs rip"))
        os.kill(s.process.pid, signal.SIGINT)
        s.process.wait(timeout=5)

    def test_syscall_catching_at_a_software_breakpoint(self):
        s = self.session("blocking")
        s.command("break blocked_syscall")
        s.command("cont")
        s.command("catch syscall 0")
        self.assertIn("syscall entry 0", s.command("cont"))

    def test_snapshot_rejects_pending_signal_without_consuming_it(self):
        s = self.session("pie", "signal")
        self.assertIn("stopped by signal 10", s.command("cont"))
        self.assertIn("without pending signal", s.command("anchor"))
        self.assertIn("no anchor", s.command("timetravel"))
        self.assertIn("exited with status 8", s.command("cont"))

    def test_symbol_cache_refreshes_after_library_replacement(self):
        library = self.root / "libreload.so"
        shutil.copyfile(self.root / "libone.so", library)
        source = self.root / "reload.c"
        source.write_text('''#include <dlfcn.h>
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
int main(int argc, char **argv) {
    void *h = dlopen(argv[1], RTLD_NOW); if (!h) return 90;
    ready(); dlclose(h);
    h = dlopen(argv[1], RTLD_NOW); if (!h) return 91;
    ready();
    int (*fresh)(void) = dlsym(h, "fresh_hit");
    int (*hex_name)(void) = dlsym(h, "abc");
    return fresh && hex_name && fresh() == 3 && hex_name() == 4 ? 0 : 92;
}
''')
        target = self.root / "reload"
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(source), "-ldl", "-o", str(target)], check=True)
        s = self.session("reload", str(library))
        s.command("break ready")
        s.command("cont")
        self.assertNotIn("error:", s.command("x shared_hit 1"))
        replacement = self.root / "fresh.c"
        replacement.write_text("int fresh_hit(void){return 3;} int abc(void){return 4;}")
        replacement_library = self.root / "fresh.so"
        subprocess.run(["gcc", "-shared", "-fPIC", str(replacement), "-o", str(replacement_library)], check=True)
        os.replace(replacement_library, library)
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("(id 2)", s.command("break fresh_hit"))
        self.assertIn("(id 3)", s.command("break abc"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 2")
        self.assertIn("hit a breakpoint", s.command("cont"))
        s.command("delete 3")
        self.assertIn("exited with status 0", s.command("cont"))

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

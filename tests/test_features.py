"""End-to-end tests for P1 workflows and hardware/syscall stop semantics."""
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import unittest
from test_debugger import Session, SDB


class FeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / "features.c"
        cls.source.write_text('''#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
volatile int counter;
char bytes[32];
char *cross_ptr;
void *code_ptr;
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void leaf(void) { ++counter; }
__attribute__((noinline)) void hardware_write(void) {
    __asm__ volatile(".global inc_counter; inc_counter: incl counter(%%rip)" ::: "memory");
}
__attribute__((noinline,optimize("omit-frame-pointer"))) int omitted(int value) {
    volatile int local = value;
    __asm__ volatile(".global omitted_body; omitted_body: nop");
    return local + 1;
}
__attribute__((noinline)) int plus(int value) { return value + 1; }
__attribute__((noinline)) void outer(void) {
    __asm__ volatile(".global call_leaf; call_leaf: call leaf; .global after_leaf; after_leaf: nop"
        ::: "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory");
}
__attribute__((noinline)) void recurse(int n) { if (n) recurse(n-1); else leaf(); }
int main(int argc, char **argv) {
    char mode = argc > 1 ? argv[1][0] : 'n';
    if (mode == 'u') {
        code_ptr = mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (code_ptr == MAP_FAILED) return 90;
        *(unsigned char *)code_ptr = 0xc3;
        if (mprotect(code_ptr,4096,PROT_READ|PROT_EXEC)) return 91;
        ready(); munmap(code_ptr,4096);
        ((void (*)(void))code_ptr)(); return 92;
    }
    if (mode == 'v') {
        __asm__ volatile("pcmpeqd %%xmm0,%%xmm0" ::: "xmm0"); ready();
        __asm__ volatile("pxor %%xmm0,%%xmm0" ::: "xmm0"); counter = 7; ready(); return 0;
    }
    if (mode == 'r') { ready(); void *p = mmap(0,4096,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); ready(); munmap(p,4096); return 0; }
    if (mode == 'h') { void *p = mmap(0,256UL*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); ready(); munmap(p,256UL*1024*1024); return 0; }
    if (mode == 'w') {
        char *p = mmap(0,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (p == MAP_FAILED) return 91;
        cross_ptr = p + 4094;
        cross_ptr[0]=0x44; cross_ptr[1]=0x33; cross_ptr[2]=0x22; cross_ptr[3]=0x11;
        if (mprotect(p+4096,4096,PROT_READ)) return 92;
        ready();
        return cross_ptr[0] == 0x44 && cross_ptr[1] == 0x33 ? 0 : 93;
    }
    if (mode == 'q') { counter = 5; ready(); return counter; }
    if (mode == 'x') {
        code_ptr = mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (code_ptr == MAP_FAILED) return 90;
        *(unsigned char *)code_ptr = 0xc3;
        if (mprotect(code_ptr,4096,PROT_READ|PROT_EXEC)) return 91;
        ready();
        munmap(code_ptr,4096);
        ready();
        return 0;
    }
    ready();
    if (mode == 'd') { hardware_write(); return counter; }
    if (mode == 's') { syscall(SYS_getpid); return 0; }
    if (mode == 'p') return plus(2);
    if (mode == 'o') return omitted(2);
    if (mode == 'b') recurse(3); else outer();
    return counter;
}
''')
        cls.target = cls.root / "features"
        subprocess.run(["gcc", "-g", "-O0", "-fno-omit-frame-pointer", "-fPIE", "-pie", str(cls.source), "-o", str(cls.target)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, mode="normal"):
        s = Session(self.target, mode)
        self.addCleanup(s.close)
        self.assertIn("loaded. entry point", s.initial)
        return s

    def address(self, s, name):
        symbols = subprocess.check_output(["nm", str(self.target)], text=True)
        offset = int(re.search(r"^([0-9a-f]+) \w " + name + "$", symbols, re.M)[1], 16)
        bias = int(re.search(r"load bias 0x([0-9a-f]+)", s.initial)[1], 16)
        return offset + bias

    def test_delete_breakpoint_after_region_is_unmapped(self):
        s = self.session("xunmap")
        self.assertIn("set a breakpoint", s.command("break ready"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        data = s.command("x code_ptr 8").strip().split(":", 1)[1].split()
        address = int.from_bytes(bytes(int(value, 16) for value in data[:8]), "little")
        self.assertIn("set a breakpoint", s.command(f"break 0x{address:x}"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        output = s.command("delete 2")
        self.assertIn("breakpoint 2: delete", output)
        self.assertIn("no longer mapped", output)
        listing = s.command("info breakpoints")
        self.assertIn("1  enabled", listing)
        self.assertNotIn("2  enabled", listing)
        self.assertIn("exited with status 0", s.command("cont"))

    def test_target_keeps_default_sigpipe_disposition(self):
        source = self.root / "sigpipe.c"
        target = self.root / "sigpipe"
        source.write_text("""#include <signal.h>
int main(void) {
    struct sigaction action;
    if (sigaction(SIGPIPE, 0, &action)) return 9;
    return action.sa_handler == SIG_DFL ? 0 : 1;
}
""")
        subprocess.run(["gcc", "-O0", str(source), "-o", str(target)], check=True)
        s = Session(target)
        self.addCleanup(s.close)
        self.assertIn("exited with status 0", s.command("cont"))

    def test_source_line_breakpoint_where_list_and_step(self):
        s = self.session()
        self.assertIn("set a breakpoint", s.command(f"break {self.source}:8"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("features.c:8", s.command("info breakpoints"))
        self.assertIn("features.c:8", s.command("where"))
        self.assertIn("> 8", s.command("list"))
        self.assertIn("> 12", s.command("list 12"))
        self.assertIn("not present", s.command("list 9999"))
        stepped = s.command("step")
        self.assertIn("features.c:", stepped)
        self.assertNotIn("error:", stepped)
        self.assertIn("exited with status 1", s.command("cont"))

    def test_next_steps_over_call_without_consuming_user_ids(self):
        s = self.session()
        s.command("break call_leaf")
        s.command("cont")
        self.assertNotIn("error:", s.command("next"))
        self.assertIn(f"rip = 0x{self.address(s, 'after_leaf'):016x}", s.command("regs rip"))
        self.assertIn(": 01 00 00 00", s.command("x counter 4"))
        self.assertIn("(id 2)", s.command("break main"))
        self.assertIn("exited with status 1", s.command("cont"))

    def test_next_respects_user_breakpoint_inside_callee(self):
        s = self.session()
        s.command("break call_leaf")
        s.command("break leaf")
        s.command("cont")
        self.assertIn("hit a breakpoint", s.command("next"))
        self.assertIn(f"rip = 0x{self.address(s, 'leaf'):016x}", s.command("regs rip"))
        self.assertNotIn("error:", s.command("finish"))
        self.assertIn(f"rip = 0x{self.address(s, 'after_leaf'):016x}", s.command("regs rip"))

    def test_backtrace_recursive_frames_and_finish(self):
        s = self.session("backtrace")
        s.command("break leaf")
        s.command("cont")
        output = s.command("bt")
        self.assertIn("leaf+", output)
        self.assertGreaterEqual(output.count("recurse+"), 4, output)
        self.assertIn("main+", output)
        self.assertIn("features.c:", output)
        s.command("finish")
        self.assertIn(": 01 00 00 00", s.command("x counter 4"))
        self.assertIn("exited with status 1", s.command("cont"))

    def test_register_edit_changes_function_argument(self):
        s = self.session("plus")
        s.command("break plus")
        s.command("cont")
        self.assertIn("register updated", s.command("set $rdi = 40"))
        s.command("finish")
        self.assertIn("rax = 0x0000000000000029", s.command("regs rax"))
        self.assertIn("exited with status 41", s.command("cont"))

    def test_memory_edit_changes_execution_and_validates_before_writing(self):
        s = self.session()
        s.command("break ready")
        s.command("cont")
        self.assertIn("wrote 4 bytes", s.command("set mem counter 06000000"))
        original = s.command("regs rip")
        self.assertIn("error:", s.command("set $rip = 0"))
        self.assertEqual(original, s.command("regs rip"))
        for command in ("set mem ready cc", "set mem 0 00", "set mem counter zz", "set mem counter a", "set $cs = 1"):
            self.assertIn("error:", s.command(command), command)
        self.assertIn(": 06 00 00 00", s.command("x counter 4"))
        self.assertIn("exited with status 7", s.command("cont"))

    def test_watchpoint_stops_after_write(self):
        s = self.session()
        self.assertIn("set watchpoint 1", s.command("watch counter 4"))
        self.assertIn("hit watchpoint 1", s.command("cont"))
        self.assertIn(": 01 00 00 00", s.command("x counter 4"))
        self.assertIn("size 4", s.command("info watchpoints"))
        s.command("unwatch 1")
        self.assertIn("exited with status 1", s.command("cont"))

    def test_read_watchpoint_stops_on_read(self):
        s = self.session("quiet")
        s.command("break ready")
        s.command("cont")
        self.assertIn("set watchpoint 1 (read)", s.command("rwatch counter 4"))
        self.assertIn("read", s.command("info watchpoints"))
        self.assertIn("hit watchpoint 1 (read)", s.command("cont"))
        self.assertIn("exited with status 5", s.command("cont"))

    def test_write_watchpoint_ignores_a_later_read(self):
        s = self.session("quiet")
        s.command("break ready")
        s.command("cont")
        self.assertIn("set watchpoint 1 (write)", s.command("watch counter 4"))
        self.assertIn("exited with status 5", s.command("cont"))

    def test_unwatch_all(self):
        s = self.session()
        address = self.address(s, "bytes")
        self.assertIn("set watchpoint 1", s.command(f"watch {address:x} 1"))
        self.assertIn("set watchpoint 2", s.command(f"watch {address+1:x} 1"))
        self.assertIn("removed 2", s.command("unwatch all"))
        self.assertIn("no watchpoints", s.command("info watchpoints"))
        self.assertIn("removed 0", s.command("unwatch all"))
        self.assertIn("exited with status 1", s.command("cont"))

    def test_watchpoint_resource_limits(self):
        s = self.session()
        address = self.address(s, "bytes")
        for i in range(4):
            self.assertIn("set watchpoint", s.command(f"watch {address+i:x} 1"))
        self.assertIn("four hardware", s.command(f"watch {address+4:x} 1"))
        s.command("unwatch 2")
        self.assertIn("set watchpoint 5", s.command(f"watch {address+4:x} 1"))
        self.assertIn("error:", s.command(f"watch {address+1:x} 8"))
        self.assertIn("error:", s.command("watch counter 3"))

    def test_syscall_entry_exit_and_filter(self):
        s = self.session("syscall")
        s.command("break ready")
        s.command("cont")
        s.command("catch syscall 39")
        output = s.command("cont")
        self.assertIn("syscall entry 39", output)
        self.assertIn("(getpid)", output)
        pid = int(re.search(r"PID: (\d+)", s.initial)[1])
        output = s.command("cont")
        self.assertIn(f"syscall exit 39 result: {pid}", output)
        self.assertIn("(getpid)", output)
        s.command("catch syscall off")
        self.assertIn("exited with status 0", s.command("cont"))

    def test_snapshot_restores_fp_and_memory(self):
        s = self.session("vector")
        s.command("break ready")
        s.command("cont")
        self.assertIn("ffffffffffffffffffffffffffffffff", s.command("regs xmm0"))
        s.command("anchor")
        s.command("cont")
        self.assertIn("00000000000000000000000000000000", s.command("regs xmm0"))
        self.assertIn(": 07 00 00 00", s.command("x counter 4"))
        self.assertIn("go back", s.command("timetravel"))
        self.assertIn("ffffffffffffffffffffffffffffffff", s.command("regs xmm0"))
        self.assertIn(": 00 00 00 00", s.command("x counter 4"))

    def test_snapshot_rejects_readonly_mapping_change(self):
        s = self.session("readonly")
        s.command("break ready")
        s.command("cont")
        s.command("anchor")
        s.command("cont")
        self.assertIn("mappings changed", s.command("timetravel"))
        self.assertIn("exited with status 0", s.command("cont"))

    def test_snapshot_limit(self):
        s = self.session("huge")
        s.command("break ready")
        s.command("cont")
        self.assertIn("128 MiB", s.command("anchor"))
        self.assertIn("exited with status 0", s.command("cont"))

    def test_source_line_breakpoint_and_listing(self):
        s = self.session()
        line = self.source.read_text().splitlines().index("    ready();") + 1
        self.assertIn("set a breakpoint", s.command(f"break {self.source}:{line}"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn(f"features.c:{line}", s.command("where"))
        self.assertIn(f"> {line} ", s.command("list"))
        self.assertNotIn("error:", s.command("step"))

    def test_source_line_missing_is_recoverable(self):
        s = self.session()
        self.assertIn("source line not found", s.command("break features.c:99999"))
        self.assertIn("no breakpoints", s.command("info breakpoints"))
        self.assertIn("exited with status 1", s.command("cont"))

    def test_memory_write_crossing_readonly_page_is_atomic(self):
        s = self.session("write-boundary")
        s.command("break ready")
        s.command("cont")
        value = s.command("x cross_ptr 8").splitlines()[0].split(":", 1)[1]
        pointer = int.from_bytes(bytes.fromhex(value), "little")
        before = s.command(f"x {pointer:x} 4")
        self.assertIn("error:", s.command(f"set mem {pointer:x} aabbccdd"))
        self.assertEqual(before, s.command(f"x {pointer:x} 4"))
        self.assertIn("exited with status 0", s.command("cont"))

    def test_watchpoint_during_internal_breakpoint_step(self):
        s = self.session("data-write")
        s.command("break inc_counter")
        s.command("watch counter")
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn("hit watchpoint", s.command("cont"))
        self.assertIn(": 01 00 00 00", s.command("x counter 4"))
        self.assertIn("exited with status 1", s.command("cont"))

    def test_snapshot_rejects_syscall_stop(self):
        s = self.session("syscall")
        s.command("catch syscall 39")
        self.assertIn("syscall entry 39", s.command("cont"))
        self.assertIn("without pending signal", s.command("anchor"))
        self.assertIn("error:", s.command("catch syscall 18446744073709551615"))
        s.command("catch syscall off")
        self.assertIn("exited with status 0", s.command("cont"))

    def test_finish_rejects_omitted_frame_inside_framed_caller(self):
        s = self.session("omitted")
        s.command("break omitted_body")
        s.command("cont")
        before = s.command("regs rip")
        self.assertIn("frame pointer unavailable", s.command("finish"))
        self.assertEqual(before, s.command("regs rip"))
        self.assertIn("exited with status 3", s.command("cont"))

    def test_backtrace_without_symbols_has_address_frames(self):
        stripped = self.root / "stripped-features"
        shutil.copyfile(self.target, stripped)
        stripped.chmod(0o755)
        subprocess.run(["strip", "--strip-all", str(stripped)], check=True)
        s = Session(stripped, "backtrace")
        self.addCleanup(s.close)
        s.command(f"break {self.address(s, 'leaf'):x}")
        self.assertIn("hit a breakpoint", s.command("cont"))
        output = s.command("bt")
        self.assertGreaterEqual(len(re.findall(r"^#\d+  0x[0-9a-f]+", output, re.M)), 4, output)
        self.assertIn("??", output)
        self.assertIn("exited with status 1", s.command("cont"))

    def test_unmapped_breakpoint_does_not_block_pending_signal_delivery(self):
        for command in ("cont", "next"):
            with self.subTest(command=command):
                s = self.session("unmapped")
                s.command("break ready")
                s.command("cont")
                value = s.command("x code_ptr 8").splitlines()[0].split(":", 1)[1]
                pointer = int.from_bytes(bytes.fromhex(value), "little")
                s.command(f"break {pointer:x}")
                self.assertIn("stopped by signal 11", s.command("cont"))
                self.assertIn("error:", s.command("finish"))
                self.assertIn("backtrace truncated", s.command("bt"))
                self.assertIn("terminated by signal 11", s.command(command))


if __name__ == "__main__":
    unittest.main(verbosity=2)

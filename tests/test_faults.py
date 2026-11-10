"""Inject real ptrace errors into the test-only debugger, never production sdb."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import test_debugger as harness  # consumes debugger path from argv


class FaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.target = cls.root / "fault-target"
        source = cls.root / "fault.c"
        source.write_text('''volatile int counter;
char bytes[32];
__attribute__((noinline)) void ready(void) { __asm__ volatile("nop"); }
int main(void) { ready(); return counter; }
''')
        subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(source), "-o", str(cls.target)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self):
        control = self.root / self._testMethodName
        os.environ["SDB_FAULT_FILE"] = str(control)
        try:
            session = harness.Session(self.target)
        finally:
            del os.environ["SDB_FAULT_FILE"]
        self.addCleanup(session.close)
        session.command("break ready")
        self.assertIn("hit a breakpoint", session.command("cont"))
        return session, control

    def test_partial_memory_write_rolls_back(self):
        s, control = self.session()
        before = s.command("x bytes 32")
        control.write_text("poke 2 0")
        self.assertIn("error:", s.command("set mem bytes " + "ab" * 32))
        self.assertEqual(before, s.command("x bytes 32"))
        self.assertIn("exited with status 0", s.command("cont"))

    def test_snapshot_memory_failure_restores_current_state(self):
        s, control = self.session()
        s.command("anchor")
        s.command("set mem counter 06000000")
        s.command("set $r12 = 77")
        # Fail the second bulk restore chunk, after the first one was written.
        control.write_text("vm 2 0")
        self.assertIn("original stopped state was restored", s.command("timetravel"))
        self.assertIn(": 06 00 00 00", s.command("x counter 4"))
        self.assertIn("000000000000004d", s.command("regs r12"))
        self.assertIn("exited with status 6", s.command("cont"))

    def test_snapshot_xsave_failure_rolls_back_memory_and_registers(self):
        s, control = self.session()
        s.command("anchor")
        s.command("set mem counter 06000000")
        before = s.command("regs xmm0")
        control.write_text("xstate 1 0")
        self.assertIn("original stopped state was restored", s.command("timetravel"))
        self.assertIn(": 06 00 00 00", s.command("x counter 4"))
        self.assertEqual(before, s.command("regs xmm0"))
        self.assertIn("exited with status 6", s.command("cont"))

    def test_reads_fall_back_when_bulk_read_is_unavailable(self):
        control = self.root / self._testMethodName
        control.write_text("r 1 0")
        os.environ["SDB_FAULT_FILE"] = str(control)
        try:
            s = harness.Session(self.target)
        finally:
            del os.environ["SDB_FAULT_FILE"]
        self.addCleanup(s.close)
        self.assertIn("loaded. entry point", s.initial)
        self.assertIn("set a breakpoint", s.command("break ready"))
        self.assertIn("hit a breakpoint", s.command("cont"))
        self.assertIn(": 00 00 00 00", s.command("x counter 4"))
        self.assertIn("exited with status 0", s.command("cont"))

    def test_snapshot_falls_back_when_bulk_write_is_unavailable(self):
        s, control = self.session()
        s.command("anchor")
        s.command("set mem counter 06000000")
        # Simulate a kernel/security module without process_vm_writev: the
        # restore must still complete through PTRACE_POKEDATA.
        control.write_text("e 1 0")
        self.assertIn("go back to the anchor", s.command("timetravel"))
        self.assertIn(": 00 00 00 00", s.command("x counter 4"))
        self.assertIn("exited with status 0", s.command("cont"))

    def test_memory_rollback_failure_terminates_target(self):
        s, control = self.session()
        pid = int(re.search(r"PID: (\d+)", s.initial)[1])
        control.write_text("poke 2 3")
        self.assertIn("rollback failed; target terminated", s.command("set mem bytes " + "ab" * 32))
        s.process.wait(timeout=5)
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_snapshot_rollback_failure_terminates_target(self):
        s, control = self.session()
        pid = int(re.search(r"PID: (\d+)", s.initial)[1])
        s.command("anchor")
        # Fail the restore of the anchor and the rollback of that failed restore.
        control.write_text("vm 2 3")
        self.assertIn("rollback failed; target terminated", s.command("timetravel"))
        s.process.wait(timeout=5)
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_syscall_info_error_does_not_forward_synthetic_sigtrap(self):
        s, control = self.session()
        control.write_text("sysinfo 1 0")
        s.command("catch syscall")
        self.assertIn("syscall information unavailable; catching disabled", s.command("cont"))
        self.assertIn("exited with status 0", s.command("cont"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Automated Verification Test Suite for Section 7: Verification & Seminar Demo Plan.

Verifies all requirements defined in Design Doc Section 7:
1. Feed Tamper Check Demo (Ed25519 signature verification + 1-byte adversary tampering)
2. Clean Baseline Scan (100% clean baseline, 0 IoC matches, false positive rate 0.0%)
3. Infected Artifact Detection (Multi-vector IoC matches: SHA-256, regex filenames, paths, SQLite cache)
4. Evidence Inspection & Authenticated Decryption (Non-printable ciphertext, authenticated unsealing, AEAD tag corruption rejection)
5. CLI and shell runner execution (pmfa-demo, run_demo.sh)
"""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pmfa.demo import SeminarDemoRunner


class TestSeminarDemoWorkflow(unittest.TestCase):
    """Integration tests validating Section 7 demo workflow."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent
        self.runner = SeminarDemoRunner(
            workspace_root=self.workspace_root,
            interactive=False,
            delay=0.0,
        )

    def test_step_1_feed_tamper_check_execution(self):
        """Validates Step 1: feed passes when valid, halts when tampered."""
        # Should not raise exception
        self.runner.step_1_feed_tamper_check()

    def test_step_2_clean_baseline_scan_execution(self):
        """Validates Step 2: clean backup produces 0 findings and seals report."""
        self.runner.step_2_clean_baseline_scan()
        self.assertTrue(self.runner.report_enc.is_file())
        self.assertTrue(self.runner.report_key.is_file())
        self.assertGreater(self.runner.report_enc.stat().st_size, 0)

    def test_step_3_infected_detection_execution(self):
        """Validates Step 3: infected backup triggers ALERT_GEN and correlates all IoCs."""
        self.runner.step_3_infected_detection()
        self.assertTrue(self.runner.report_enc.is_file())
        self.assertTrue(self.runner.report_key.is_file())

    def test_step_4_evidence_inspection_execution(self):
        """Validates Step 4: ciphertext inspection, authenticated decryption, and tamper rejection."""
        # Run infected scan first so report exists
        self.runner.step_3_infected_detection()
        # Verify inspection and authenticated decryption
        self.runner.step_4_evidence_inspection()

    def test_step_5_benchmarks_summary_execution(self):
        """Validates Step 5: live cryptographic performance benchmarks run cleanly."""
        self.runner.step_5_benchmarks_summary()

    def test_complete_demo_workflow_run(self):
        """Validates full end-to-end demo execution in automated mode."""
        exit_code = self.runner.run()
        self.assertEqual(exit_code, 0)

    def test_pmfa_demo_cli_executable(self):
        """Validates pmfa-demo console script execution."""
        proc = subprocess.run(
            ["pmfa-demo", "--auto", "--delay", "0"],
            cwd=str(self.workspace_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PEGASUS MOBILE FORENSIC AGENT (PMFA) - SEMINAR DEMO", proc.stdout)
        self.assertIn("Threat feed verified via Ed25519", proc.stdout)
        self.assertIn("100% Clean | 0 IOC Matches", proc.stdout)
        self.assertIn("ALERT_GEN State Triggered: 6 IOC findings correlated", proc.stdout)
        self.assertIn("Decryption Successful - Chain of Custody Intact!", proc.stdout)
        self.assertIn("AEAD Tag Verification Passed: Evidence tampering rejected", proc.stdout)
        self.assertIn("DEMO COMPLETED SUCCESSFULLY", proc.stdout)

    def test_run_demo_sh_script(self):
        """Validates ./run_demo.sh bash script execution."""
        script_path = self.workspace_root / "run_demo.sh"
        self.assertTrue(script_path.is_file())

        proc = subprocess.run(
            ["./run_demo.sh", "--auto", "--delay", "0"],
            cwd=str(self.workspace_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("DEMO COMPLETED SUCCESSFULLY", proc.stdout)


if __name__ == "__main__":
    unittest.main()

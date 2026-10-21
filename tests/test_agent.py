"""Unit and integration tests for PMFA Autonomous Agent Orchestrator & State Machine.

Validates:
1. Complete state machine lifecycle (Design Doc Section 4):
   - Clean execution: INITIALIZING -> FEED_VERIFY -> SCANNING -> ANALYZING -> SEALING -> COMPLETE
   - Anomaly detection: INITIALIZING -> FEED_VERIFY -> SCANNING -> ANALYZING -> ALERT_GEN -> SEALING -> COMPLETE
   - Failure abort: INITIALIZING -> FEED_VERIFY -> HALT
2. Alert callback invocation and alert JSON export
3. pmfa CLI entrypoints
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pmfa.agent import AgentState, PegasusForensicAgent
from pmfa.feed_verifier import E_INTEGRITY_FAIL


class TestAgentStateMachine(unittest.TestCase):
    """Tests autonomous state machine lifecycle transitions and anomaly branching."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent
        self.clean_backup = self.workspace_root / "test_fixtures" / "clean_backup"
        self.infected_backup = self.workspace_root / "test_fixtures" / "infected_backup"
        self.feed_path = self.workspace_root / "pmfa" / "feeds" / "iocs.json"
        self.sig_path = self.workspace_root / "pmfa" / "feeds" / "iocs.json.sig"
        self.pubkey_path = self.workspace_root / "pmfa" / "keys" / "vendor_public.pem"

    def test_clean_backup_state_transitions(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            enc_file = Path(tmp_dir) / "report.enc"
            key_file = Path(tmp_dir) / "report.key"

            agent = PegasusForensicAgent(
                target_path=str(self.clean_backup),
                feed_path=str(self.feed_path),
                sig_path=str(self.sig_path),
                pubkey_path=str(self.pubkey_path),
                output_enc_path=str(enc_file),
                output_key_path=str(key_file),
            )
            exit_code = agent.run()
            self.assertEqual(exit_code, 0)
            self.assertEqual(agent.state, AgentState.COMPLETE)

            expected_history = [
                AgentState.INITIALIZING,
                AgentState.FEED_VERIFY,
                AgentState.SCANNING,
                AgentState.ANALYZING,
                AgentState.SEALING,
                AgentState.COMPLETE,
            ]
            self.assertEqual(agent.state_history, expected_history)

    def test_infected_backup_triggers_alert_gen_state(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            enc_file = Path(tmp_dir) / "report.enc"
            key_file = Path(tmp_dir) / "report.key"
            alert_json = Path(tmp_dir) / "alert.json"

            callback_called = []

            def on_alert(report):
                callback_called.append(report.scan_id)

            agent = PegasusForensicAgent(
                target_path=str(self.infected_backup),
                feed_path=str(self.feed_path),
                sig_path=str(self.sig_path),
                pubkey_path=str(self.pubkey_path),
                output_enc_path=str(enc_file),
                output_key_path=str(key_file),
                alert_callback=on_alert,
                alert_json_path=str(alert_json),
            )
            exit_code = agent.run()
            self.assertEqual(exit_code, 0)
            self.assertEqual(agent.state, AgentState.COMPLETE)

            # Anomaly branching must transition into ALERT_GEN before SEALING
            expected_history = [
                AgentState.INITIALIZING,
                AgentState.FEED_VERIFY,
                AgentState.SCANNING,
                AgentState.ANALYZING,
                AgentState.ALERT_GEN,
                AgentState.SEALING,
                AgentState.COMPLETE,
            ]
            self.assertEqual(agent.state_history, expected_history)

            # Verify alert callback executed
            self.assertEqual(len(callback_called), 1)

            # Verify alert JSON was written to disk
            self.assertTrue(alert_json.is_file())
            data = json.loads(alert_json.read_text(encoding="utf-8"))
            self.assertTrue(data["threat_detected"])
            self.assertGreater(len(data["findings"]), 0)

    def test_tampered_feed_halts_in_halt_state(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tampered_feed = Path(tmp_dir) / "iocs.json"
            tampered_feed.write_text('{"bad": "feed"}', encoding="utf-8")

            agent = PegasusForensicAgent(
                target_path=str(self.clean_backup),
                feed_path=str(tampered_feed),
                sig_path=str(self.sig_path),
                pubkey_path=str(self.pubkey_path),
            )
            exit_code = agent.run()
            self.assertEqual(exit_code, E_INTEGRITY_FAIL)
            self.assertEqual(agent.state, AgentState.HALT)
            self.assertEqual(
                agent.state_history,
                [AgentState.INITIALIZING, AgentState.FEED_VERIFY, AgentState.HALT],
            )


class TestAgentCLI(unittest.TestCase):
    """Tests installed entry point and CLI orchestration."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent

    def test_cli_clean_execution(self):
        cmd = [
            "pmfa",
            "--target",
            "test_fixtures/clean_backup",
        ]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("100% Clean | 0 IOC Matches", proc.stdout)

    def test_cli_infected_with_alert_json(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            alert_out = Path(tmp_dir) / "cli_alert.json"
            cmd = [
                "pmfa",
                "--target",
                "test_fixtures/infected_backup",
                "--alert-json",
                str(alert_out),
            ]
            proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("ALERT: Threat Detected", proc.stdout)
            self.assertTrue(alert_out.is_file())


if __name__ == "__main__":
    unittest.main()

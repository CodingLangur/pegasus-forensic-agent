"""Main CLI Orchestrator & Autonomous State Machine for PMFA.

Coordinates the four discrete core architectural components:
1. Threat Feed Verification (Ed25519)
2. Forensic Inspection & Block Hashing (SHA-256)
3. Agent Logic & IoC Matching Engine (3 match vectors)
4. Evidence Packaging & Cryptographic Sealing (AES-256-GCM)
"""

import argparse
from enum import Enum
import logging
from pathlib import Path
import sys
from typing import Any, Callable, List, Optional

from pmfa.feed_verifier import E_INTEGRITY_FAIL, IntegrityVerificationError, verify_and_load_feed
from pmfa.matcher import IoCMatcher, display_terminal_summary
from pmfa.scanner import scan_directory
from pmfa.sealer import seal_report, unseal_report

logger = logging.getLogger("pmfa.agent")


class AgentState(Enum):
    """Forensic agent state machine states adhering to Design Doc Section 4."""
    INITIALIZING = "INITIALIZING"
    FEED_VERIFY = "FEED_VERIFY"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    ALERT_GEN = "ALERT_GEN"
    SEALING = "SEALING"
    COMPLETE = "COMPLETE"
    ABORTED = "ABORTED"
    HALT = "HALT"


class PegasusForensicAgent:
    """Autonomous mobile forensic analysis agent with state machine coordination."""

    def __init__(
        self,
        target_path: str,
        feed_path: str = "pmfa/feeds/iocs.json",
        sig_path: str = "pmfa/feeds/iocs.json.sig",
        pubkey_path: str = "pmfa/keys/vendor_public.pem",
        output_enc_path: str = "output/report.enc",
        output_key_path: str = "output/report.key",
        workers: int = 4,
        analyst_pubkey_path: Optional[str] = None,
        passphrase: Optional[str] = None,
        alert_callback: Optional[Callable[[Any], None]] = None,
        alert_json_path: Optional[str] = None,
    ):
        self.target_path = Path(target_path)
        self.feed_path = Path(feed_path)
        self.sig_path = Path(sig_path)
        self.pubkey_path = Path(pubkey_path)
        self.output_enc_path = Path(output_enc_path)
        self.output_key_path = Path(output_key_path)
        self.workers = workers
        self.analyst_pubkey_path = Path(analyst_pubkey_path) if analyst_pubkey_path else None
        self.passphrase = passphrase
        self.alert_callback = alert_callback
        self.alert_json_path = Path(alert_json_path) if alert_json_path else None
        self.state = AgentState.INITIALIZING
        self.state_history: List[AgentState] = [self.state]

    def transition(self, next_state: AgentState) -> None:
        """Executes state transition in agent lifecycle and records state history."""
        logger.debug("[State Machine] Transition: %s -> %s", self.state.value, next_state.value)
        self.state = next_state
        self.state_history.append(next_state)

    def run(self) -> int:
        """Executes autonomous forensic scanning and evidence packaging workflow."""
        # 1. State: INITIALIZING -> FEED_VERIFY
        self.transition(AgentState.FEED_VERIFY)
        try:
            feed = verify_and_load_feed(self.feed_path, self.sig_path, self.pubkey_path)
        except IntegrityVerificationError:
            self.transition(AgentState.HALT)
            return E_INTEGRITY_FAIL
        except Exception as exc:
            sys.stderr.write(f"[-] Fatal error during feed verification: {exc}\n")
            self.transition(AgentState.HALT)
            return 1

        # 2. State: FEED_VERIFY -> SCANNING
        self.transition(AgentState.SCANNING)
        try:
            scan_result = scan_directory(self.target_path, max_workers=self.workers)
        except Exception as exc:
            sys.stderr.write(f"[-] Scan traversal failed: {exc}\n")
            self.transition(AgentState.HALT)
            return 1

        # 3. State: SCANNING -> ANALYZING
        self.transition(AgentState.ANALYZING)
        matcher = IoCMatcher(feed)
        report = matcher.correlate_scan(scan_result)

        # 4. State Anomaly Branching: If anomalies detected, enter ALERT_GEN state before SEALING
        if report.threat_detected:
            self.transition(AgentState.ALERT_GEN)
            logger.warning(
                "[!] ALERT_GEN: %d anomaly match(es) detected. Generating forensic triage alert.",
                len(report.findings),
            )
            if self.alert_json_path:
                self.alert_json_path.parent.mkdir(parents=True, exist_ok=True)
                self.alert_json_path.write_text(report.to_json(), encoding="utf-8")
                print(f"[!] Pre-encryption alert exported : {self.alert_json_path}")
            if self.alert_callback:
                try:
                    self.alert_callback(report)
                except Exception as exc:
                    logger.error("[-] Error executing alert_callback: %s", exc)

        # 5. State: ANALYZING / ALERT_GEN -> SEALING
        self.transition(AgentState.SEALING)
        try:
            pkg = seal_report(
                report_data=report,
                output_enc_path=self.output_enc_path,
                output_key_path=self.output_key_path,
                analyst_pubkey=self.analyst_pubkey_path,
                passphrase=self.passphrase,
            )
        except Exception as exc:
            sys.stderr.write(f"[-] Cryptographic sealing failed: {exc}\n")
            self.transition(AgentState.HALT)
            return 1

        # 6. State: SEALING -> COMPLETE
        self.transition(AgentState.COMPLETE)

        # Output execution metrics and summary
        display_terminal_summary(report)
        print(f"[+] Encrypted Evidence Sealed : {pkg.encrypted_report_path}")
        if pkg.is_wrapped:
            print(f"[+] Chain of Custody Key ({pkg.wrapping_type}) : {pkg.key_path}")
        else:
            print(f"[+] Chain of Custody Key      : {pkg.key_path}")

        return 0


def main() -> int:
    """CLI orchestrator entry point."""
    parser = argparse.ArgumentParser(
        description="Pegasus Mobile Forensic Agent (PMFA) Orchestrator"
    )
    parser.add_argument(
        "--target",
        help="Target device backup or filesystem dump directory to inspect",
    )
    parser.add_argument(
        "--feed",
        default="pmfa/feeds/iocs.json",
        help="Path to threat feed JSON file (default: pmfa/feeds/iocs.json)",
    )
    parser.add_argument(
        "--sig",
        default="pmfa/feeds/iocs.json.sig",
        help="Path to detached signature file (default: pmfa/feeds/iocs.json.sig)",
    )
    parser.add_argument(
        "--pubkey",
        default="pmfa/keys/vendor_public.pem",
        help="Path to vendor public key PEM (default: pmfa/keys/vendor_public.pem)",
    )
    parser.add_argument(
        "--output-enc",
        default="output/report.enc",
        help="Path for encrypted report (default: output/report.enc)",
    )
    parser.add_argument(
        "--output-key",
        default="output/report.key",
        help="Path for encryption key (default: output/report.key)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent worker threads (default: 4)",
    )
    parser.add_argument(
        "--decrypt-report",
        metavar="REPORT_ENC",
        help="Inspect and decrypt an encrypted forensic report",
    )
    parser.add_argument(
        "--key",
        metavar="KEY_FILE",
        default="output/report.key",
        help="Key to use with --decrypt-report (default: output/report.key)",
    )
    parser.add_argument(
        "--analyst-pubkey",
        metavar="PUBKEY_FILE",
        help="Path to analyst RSA public key PEM to wrap evidence key",
    )
    parser.add_argument(
        "--analyst-privkey",
        metavar="PRIVKEY_FILE",
        help="Path to analyst RSA private key PEM to unwrap evidence key",
    )
    parser.add_argument(
        "--passphrase",
        help="Passphrase to derive KEK and wrap or unwrap evidence key",
    )
    parser.add_argument(
        "--alert-json",
        metavar="ALERT_FILE",
        help="Path to export unencrypted alert findings JSON if threats are detected (ALERT_GEN state)",
    )

    args = parser.parse_args()

    # Evidence decryption mode
    if args.decrypt_report:
        from pmfa.sealer import unseal_report
        import json
        try:
            report_dict = unseal_report(
                args.decrypt_report,
                args.key,
                analyst_privkey=args.analyst_privkey,
                passphrase=args.passphrase,
            )
            print(json.dumps(report_dict, indent=2))
            return 0
        except Exception as exc:
            sys.stderr.write(f"[-] Decryption error: {exc}\n")
            return 1

    if not args.target:
        parser.print_help()
        return 1

    agent = PegasusForensicAgent(
        target_path=args.target,
        feed_path=args.feed,
        sig_path=args.sig,
        pubkey_path=args.pubkey,
        output_enc_path=args.output_enc,
        output_key_path=args.output_key,
        workers=args.workers,
        analyst_pubkey_path=args.analyst_pubkey,
        passphrase=args.passphrase,
        alert_json_path=args.alert_json,
    )
    return agent.run()


if __name__ == "__main__":
    sys.exit(main())

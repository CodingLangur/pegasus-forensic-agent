"""Agent Logic & IoC Matching Engine.

Autonomous correlation engine that evaluates fingerprinted forensic artifacts
against verified threat intelligence definitions using three distinct match vectors:
1. Cryptographic SHA-256 hashes (exact malicious binary fingerprints)
2. Anomalous process / file names and injection paths
3. Network / domain indicators within SQLite caches or preference stores

Scores matches with forensic severity (CRITICAL, HIGH), extracts byte offsets,
and compiles standardized triage reports.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Union
import uuid

from pmfa.feed_verifier import ThreatFeed, verify_and_load_feed
from pmfa.parsers import (
    inspect_plist_file,
    inspect_sqlite_database,
    scan_raw_bytes_for_domains,
)
from pmfa.scanner import ForensicArtifact, ScanResult, scan_directory

logger = logging.getLogger("pmfa.matcher")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# ANSI terminal formatting
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


@dataclass(frozen=True)
class Finding:
    """Forensic match record identifying an indicator of compromise."""
    severity: str  # "CRITICAL", "HIGH"
    indicator_type: str  # "SHA256_HASH", "SUSPICIOUS_FILENAME", "SUSPICIOUS_PATH", "NETWORK_DOMAIN"
    matched_value: str
    file_path: str
    file_size_bytes: int
    details: str
    remediation: str
    byte_offset: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "severity": self.severity,
            "indicator_type": self.indicator_type,
            "matched_value": self.matched_value,
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
        }
        if self.details:
            result["details"] = self.details
        if self.remediation:
            result["remediation"] = self.remediation
        if self.byte_offset is not None:
            result["byte_offset"] = self.byte_offset
        return result


@dataclass
class TriageReport:
    """Pre-encryption forensic triage report adhering to Section 5.2 schema."""
    scan_id: str
    timestamp: str
    target_path: str
    metrics: Dict[str, Any]
    threat_detected: bool
    findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target_path": self.target_path,
            "metrics": {
                "files_scanned": self.metrics.get("files_scanned", 0),
                "scan_duration_ms": self.metrics.get("scan_duration_ms", 0.0),
            },
            "threat_detected": self.threat_detected,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class IoCMatcher:
    """Engine for evaluating discovered artifacts against verified IoC feeds."""

    def __init__(self, feed: ThreatFeed):
        self.feed = feed

    def match_hash(self, artifact: ForensicArtifact) -> Optional[Finding]:
        """Vector 1: Exact SHA-256 match against known malware/loader payloads."""
        if self.feed.matches_hash(artifact.sha256):
            return Finding(
                severity="CRITICAL",
                indicator_type="SHA256_HASH",
                matched_value=artifact.sha256,
                file_path=artifact.relative_path,
                file_size_bytes=artifact.file_size_bytes,
                details="Exact cryptographic SHA-256 match against verified Pegasus payload binary",
                remediation="Isolate device immediately from all cellular and Wi-Fi networks. Revoke credentials.",
            )
        return None

    def match_filename(self, artifact: ForensicArtifact) -> Optional[Finding]:
        """Vector 2a: Exact/regex match against known malicious process/dylib names."""
        file_name = Path(artifact.relative_path).name
        if self.feed.matches_filename(file_name):
            return Finding(
                severity="CRITICAL",
                indicator_type="SUSPICIOUS_FILENAME",
                matched_value=file_name,
                file_path=artifact.relative_path,
                file_size_bytes=artifact.file_size_bytes,
                details=f"Known malicious binary or injected extension filename detected: {file_name}",
                remediation="Preserve disk image for chain of custody. Investigate parent launch daemons.",
            )

        # Regex pattern matching
        matched_pat = self.feed.match_filename_pattern(file_name)
        if matched_pat:
            return Finding(
                severity="CRITICAL",
                indicator_type="SUSPICIOUS_FILENAME",
                matched_value=file_name,
                file_path=artifact.relative_path,
                file_size_bytes=artifact.file_size_bytes,
                details=f"Injected extension or malicious binary matched regex pattern '{matched_pat}': {file_name}",
                remediation="Preserve disk image for chain of custody. Investigate parent launch daemons.",
            )
        return None

    def match_path(self, artifact: ForensicArtifact) -> Optional[Finding]:
        """Vector 2b: Match against known temporary injection directories or persistence paths."""
        rel_norm = "/" + artifact.relative_path.lstrip("/").replace("\\", "/")
        abs_norm = "/" + artifact.absolute_path.lstrip("/").replace("\\", "/")

        for sp in self.feed.suspicious_paths:
            sp_norm = sp.strip().replace("\\", "/")
            # Check if relative or absolute path contains or ends with suspicious path
            if rel_norm.endswith(sp_norm) or abs_norm.endswith(sp_norm) or sp_norm in rel_norm or sp_norm in abs_norm:
                return Finding(
                    severity="CRITICAL",
                    indicator_type="SUSPICIOUS_PATH",
                    matched_value=sp,
                    file_path=artifact.relative_path,
                    file_size_bytes=artifact.file_size_bytes,
                    details=f"Anomalous persistence path or temporary injection directory identified: {sp}",
                    remediation="Inspect persistence hooks (LaunchDaemons, LaunchAgents) and crash logs.",
                )

        # Regex pattern matching for paths
        matched_pat = self.feed.match_path_pattern(rel_norm) or self.feed.match_path_pattern(abs_norm)
        if matched_pat:
            return Finding(
                severity="CRITICAL",
                indicator_type="SUSPICIOUS_PATH",
                matched_value=matched_pat,
                file_path=artifact.relative_path,
                file_size_bytes=artifact.file_size_bytes,
                details=f"Anomalous persistence path or temporary injection directory matched regex pattern '{matched_pat}': {rel_norm}",
                remediation="Inspect persistence hooks (LaunchDaemons, LaunchAgents) and crash logs.",
            )
        return None

    def match_network_domains(self, artifact: ForensicArtifact) -> List[Finding]:
        """Vector 3: Deep inspection of SQLite caches, Safari/WhatsApp plists, and binaries for C2 domains."""
        if not self.feed.suspicious_domains:
            return []

        # Target candidate files likely to hold network artifacts
        inspectable_types = {"database", "plist", "log", "data"}
        if artifact.file_type not in inspectable_types and not any(
            artifact.relative_path.endswith(ext) for ext in [".db", ".sqlite", ".sqlite3", ".plist", ".log", ".txt"]
        ):
            return []

        file_path = Path(artifact.absolute_path)
        if not file_path.is_file():
            return []

        try:
            content = file_path.read_bytes()
        except Exception:
            return []

        findings: List[Finding] = []
        seen_domains: Set[str] = set()

        # 1. Deep SQLite Inspection
        if artifact.file_type == "database" or any(artifact.relative_path.endswith(ext) for ext in [".db", ".sqlite", ".sqlite3"]):
            sqlite_matches = inspect_sqlite_database(file_path, self.feed.suspicious_domains)
            for sm in sqlite_matches:
                offset = content.find(sm.matched_value.encode("utf-8"))
                findings.append(
                    Finding(
                        severity=sm.severity,
                        indicator_type=sm.indicator_type,
                        matched_value=sm.matched_value,
                        file_path=artifact.relative_path,
                        file_size_bytes=artifact.file_size_bytes,
                        details=sm.details,
                        remediation="Block domain at perimeter DNS/firewall sinks. Review network flow logs for beaconing.",
                        byte_offset=offset if offset != -1 else None,
                    )
                )
                seen_domains.add(sm.matched_value)

        # 2. Deep Plist Inspection
        if artifact.file_type == "plist" or artifact.relative_path.endswith(".plist"):
            plist_matches = inspect_plist_file(
                file_path,
                suspicious_domains=self.feed.suspicious_domains,
                suspicious_filenames=self.feed.suspicious_filenames,
                suspicious_paths=self.feed.suspicious_paths,
            )
            for pm in plist_matches:
                if pm.indicator_type == "NETWORK_DOMAIN":
                    offset = content.find(pm.matched_value.encode("utf-8"))
                    findings.append(
                        Finding(
                            severity=pm.severity,
                            indicator_type=pm.indicator_type,
                            matched_value=pm.matched_value,
                            file_path=artifact.relative_path,
                            file_size_bytes=artifact.file_size_bytes,
                            details=pm.details,
                            remediation="Block domain at perimeter DNS/firewall sinks. Review network flow logs for beaconing.",
                            byte_offset=offset if offset != -1 else None,
                        )
                    )
                    seen_domains.add(pm.matched_value)

        # 3. Raw Byte Scanning Fallback (for unparsed databases, plists, logs, binaries)
        raw_matches = scan_raw_bytes_for_domains(content, self.feed.suspicious_domains)
        for domain, offset in raw_matches:
            if domain not in seen_domains:
                findings.append(
                    Finding(
                        severity="HIGH",
                        indicator_type="NETWORK_DOMAIN",
                        matched_value=domain,
                        file_path=artifact.relative_path,
                        file_size_bytes=artifact.file_size_bytes,
                        details=f"Pegasus C2 / telemetry domain string discovered at byte offset {offset}",
                        remediation="Block domain at perimeter DNS/firewall sinks. Review network flow logs for beaconing.",
                        byte_offset=offset,
                    )
                )
                seen_domains.add(domain)

        return findings

    def evaluate_artifact(self, artifact: ForensicArtifact) -> List[Finding]:
        """Correlates a single artifact across all three match vectors."""
        findings: List[Finding] = []

        # Vector 1: Cryptographic Hashes
        hash_finding = self.match_hash(artifact)
        if hash_finding:
            findings.append(hash_finding)

        # Vector 2a: Suspicious Filenames
        name_finding = self.match_filename(artifact)
        if name_finding:
            findings.append(name_finding)

        # Vector 2b: Suspicious Paths
        path_finding = self.match_path(artifact)
        if path_finding:
            findings.append(path_finding)

        # Vector 3: Network / Domain Indicators
        net_findings = self.match_network_domains(artifact)
        findings.extend(net_findings)

        return findings

    def correlate_scan(self, scan_result: ScanResult) -> TriageReport:
        """Executes full correlation across all artifacts in a scan result."""
        all_findings: List[Finding] = []
        for artifact in scan_result.artifacts:
            findings = self.evaluate_artifact(artifact)
            all_findings.extend(findings)

        # Deterministic sorting: CRITICAL first, then by relative path
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.indicator_type))

        scan_id = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return TriageReport(
            scan_id=scan_id,
            timestamp=timestamp,
            target_path=scan_result.target_path,
            metrics={
                "files_scanned": scan_result.metrics.files_scanned,
                "scan_duration_ms": scan_result.metrics.scan_duration_ms,
                "total_bytes_scanned": scan_result.metrics.total_bytes_scanned,
            },
            threat_detected=len(all_findings) > 0,
            findings=all_findings,
        )


def display_terminal_summary(report: TriageReport) -> None:
    """Renders formatted terminal output per Section 7 Course Demo Plan."""
    print("=" * 72)
    print("           PEGASUS MOBILE FORENSIC AGENT (PMFA) - TRIAGE REPORT          ")
    print("=" * 72)
    print(f" Scan ID         : {report.scan_id}")
    print(f" Timestamp       : {report.timestamp}")
    print(f" Target Path     : {report.target_path}")
    print(f" Files Scanned   : {report.metrics.get('files_scanned', 0)}")
    print(f" Scan Duration   : {report.metrics.get('scan_duration_ms', 0):.2f} ms")
    print("-" * 72)

    if not report.threat_detected:
        print(f"{ANSI_GREEN}{ANSI_BOLD}[+] RESULT: 100% Clean | 0 IOC Matches{ANSI_RESET}")
        print(f"{ANSI_GREEN}[+] Device backup shows no indicators of Pegasus compromise.{ANSI_RESET}")
    else:
        print(
            f"{ANSI_RED}{ANSI_BOLD}[!] ALERT: Threat Detected | {len(report.findings)} IOC Match(es) Found!{ANSI_RESET}"
        )
        print("-" * 72)
        for idx, finding in enumerate(report.findings, start=1):
            sev_color = ANSI_RED if finding.severity == "CRITICAL" else ANSI_YELLOW
            print(
                f"{sev_color}[{idx}] [{finding.severity}] {finding.indicator_type}: "
                f"'{finding.matched_value}'{ANSI_RESET}"
            )
            print(f"    File: {finding.file_path} ({finding.file_size_bytes:,} bytes)")
            if finding.byte_offset is not None:
                print(f"    Offset: Byte {finding.byte_offset}")
            print(f"    Details: {finding.details}")
            print(f"    Remediation: {finding.remediation}\n")

    print("=" * 72)


def main() -> int:
    """CLI utility for running IoC matching against device backups."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PMFA Agent Logic & IoC Matching Engine"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target device backup directory to scan and correlate",
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
        "--json",
        action="store_true",
        help="Output raw pre-encryption JSON triage report",
    )

    args = parser.parse_args()

    # Step 1: Verify and load threat feed
    try:
        feed = verify_and_load_feed(args.feed, args.sig, args.pubkey)
    except Exception as exc:
        sys.stderr.write(f"[-] Threat feed verification failed: {exc}\n")
        return 2

    # Step 2: Scan target backup
    try:
        scan_result = scan_directory(args.target)
    except Exception as exc:
        sys.stderr.write(f"[-] Target scan failed: {exc}\n")
        return 1

    # Step 3: Correlate artifacts against verified IoCs
    matcher = IoCMatcher(feed)
    report = matcher.correlate_scan(scan_result)

    if args.json:
        print(report.to_json())
    else:
        display_terminal_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())

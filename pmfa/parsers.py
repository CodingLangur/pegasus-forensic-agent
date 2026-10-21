"""Forensic Artifact Parsers for SQLite and Property Lists (plists).

Provides deep structural parsing of iOS device backups, extracted application
databases, and configuration plists:
1. SQLite Parser: Safely opens databases in read-only mode, queries tables and
   columns for network indicators (C2 domains), and extracts table/column/row context.
2. Property List Parser: Recursively inspects XML and binary plists (bplist00)
   to identify malicious bundle IDs, C2 domains, and persistence configurations.
3. Raw Byte Scanner: High-performance fallback byte search for corrupted, stub,
   or unstructured binary dumps.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
import plistlib
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("pmfa.parsers")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# SQLite file signature: 16 bytes: "SQLite format 3\x00"
SQLITE_HEADER = b"SQLite format 3\x00"


@dataclass(frozen=True)
class PlistMatch:
    """Represents a matched indicator discovered inside a property list."""
    key_path: str
    indicator_type: str
    matched_value: str
    details: str
    severity: str = "HIGH"


@dataclass(frozen=True)
class SQLiteMatch:
    """Represents an indicator discovered inside a SQLite database record."""
    table_name: str
    column_name: str
    row_id: Optional[Union[int, str]]
    indicator_type: str
    matched_value: str
    details: str
    severity: str = "HIGH"


def _walk_plist_structure(
    node: Any,
    current_path: str,
    suspicious_domains: Set[str],
    suspicious_filenames: Set[str],
    suspicious_paths: Set[str],
    results: List[PlistMatch],
) -> None:
    """Recursively walks nested plist dicts/lists to detect IoC indicators."""
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{current_path}/{k}" if current_path else k
            # Check key name itself
            for domain in suspicious_domains:
                if domain.lower() in k.lower():
                    results.append(
                        PlistMatch(
                            key_path=path,
                            indicator_type="NETWORK_DOMAIN",
                            matched_value=domain,
                            details=f"Suspicious domain discovered in plist key name: '{path}'",
                        )
                    )
            _walk_plist_structure(v, path, suspicious_domains, suspicious_filenames, suspicious_paths, results)

    elif isinstance(node, list):
        for idx, item in enumerate(node):
            path = f"{current_path}[{idx}]"
            _walk_plist_structure(item, path, suspicious_domains, suspicious_filenames, suspicious_paths, results)

    elif isinstance(node, (str, bytes)):
        val_str = node.decode("utf-8", errors="replace") if isinstance(node, bytes) else node

        # 1. Match domains
        for domain in suspicious_domains:
            if domain.lower() in val_str.lower():
                results.append(
                    PlistMatch(
                        key_path=current_path,
                        indicator_type="NETWORK_DOMAIN",
                        matched_value=domain,
                        details=f"C2/telemetry domain discovered in plist value at '{current_path}': '{val_str}'",
                    )
                )

        # 2. Match suspicious filenames / bundle IDs
        for fn in suspicious_filenames:
            if fn.lower() in val_str.lower():
                results.append(
                    PlistMatch(
                        key_path=current_path,
                        indicator_type="SUSPICIOUS_FILENAME",
                        matched_value=fn,
                        details=f"Malicious binary or bundle identifier discovered in plist at '{current_path}': '{val_str}'",
                        severity="CRITICAL",
                    )
                )

        # 3. Match suspicious paths
        for sp in suspicious_paths:
            if sp.lower() in val_str.lower():
                results.append(
                    PlistMatch(
                        key_path=current_path,
                        indicator_type="SUSPICIOUS_PATH",
                        matched_value=sp,
                        details=f"Suspicious injection or persistence path discovered in plist at '{current_path}': '{val_str}'",
                        severity="CRITICAL",
                    )
                )


def inspect_plist_file(
    file_path: Union[str, Path],
    suspicious_domains: Set[str],
    suspicious_filenames: Optional[Set[str]] = None,
    suspicious_paths: Optional[Set[str]] = None,
) -> List[PlistMatch]:
    """Inspects an XML or binary property list (.plist) file for threat indicators."""
    path = Path(file_path)
    if not path.is_file():
        return []

    try:
        content = path.read_bytes()
        parsed = plistlib.loads(content)
    except Exception as exc:
        logger.debug("Plist parsing skipped for %s: %s", path.name, exc)
        return []

    matches: List[PlistMatch] = []
    _walk_plist_structure(
        node=parsed,
        current_path="",
        suspicious_domains=suspicious_domains,
        suspicious_filenames=suspicious_filenames or set(),
        suspicious_paths=suspicious_paths or set(),
        results=matches,
    )
    return matches


def is_sqlite_database(file_path: Union[str, Path]) -> bool:
    """Verifies whether a file starts with the standard SQLite 3 header."""
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size < len(SQLITE_HEADER):
        return False
    try:
        with open(path, "rb") as f:
            header = f.read(len(SQLITE_HEADER))
            return header == SQLITE_HEADER
    except Exception:
        return False


def inspect_sqlite_database(
    file_path: Union[str, Path],
    suspicious_domains: Set[str],
    max_matches_per_table: int = 5,
) -> List[SQLiteMatch]:
    """Inspects a SQLite database in read-only mode, scanning table records for IoC domains.

    Queries all user tables across text and blob columns to identify network C2 indicators,
    capturing table names, column names, and row IDs.
    """
    path = Path(file_path).resolve()
    if not path.is_file() or not suspicious_domains:
        return []

    if not is_sqlite_database(path):
        return []

    matches: List[SQLiteMatch] = []
    uri = f"file:{path.as_posix()}?mode=ro"

    try:
        conn = sqlite3.connect(uri, uri=True, timeout=3.0)
    except Exception as exc:
        logger.debug("Could not open SQLite database %s: %s", path.name, exc)
        return []

    try:
        cursor = conn.cursor()
        # Enumerate user tables (excluding SQLite internal metadata)
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        )
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            # Get column info
            try:
                cursor.execute(f"PRAGMA table_info(\"{table}\");")
                columns_info = cursor.fetchall()
            except sqlite3.Error:
                continue

            # Check text or blob columns
            column_names = [col[1] for col in columns_info if col[1]]
            if not column_names:
                continue

            for col in column_names:
                for domain in suspicious_domains:
                    try:
                        # Parameterized query to avoid injection
                        query = f"SELECT rowid, \"{col}\" FROM \"{table}\" WHERE \"{col}\" LIKE ? LIMIT ?"
                        cursor.execute(query, (f"%{domain}%", max_matches_per_table))
                        rows = cursor.fetchall()
                        for row in rows:
                            row_id = row[0]
                            val = str(row[1])
                            matches.append(
                                SQLiteMatch(
                                    table_name=table,
                                    column_name=col,
                                    row_id=row_id,
                                    indicator_type="NETWORK_DOMAIN",
                                    matched_value=domain,
                                    details=(
                                        f"Pegasus C2 domain discovered in SQLite table '{table}', "
                                        f"column '{col}' (rowid {row_id})"
                                    ),
                                    severity="HIGH",
                                )
                            )
                    except sqlite3.Error:
                        # Some virtual tables or blob formats may not support rowid or LIKE; continue safely
                        continue
    except Exception as exc:
        logger.debug("Error querying SQLite database %s: %s", path.name, exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return matches


def scan_raw_bytes_for_domains(
    content: bytes,
    suspicious_domains: Set[str],
) -> List[Tuple[str, int]]:
    """Scans binary content for domain strings and returns list of (domain, byte_offset)."""
    matches: List[Tuple[str, int]] = []
    for domain in suspicious_domains:
        domain_bytes = domain.encode("utf-8")
        offset = content.find(domain_bytes)
        if offset != -1:
            matches.append((domain, offset))
    return matches

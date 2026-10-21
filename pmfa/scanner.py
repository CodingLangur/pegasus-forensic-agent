"""Forensic Inspection & Hashing Engine.

Autonomous inspection engine that traverses device backups, filesystem dumps,
and database artifacts to extract structural forensic metadata (POSIX timestamps,
permissions, sizes) and compute block-level streaming SHA-256 fingerprints.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Dict, List, Optional, Union

from pmfa.crypto.hashing import DEFAULT_CHUNK_SIZE, compute_sha256

logger = logging.getLogger("pmfa.scanner")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


@dataclass(frozen=True)
class ForensicArtifact:
    """Forensic record and cryptographic fingerprint for an inspected file."""
    absolute_path: str
    relative_path: str
    file_size_bytes: int
    sha256: str
    mtime: float
    ctime: float
    mtime_iso: str
    ctime_iso: str
    permissions_octal: str
    permissions_symbolic: str
    file_type: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes forensic artifact into a standard dictionary."""
        return asdict(self)


@dataclass
class ScanMetrics:
    """Performance and progress metrics for a forensic inspection run."""
    files_scanned: int = 0
    total_bytes_scanned: int = 0
    scan_duration_ms: float = 0.0
    errors_encountered: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Consolidated result of a device backup inspection run."""
    target_path: str
    start_time_iso: str
    artifacts: List[ForensicArtifact]
    metrics: ScanMetrics
    errors: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "start_time_iso": self.start_time_iso,
            "metrics": self.metrics.to_dict(),
            "artifacts_count": len(self.artifacts),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "errors": self.errors,
        }


def classify_file_type(path: Path) -> str:
    """Infers structural file type from extension or naming."""
    suffix = path.suffix.lower()
    if suffix in {".plist"}:
        return "plist"
    if suffix in {".dylib", ".so", ".bin", ".ext"}:
        return "binary"
    if suffix in {".db", ".sqlite", ".sqlite3"}:
        return "database"
    if suffix in {".log", ".txt", ".json"}:
        return "log"
    return suffix.lstrip(".") or "data"


def inspect_file(
    file_path: Union[str, Path],
    base_dir: Optional[Union[str, Path]] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ForensicArtifact:
    """Inspects a single file, extracting POSIX metadata and computing SHA-256."""
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Target file does not exist or is not a regular file: {path}")

    st = path.stat()
    file_sha256 = compute_sha256(path, chunk_size=chunk_size)

    base = Path(base_dir).resolve() if base_dir else path.parent
    try:
        rel_path = str(path.relative_to(base))
    except ValueError:
        rel_path = path.name

    mtime_iso = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    ctime_iso = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
    perm_octal = oct(st.st_mode & 0o777)
    perm_symbolic = stat.filemode(st.st_mode)
    file_type = classify_file_type(path)

    return ForensicArtifact(
        absolute_path=str(path),
        relative_path=rel_path,
        file_size_bytes=st.st_size,
        sha256=file_sha256,
        mtime=st.st_mtime,
        ctime=st.st_ctime,
        mtime_iso=mtime_iso,
        ctime_iso=ctime_iso,
        permissions_octal=perm_octal,
        permissions_symbolic=perm_symbolic,
        file_type=file_type,
    )


def scan_directory(
    target_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_workers: Optional[int] = None,
    follow_symlinks: bool = False,
) -> ScanResult:
    """Traverses a device backup directory or filesystem dump.

    Orchestrates multi-threaded block-level SHA-256 hashing and structural
    POSIX metadata extraction across all discovered binaries, plists, databases,
    and log files.
    """
    start_time = time.perf_counter()
    start_time_iso = datetime.now(timezone.utc).isoformat()

    root_path = Path(target_path).resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_path}")

    # Discover candidate files
    discovered_files: List[Path] = []
    for dirpath, _, filenames in os.walk(root_path, followlinks=follow_symlinks):
        for fname in filenames:
            file_path = Path(dirpath) / fname
            # Avoid broken symlinks unless explicitly requested
            if follow_symlinks or not file_path.is_symlink():
                discovered_files.append(file_path)

    artifacts: List[ForensicArtifact] = []
    errors: List[Dict[str, str]] = []
    total_bytes = 0

    workers = max_workers if (max_workers is not None and max_workers > 0) else min(32, (os.cpu_count() or 1) + 4)

    if workers > 1 and len(discovered_files) > 1:
        # Multi-threaded execution across backup artifacts
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_file = {
                executor.submit(inspect_file, f, root_path, chunk_size): f
                for f in discovered_files
            }
            for future in as_completed(future_to_file):
                f_path = future_to_file[future]
                try:
                    artifact = future.result()
                    artifacts.append(artifact)
                    total_bytes += artifact.file_size_bytes
                except Exception as exc:
                    logger.warning("[-] Error inspecting %s: %s", f_path, exc)
                    errors.append({"file": str(f_path), "error": str(exc)})
    else:
        # Sequential execution
        for f in discovered_files:
            try:
                artifact = inspect_file(f, root_path, chunk_size)
                artifacts.append(artifact)
                total_bytes += artifact.file_size_bytes
            except Exception as exc:
                logger.warning("[-] Error inspecting %s: %s", f, exc)
                errors.append({"file": str(f), "error": str(exc)})

    # Sort artifacts deterministically by relative path
    artifacts.sort(key=lambda a: a.relative_path)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    metrics = ScanMetrics(
        files_scanned=len(artifacts),
        total_bytes_scanned=total_bytes,
        scan_duration_ms=round(elapsed_ms, 2),
        errors_encountered=len(errors),
    )

    return ScanResult(
        target_path=str(root_path),
        start_time_iso=start_time_iso,
        artifacts=artifacts,
        metrics=metrics,
        errors=errors,
    )


def main() -> int:
    """CLI utility for standalone forensic backup inspection and hashing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PMFA Forensic Inspection & Hashing Engine (SHA-256)"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target device backup or filesystem dump directory to inspect",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent worker threads for file hashing (default: 4)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON scan results instead of summary",
    )

    args = parser.parse_args()

    try:
        result = scan_directory(args.target, max_workers=args.workers)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"[+] Target Scanned       : {result.target_path}")
            print(f"[+] Files Fingerprinted  : {result.metrics.files_scanned}")
            print(f"[+] Total Bytes Processed: {result.metrics.total_bytes_scanned:,} bytes")
            print(f"[+] Scan Duration        : {result.metrics.scan_duration_ms:.2f} ms")
            if result.errors:
                print(f"[-] Errors Encountered   : {result.metrics.errors_encountered}")
            print("\nSample Discovered Artifacts:")
            for artifact in result.artifacts[:5]:
                print(
                    f"  * [{artifact.file_type.upper():8s}] {artifact.relative_path} "
                    f"({artifact.file_size_bytes} B) -> {artifact.sha256[:16]}..."
                )
            if len(result.artifacts) > 5:
                print(f"  ... and {len(result.artifacts) - 5} more files.")
        return 0
    except Exception as exc:
        sys.stderr.write(f"[-] Inspection failed: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())

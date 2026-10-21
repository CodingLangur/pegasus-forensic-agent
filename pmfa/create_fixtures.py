"""Synthetic iOS Backup Fixture Generator for PMFA.

Builds realistic mock iOS device backup directories conforming to Apple iOS
backup structures:
1. Valid SQLite 3 databases:
   - clean_backup/Library/SMS/sms.db (message & chat tables with benign records)
   - infected_backup/Library/Caches/com.apple.WebKit.Networking/network_cache.db (cfurl_cache_response table with Pegasus C2 URL)
2. Property Lists:
   - XML plists (Info.plist, Manifest.plist, Status.plist, crashreporter.plist)
   - Binary plists (bplist00 format for MobileSafari preferences and stage2 injection plist)
3. Known IoC binaries, extensions, and hash trigger files
"""

import argparse
from pathlib import Path
import plistlib
import sqlite3
import sys
from typing import Union


def create_clean_backup_fixtures(target_dir: Union[str, Path]) -> Path:
    """Generates a realistic benign iOS device backup directory."""
    root = Path(target_dir)
    root.mkdir(parents=True, exist_ok=True)

    # 1. Standard Root plists (XML format)
    info_data = {
        "DeviceName": "iPhone (Research Baseline)",
        "ProductType": "iPhone14,2",
        "ProductVersion": "16.5",
        "SerialNumber": "F2LW80XXXXXX",
        "TargetType": "Device",
        "UniqueDeviceID": "00008101-00123456789ABCDE",
    }
    (root / "Info.plist").write_bytes(plistlib.dumps(info_data, fmt=plistlib.FMT_XML))

    manifest_data = {
        "BackupKeyBag": b"MOCK_KEYBAG_BLOB_0123456789",
        "IsEncrypted": False,
        "Version": "3.3",
    }
    (root / "Manifest.plist").write_bytes(plistlib.dumps(manifest_data, fmt=plistlib.FMT_XML))

    status_data = {
        "BackupState": "completed",
        "Date": "2026-10-21T06:00:00Z",
        "IsFullBackup": True,
        "Version": "2.4",
    }
    (root / "Status.plist").write_bytes(plistlib.dumps(status_data, fmt=plistlib.FMT_XML))

    # 2. Preferences (Binary Plist & XML)
    prefs_dir = root / "Library" / "Preferences"
    prefs_dir.mkdir(parents=True, exist_ok=True)

    # com.apple.Preferences.plist (XML)
    sys_prefs = {"AppleLanguages": ["en-US"], "AppleLocale": "en_US"}
    (prefs_dir / "com.apple.Preferences.plist").write_bytes(
        plistlib.dumps(sys_prefs, fmt=plistlib.FMT_XML)
    )

    # com.apple.mobilesafari.plist (Binary plist bplist00)
    safari_prefs = {
        "AutoFillPasswords": True,
        "SearchProviderIdentifier": "com.duckduckgo",
        "OpenLinksInBackground": True,
        "WebKitJavaScriptEnabled": True,
        "HistoryStorageVersion": 2,
    }
    (prefs_dir / "com.apple.mobilesafari.plist").write_bytes(
        plistlib.dumps(safari_prefs, fmt=plistlib.FMT_BINARY)
    )

    # 3. SMS Database (Genuine SQLite 3 database)
    sms_dir = root / "Library" / "SMS"
    sms_dir.mkdir(parents=True, exist_ok=True)
    sms_db = sms_dir / "sms.db"
    if sms_db.exists():
        sms_db.unlink()

    conn = sqlite3.connect(sms_db)
    conn.execute("""
        CREATE TABLE message (
            ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
            guid TEXT UNIQUE,
            text TEXT,
            handle_id INTEGER,
            date INTEGER,
            is_from_me INTEGER
        );
    """)
    conn.execute("""
        CREATE TABLE chat (
            ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
            guid TEXT UNIQUE,
            chat_identifier TEXT
        );
    """)
    conn.execute(
        "INSERT INTO message (guid, text, handle_id, date, is_from_me) VALUES (?, ?, ?, ?, ?);",
        ("sms:10001", "Team meeting scheduled for 10:00 AM tomorrow.", 1, 1700000000, 0),
    )
    conn.execute(
        "INSERT INTO message (guid, text, handle_id, date, is_from_me) VALUES (?, ?, ?, ?, ?);",
        ("sms:10002", "Confirmed. Presentation slides are uploaded.", 1, 1700000060, 1),
    )
    conn.commit()
    conn.close()

    return root


def create_infected_backup_fixtures(target_dir: Union[str, Path]) -> Path:
    """Generates a realistic infected iOS backup containing Pegasus IoC vectors."""
    root = Path(target_dir)
    root.mkdir(parents=True, exist_ok=True)

    # 1. Standard Root plists
    info_data = {
        "DeviceName": "Infected iPhone (Target Asset)",
        "ProductType": "iPhone13,3",
        "ProductVersion": "14.6",
        "UniqueDeviceID": "00008030-00192837465ABCD0",
    }
    (root / "Info.plist").write_bytes(plistlib.dumps(info_data, fmt=plistlib.FMT_XML))

    manifest_data = {
        "BackupKeyBag": b"MOCK_KEYBAG_BLOB_INFECTED",
        "IsEncrypted": False,
        "Version": "3.3",
    }
    (root / "Manifest.plist").write_bytes(plistlib.dumps(manifest_data, fmt=plistlib.FMT_XML))

    # 2. Vector 1: Zero-byte SHA-256 trigger binary (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
    (root / "zero_trigger.bin").write_bytes(b"")

    # 3. Vector 2a: Malicious filenames & injected extensions
    ext_dir = root / "System" / "Library" / "Extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)
    # Mach-O header simulation for com.apple.coretelephony.ext
    mach_o_stub = (
        b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00"
        b"\x04\x00\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
        + b"\x90" * 1480
    )
    (ext_dir / "com.apple.coretelephony.ext").write_bytes(mach_o_stub)

    lib_dir = root / "usr" / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    dylib_stub = (
        b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00"
        + b"\xcc" * 1876
    )
    (lib_dir / "libagent_payload.dylib").write_bytes(dylib_stub)

    # 4. Vector 2b: Suspicious injection paths
    tmp_dir = root / "private" / "var" / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    crash_data = {
        "Stage": "InjectedCrashReporter",
        "PayloadStatus": "PERSISTED",
        "Daemon": "com.apple.crashreporter.extension",
    }
    (tmp_dir / "com.apple.crashreporter.plist").write_bytes(
        plistlib.dumps(crash_data, fmt=plistlib.FMT_XML)
    )

    # Binary plist persistence artifact
    pref_dir = root / "Library" / "Preferences"
    pref_dir.mkdir(parents=True, exist_ok=True)
    stage2_data = {
        "Payload": "PegasusStage2Config",
        "Stage": "stage2_loader",
        "InjectionTarget": "com.apple.coretelephony.ext",
    }
    (pref_dir / "com.nso.stage2.plist").write_bytes(
        plistlib.dumps(stage2_data, fmt=plistlib.FMT_BINARY)
    )

    # 5. Vector 3: Genuine WebKit Networking SQLite Cache Database
    cache_dir = root / "Library" / "Caches" / "com.apple.WebKit.Networking"
    cache_dir.mkdir(parents=True, exist_ok=True)
    net_cache_db = cache_dir / "network_cache.db"
    if net_cache_db.exists():
        net_cache_db.unlink()

    conn = sqlite3.connect(net_cache_db)
    conn.execute("""
        CREATE TABLE cfurl_cache_response (
            entry_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER,
            request_key TEXT,
            time_stamp REAL
        );
    """)
    conn.execute("""
        CREATE TABLE cfurl_cache_receiver_data (
            entry_ID INTEGER PRIMARY KEY,
            receiver_data BLOB
        );
    """)
    # Inject Pegasus C2 domain URL in cfurl_cache_response
    conn.execute(
        "INSERT INTO cfurl_cache_response (version, request_key, time_stamp) VALUES (?, ?, ?);",
        (1, "POST https://cloud-services-sync.net/api/v1/sync HTTP/1.1", 1700000000.0),
    )
    conn.execute(
        "INSERT INTO cfurl_cache_receiver_data (entry_ID, receiver_data) VALUES (?, ?);",
        (1, b"\x00\x01TELEMETRY_ACK\x02\x03"),
    )
    # Benign background requests
    conn.execute(
        "INSERT INTO cfurl_cache_response (version, request_key, time_stamp) VALUES (?, ?, ?);",
        (1, "GET https://configuration.apple.com/ios/14.6/update.plist", 1700000010.0),
    )
    conn.commit()
    conn.close()

    return root


def generate_all_fixtures(base_dir: Union[str, Path] = "test_fixtures") -> None:
    """Builds both clean and infected synthetic iOS backup directories."""
    base = Path(base_dir)
    create_clean_backup_fixtures(base / "clean_backup")
    create_infected_backup_fixtures(base / "infected_backup")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synthetic iOS Backup Fixture Generator for PMFA.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dir",
        default="test_fixtures",
        help="Target base directory where mock iOS backups will be generated",
    )
    args = parser.parse_args()
    base_dir = Path(args.dir)
    print(f"[*] Generating synthetic iOS backup fixtures in: {base_dir}")
    generate_all_fixtures(base_dir)
    print(f"[+] Clean backup generated at   : {base_dir / 'clean_backup'}")
    print(f"[+] Infected backup generated at: {base_dir / 'infected_backup'}")


if __name__ == "__main__":
    main()

"""Unit and integration tests for PMFA Forensic Parsers (SQLite & Property Lists).

Validates:
1. Plist deep inspection across XML and binary plists (bplist00)
2. SQLite read-only connection, query parameterization, and table/column extraction
3. Error handling and fallback behavior on corrupt or stub artifacts
"""

from pathlib import Path
import plistlib
import sqlite3
import tempfile
import unittest

from pmfa.parsers import (
    PlistMatch,
    SQLiteMatch,
    inspect_plist_file,
    inspect_sqlite_database,
    is_sqlite_database,
    scan_raw_bytes_for_domains,
)


class TestPlistParser(unittest.TestCase):
    """Tests XML and binary property list deep inspection."""

    def test_xml_plist_domain_and_bundle_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            plist_file = Path(tmp_dir) / "com.malicious.test.plist"
            data = {
                "CFBundleIdentifier": "com.nso.stage2.payload",
                "ServerConfig": {
                    "C2Url": "https://cloud-services-sync.net/api/v1",
                    "Port": 443,
                },
                "LaunchItems": [
                    "/System/Library/clean.bin",
                    "/private/var/tmp/com.apple.crashreporter.plist",
                ],
            }
            with open(plist_file, "wb") as f:
                plistlib.dump(data, f, fmt=plistlib.FMT_XML)

            matches = inspect_plist_file(
                file_path=plist_file,
                suspicious_domains={"cloud-services-sync.net"},
                suspicious_filenames={"com.nso.stage2.payload"},
                suspicious_paths={"/private/var/tmp/com.apple.crashreporter.plist"},
            )

            self.assertEqual(len(matches), 3)
            match_types = {m.indicator_type for m in matches}
            self.assertIn("NETWORK_DOMAIN", match_types)
            self.assertIn("SUSPICIOUS_FILENAME", match_types)
            self.assertIn("SUSPICIOUS_PATH", match_types)

            domain_match = next(m for m in matches if m.indicator_type == "NETWORK_DOMAIN")
            self.assertEqual(domain_match.matched_value, "cloud-services-sync.net")
            self.assertIn("ServerConfig/C2Url", domain_match.key_path)

    def test_binary_plist_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            plist_file = Path(tmp_dir) / "binary_preferences.plist"
            data = {
                "Preferences": {
                    "TelemetrySink": "apple-telemetry-server.com",
                }
            }
            with open(plist_file, "wb") as f:
                plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)

            matches = inspect_plist_file(
                file_path=plist_file,
                suspicious_domains={"apple-telemetry-server.com"},
            )

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].matched_value, "apple-telemetry-server.com")
            self.assertIn("Preferences/TelemetrySink", matches[0].key_path)

    def test_corrupted_plist_graceful_handling(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_file = Path(tmp_dir) / "corrupt.plist"
            bad_file.write_bytes(b"NOT A REAL PLIST CONTENT <<<<????")

            matches = inspect_plist_file(
                file_path=bad_file,
                suspicious_domains={"apple-telemetry-server.com"},
            )
            self.assertEqual(matches, [])


class TestSQLiteParser(unittest.TestCase):
    """Tests SQLite database read-only querying and table record extraction."""

    def test_is_sqlite_database_header_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            valid_db = Path(tmp_dir) / "valid.db"
            conn = sqlite3.connect(valid_db)
            conn.execute("CREATE TABLE test (id INT);")
            conn.close()

            self.assertTrue(is_sqlite_database(valid_db))

            non_db = Path(tmp_dir) / "invalid.txt"
            non_db.write_text("Hello World")
            self.assertFalse(is_sqlite_database(non_db))

    def test_sqlite_query_finds_c2_domain_records(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "cfurl_cache_response.db"
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE cfurl_cache_response (
                    id INTEGER PRIMARY KEY,
                    request_key TEXT,
                    time_stamp REAL
                );
            """)
            conn.execute(
                "INSERT INTO cfurl_cache_response (request_key, time_stamp) VALUES (?, ?);",
                ("https://cloud-services-sync.net/auth/token", 1700000000.0),
            )
            conn.execute(
                "INSERT INTO cfurl_cache_response (request_key, time_stamp) VALUES (?, ?);",
                ("https://apple.com/valid/service", 1700000001.0),
            )
            conn.commit()
            conn.close()

            matches = inspect_sqlite_database(
                file_path=db_path,
                suspicious_domains={"cloud-services-sync.net"},
            )

            self.assertEqual(len(matches), 1)
            match = matches[0]
            self.assertEqual(match.indicator_type, "NETWORK_DOMAIN")
            self.assertEqual(match.matched_value, "cloud-services-sync.net")
            self.assertEqual(match.table_name, "cfurl_cache_response")
            self.assertEqual(match.column_name, "request_key")
            self.assertEqual(match.row_id, 1)

    def test_corrupt_sqlite_file_handles_exception_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            stub_file = Path(tmp_dir) / "stub_cache.db"
            # Fake header followed by non-sqlite data
            stub_file.write_bytes(b"SQLite format 3\x00corrupted garbage data")

            matches = inspect_sqlite_database(
                file_path=stub_file,
                suspicious_domains={"cloud-services-sync.net"},
            )
            self.assertEqual(matches, [])


class TestRawByteFallbackScanner(unittest.TestCase):
    """Tests byte offset search on binary files."""

    def test_raw_byte_search_returns_offset(self):
        content = b"PREAMBLE\x00\x01\x02POST https://cloud-services-sync.net/api HTTP/1.1"
        matches = scan_raw_bytes_for_domains(content, {"cloud-services-sync.net"})

        self.assertEqual(len(matches), 1)
        domain, offset = matches[0]
        self.assertEqual(domain, "cloud-services-sync.net")
        self.assertEqual(offset, content.find(b"cloud-services-sync.net"))


if __name__ == "__main__":
    unittest.main()

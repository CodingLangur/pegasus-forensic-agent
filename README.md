# Pegasus Mobile Forensic Agent (PMFA)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)

The **Pegasus Mobile Forensic Agent (PMFA)** is an autonomous forensic scanning and evidence analysis agent designed to detect Indicators of Compromise (IoCs) associated with zero-click mobile spyware like Pegasus.

Because zero-click mobile compromises bypass transit encryption (E2EE) directly at the operating system layer, PMFA performs post-infection forensic triage across mobile device backups, filesystem dumps, and extracted application databases.

```
+-----------------------------------------------------------------------------------+  
|                            PEGASUS FORENSIC AGENT (PMFA)                          |  
|                                                                                   |  
|  +--------------------+      +--------------------+      +---------------------+  |  
|  |  Feed Verification | ---> |  Forensic Scanner  | ---> | Evidence Packaging  |  |  
|  |    (Ed25519)       |      |     (SHA-256)      |      |    (AES-256-GCM)    |  |  
|  +--------------------+      +--------------------+      +---------------------+  |  
|            ^                           ^                            |             |  
|            |                           |                            v             |  
|    [iocs.json + sig]            [Target Backup]             [report.enc + key]    |  
+-----------------------------------------------------------------------------------+
```

---

## Core Architectural Components

### 1. Threat Feed Ingestion & Cryptographic Verification (`pmfa/feed_verifier.py`, `pmfa/crypto/signatures.py`)
* **Primitives**: **Ed25519** (RFC 8032) and **RSA-PSS** (2048/4096-bit with SHA-256 and PSS padding).
* **Function**: Ingests threat intelligence indicators (`iocs.json`) alongside detached signatures (`iocs.json.sig`), validating them against the trusted vendor public key (`vendor_public.pem`).
* **Security Control**: Aborts execution immediately (`exit code 2: E_INTEGRITY_FAIL`) if adversary poisoning or signature tampering is detected.

### 2. Forensic Inspection & Hashing Engine (`pmfa/scanner.py`, `pmfa/crypto/hashing.py`)
* **Primitive**: Streaming **SHA-256** (chunk-based block hashing).
* **Function**: Recursively traverses device backups and filesystem dumps, fingerprinting all target binaries, plists, logs, and SQLite databases.
* **Metadata Extraction**: Captures POSIX timestamps (`mtime`, `ctime`), permissions (octal and symbolic), file sizes, and structural file classifications.
* **Performance**: Features a multi-threaded `ThreadPoolExecutor` worker pool for high-throughput block hashing.

### 3. Agent Logic & IoC Matching Engine (`pmfa/matcher.py`, `pmfa/parsers.py`)
* **Function**: Correlates discovered artifacts against verified IoC definitions using three distinct match vectors:
  1. **Cryptographic Hashes**: Exact SHA-256 match against known malicious loader/payload binaries.
  2. **Anomalous Process & Path Names**: Exact and regex evaluation of malicious binaries (`com.apple.coretelephony.ext`, `libagent_payload.dylib`) and injection paths (`/private/var/tmp/`, `/Library/Preferences/com.nso.*`).
  3. **Deep Network / Domain Artifact Parsing**: Structured read-only SQLite inspection (`cfurl_cache_response`, database tables) and recursive Property List (`.plist`) traversal to discover C2 domains (e.g. `cloud-services-sync.net`), with byte offset fallback.
* **Triage Scoring**: Marks findings with severity levels (`CRITICAL`, `HIGH`), extracts remediation advice, and compiles pre-encryption JSON triage reports.

### 4. Evidence Packaging & Cryptographic Sealing (`pmfa/sealer.py`, `pmfa/crypto/cipher.py`)
* **Primitive**: **AES-256-GCM** (Galois/Counter Mode).
* **Parameters**: 256-bit symmetric key, 96-bit unique CSPRNG initialization vector ($IV$), and 128-bit authentication tag ($T$).
* **Format**: $IV \parallel \text{Ciphertext} \parallel T$.
* **Key Wrapping (Key Encapsulation)**:
  * **RSA-OAEP (SHA-256)**: Encrypts the ephemeral AES key directly under an investigator's RSA public key.
  * **Passphrase KDF**: Derives a 256-bit Key Encryption Key (KEK) using PBKDF2-HMAC-SHA256 (100,000 rounds).
  * **Plaintext Ephemeral Key**: Fallback option for demo and pipeline automation (`output/report.key`).
* **Function**: Seals the forensic triage report to guarantee strict chain of custody, non-repudiation, and data confidentiality (`output/report.enc`).

---

## File System Structure

```text
.
├── LICENSE
├── README.md
├── DEMO_GUIDE.md              # 2-3 minute presentation speaker script & benchmark reference
├── run_demo.sh                # Executable demo launcher for seminar presentations
├── pyproject.toml             # PEP 517 build configuration & CLI console entry points
├── requirements.txt           # Package requirements
├── pmfa/
│   ├── __init__.py
│   ├── agent.py               # Main CLI orchestrator & agent state machine
│   ├── feed_verifier.py       # Threat feed ingestion & Ed25519 / RSA-PSS verification
│   ├── scanner.py             # Multi-threaded forensic inspection engine
│   ├── matcher.py             # Multi-vector IoC matching & triage engine
│   ├── parsers.py             # SQLite and Property List (.plist) deep forensic parsers
│   ├── sealer.py              # AES-256-GCM evidence packaging & key wrapping
│   ├── create_fixtures.py     # Deterministic synthetic iOS backup fixture generator
│   ├── demo.py                # Seminar presentation demo orchestrator (Design Doc §7)
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── signatures.py      # Ed25519 & RSA-PSS digital signature verification
│   │   ├── hashing.py         # Streaming SHA-256 file hashing
│   │   └── cipher.py          # AES-256-GCM AEAD & RSA-OAEP / Passphrase key wrapping
│   ├── feeds/
│   │   ├── iocs.json          # Threat intelligence indicators (exact & regex patterns)
│   │   └── iocs.json.sig      # Detached digital signature
│   └── keys/
│       ├── vendor_public.pem  # Vendor public key for feed verification
│       └── vendor_private.pem # Vendor private key for feed signing
├── test_fixtures/
│   ├── clean_backup/          # Genuine SQLite & binary plist benign backup
│   └── infected_backup/       # Backup with Pegasus IoCs (Mach-O stubs, C2 SQLite cache, bplist00)
├── tests/
│   ├── __init__.py
│   ├── test_feed_verification.py
│   ├── test_scanner.py
│   ├── test_matcher.py
│   ├── test_parsers.py
│   ├── test_sealer.py
│   ├── test_agent.py
│   └── test_demo_workflow.py
└── output/                    # Sealed evidence reports & ephemeral/wrapped keys
    └── .gitkeep
```

---

## Installation & Prerequisites

Requires Python 3.9+ and the `cryptography` library:

```bash
pip install cryptography
```

---

## Usage Guide & Demo Workflow

### 1. Run Complete End-to-End Forensic Scan

**Clean Device Baseline Scan:**
```bash
python -m pmfa.agent --target test_fixtures/clean_backup
```
*Output: Green terminal summary showing 100% Clean | 0 IoC Matches, and report sealed to `output/report.enc`.*

**Infected Device Scan:**
```bash
python -m pmfa.agent --target test_fixtures/infected_backup
```
*Output: Highlights detected IoCs across SHA-256 hash, suspicious path, filename, and domain vectors, and seals evidence to `output/report.enc`.*

---

### 2. Standalone Threat Feed Verification & Tamper Check

```bash
# Verify feed against vendor public key
python -m pmfa.feed_verifier

# Simulate adversary tampering (alters 1 byte of the feed)
python -m pmfa.feed_verifier --tamper
# Exits with status code 2 (E_INTEGRITY_FAIL)
```

---

### 3. Evidence Inspection & Key Unwrapping

```bash
# View non-printable binary ciphertext (first 64 bytes)
hexdump -C -n 64 output/report.enc

# Mode A: Standard ephemeral key decryption
python -m pmfa.agent --decrypt-report output/report.enc --key output/report.key

# Mode B: Asymmetric unwrap with analyst RSA private key
python -m pmfa.agent --decrypt-report output/report.enc --key output/report.key --analyst-privkey analyst_private.pem

# Mode C: Passphrase KEK unwrap
python -m pmfa.agent --decrypt-report output/report.enc --key output/report.key --passphrase "MyPassphrase"

# Verify evidence tamper detection (AEAD tag rejection on corrupted ciphertext)
python -m pmfa.sealer --tamper-check
```

---

## Test Fixture Generation

PMFA includes a deterministic synthetic backup fixture generator that constructs realistic mock iOS device backups conforming to iOS file layout standards:
- **Clean Backup** (`test_fixtures/clean_backup`): Valid `bplist00` binary plists (`com.apple.mobilesafari.plist`), XML plists, and a valid SQLite 3 database (`Library/SMS/sms.db`).
- **Infected Backup** (`test_fixtures/infected_backup`): Valid binary plist (`com.nso.stage2.plist`), zero-byte trigger (`zero_trigger.bin`), Mach-O header stubs (`com.apple.coretelephony.ext`, `libagent_payload.dylib`), XML persistence plists, and a genuine WebKit SQLite networking cache (`Library/Caches/com.apple.WebKit.Networking/network_cache.db`) housing Pegasus C2 URLs.

To regenerate fixtures at any time:
```bash
# Using the installed CLI entry point
pmfa-fixtures

# Or directly via Python module
python -m pmfa.create_fixtures
```

---

## Seminar Presentation Demo (Design Doc §7)

PMFA includes an interactive course presentation demo runner that implements the complete 2-3 minute presentation workflow from Design Doc Section 7:
1. **Threat Feed Tamper Check**: Validates Ed25519 signature and tests 1-byte adversary feed poisoning (immediate exit code `2: E_INTEGRITY_FAIL` abort).
2. **Clean Baseline Scan**: Scans mock iOS backup proving 100% clean baseline and 0 false positives.
3. **Infected Artifact Detection**: Demonstrates multi-vector Pegasus detection (SHA-256 match, malicious extension Mach-O stubs, `/private/var/tmp/` persistence, and WebKit SQLite cache C2 domain extraction).
4. **Sealed Evidence Inspection**: Inspects raw AES-256-GCM binary ciphertext and demonstrates authenticated decryption with ephemeral key unwrapping.
5. **Cryptographic Tamper Rejection**: Flips 1 bit in ciphertext proving AEAD authentication tag verification failure.
6. **Live Performance Benchmarks**: Measures Ed25519 verification, SHA-256 throughput (>200 MB/s), and AES-GCM speeds.

See [DEMO_GUIDE.md](file:///home/trinath/Desktop/temp/transfertousb/CNS_Case_Study/DEMO_GUIDE.md) for the complete slide-by-slide speaker script.

To launch the demo:
```bash
# Interactive mode (press Enter to advance through presentation phases)
./run_demo.sh

# Or via installed console script
pmfa-demo

# Automated non-interactive mode
./run_demo.sh --auto --delay 1.0
```

---

## Running the Automated Test Suite

PMFA includes 84 comprehensive unit and integration tests covering all cryptographic modules, parsers, scanners, matcher vectors, sealer modes, state machine transitions, and demo workflows:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## License

This project is licensed under the [MIT License](LICENSE).

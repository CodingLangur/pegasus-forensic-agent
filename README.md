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

### 1. Threat Feed Ingestion & Cryptographic Verification (`pmfa/feed_verifier.py`)
* **Primitive**: **Ed25519** digital signatures (RFC 8032).
* **Function**: Ingests threat intelligence indicators (`iocs.json`) alongside detached signatures (`iocs.json.sig`), validating them against the trusted vendor public key (`vendor_public.pem`).
* **Security Control**: Aborts execution immediately (`exit code 2: E_INTEGRITY_FAIL`) if adversary poisoning or signature tampering is detected.

### 2. Forensic Inspection & Hashing Engine (`pmfa/scanner.py`, `pmfa/crypto/hashing.py`)
* **Primitive**: Streaming **SHA-256** (chunk-based block hashing).
* **Function**: Recursively traverses device backups and filesystem dumps, fingerprinting all target binaries, plists, logs, and SQLite databases.
* **Metadata Extraction**: Captures POSIX timestamps (`mtime`, `ctime`), permissions (octal and symbolic), file sizes, and structural file classifications.
* **Performance**: Features a multi-threaded `ThreadPoolExecutor` worker pool for high-throughput block hashing.

### 3. Agent Logic & IoC Matching Engine (`pmfa/matcher.py`)
* **Function**: Correlates discovered artifacts against verified IoC definitions using three distinct match vectors:
  1. **Cryptographic Hashes**: Exact SHA-256 match against known malicious loader/payload binaries.
  2. **Anomalous Process & Path Names**: Exact/regex detection of malicious binaries (`com.apple.coretelephony.ext`, `libagent_payload.dylib`) and anomalous injection paths (`/private/var/tmp/`, `/Library/Preferences/com.nso.*`).
  3. **Network / Domain Indicators**: Deep byte search in SQLite network caches and preferences for C2 domains (e.g. `cloud-services-sync.net`), recording exact byte offsets.
* **Triage Scoring**: Marks findings with severity levels (`CRITICAL`, `HIGH`), extracts remediation advice, and compiles pre-encryption JSON triage reports.

### 4. Evidence Packaging & Cryptographic Sealing (`pmfa/sealer.py`, `pmfa/crypto/cipher.py`)
* **Primitive**: **AES-256-GCM** (Galois/Counter Mode).
* **Parameters**: 256-bit symmetric key, 96-bit unique CSPRNG initialization vector ($IV$), and 128-bit authentication tag ($T$).
* **Format**: $IV \parallel \text{Ciphertext} \parallel T$.
* **Function**: Seals the forensic triage report to guarantee strict chain of custody, non-repudiation, and data confidentiality (`output/report.enc` and `output/report.key`).

---

## File System Structure

```text
.
├── LICENSE
├── README.md
├── pmfa/
│   ├── __init__.py
│   ├── agent.py               # Main CLI orchestrator & agent state machine
│   ├── feed_verifier.py       # Threat feed ingestion & Ed25519 verification
│   ├── scanner.py             # Multi-threaded forensic inspection engine
│   ├── matcher.py             # Multi-vector IoC matching & triage engine
│   ├── sealer.py              # AES-256-GCM evidence packaging & sealing
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── signatures.py      # Ed25519 signature generation & verification
│   │   ├── hashing.py         # Streaming SHA-256 file hashing
│   │   └── cipher.py          # AES-256-GCM authenticated encryption routines
│   ├── feeds/
│   │   ├── iocs.json          # Threat intelligence indicators
│   │   └── iocs.json.sig      # Detached digital signature
│   └── keys/
│       ├── vendor_public.pem  # Vendor public key for feed verification
│       └── vendor_private.pem # Vendor private key for feed signing
├── test_fixtures/
│   ├── clean_backup/          # Mock benign device backup
│   └── infected_backup/       # Mock backup containing Pegasus IoC vectors
├── tests/
│   ├── __init__.py
│   ├── test_feed_verification.py
│   ├── test_scanner.py
│   ├── test_matcher.py
│   └── test_sealer.py
└── output/                    # Sealed evidence reports & ephemeral keys
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

### 3. Evidence Inspection & Decryption

```bash
# View non-printable binary ciphertext (first 64 bytes)
hexdump -C -n 64 output/report.enc

# Authenticate AEAD tag and decrypt evidence findings
python -m pmfa.sealer --decrypt-report output/report.enc --key output/report.key

# Verify evidence tamper detection (rejection on corrupted ciphertext)
python -m pmfa.sealer --tamper-check
```

---

## Running the Automated Test Suite

PMFA includes 45 comprehensive unit and integration tests covering all four core components:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## License

This project is licensed under the [MIT License](LICENSE).

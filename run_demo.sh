#!/usr/bin/env bash
# ==============================================================================
# Pegasus Mobile Forensic Agent (PMFA) - Seminar Presentation Demo Runner
# Implements Design Doc Section 7: Verification & Seminar Demo Plan (2-3 Minutes)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Ensure Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is required to run the PMFA demo." >&2
    exit 1
fi

# Run the Python demo orchestrator passing any user flags (e.g. --auto, --delay 0)
python3 -m pmfa.demo "$@"

#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d .venv ]; then
    echo "=== max-reverse ==="
    echo "creating venv..."
    python3.13 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi

exec .venv/bin/python sniffer.py "$@"

#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$0")/e2e-ied-gcs-candidate.py" "$@"

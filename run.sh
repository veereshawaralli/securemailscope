#!/usr/bin/env bash
# SecureMailScope launcher (Linux/macOS/Git Bash).
#
#   ./run.sh                 # bootstrap venv + run the zero-credential demo
#   ./run.sh dashboard       # forward any subcommand to the CLI
#   ./run.sh analyze x.pcap --out-dir out
#
# Set SMS_NO_VENV=1 to use the current environment instead of a local .venv.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python

if [ "${SMS_NO_VENV:-0}" != "1" ]; then
  if [ ! -d .venv ]; then
    echo "[run] creating virtualenv in .venv ..."
    "$PYTHON" -m venv .venv
  fi
  # shellcheck disable=SC1091
  if [ -f .venv/bin/activate ]; then . .venv/bin/activate
  else . .venv/Scripts/activate; fi   # Git Bash on Windows
  PYTHON=python
fi

# Install the package (with all extras) once; core install still runs the demo
# even if the optional extras cannot be fetched offline.
if ! "$PYTHON" -c "import securemailscope" >/dev/null 2>&1; then
  echo "[run] installing SecureMailScope ..."
  "$PYTHON" -m pip install --upgrade pip >/dev/null
  "$PYTHON" -m pip install -e ".[all]" || "$PYTHON" -m pip install -e .
fi

if [ "$#" -eq 0 ]; then
  set -- demo
fi
echo "[run] securemailscope $*"
exec "$PYTHON" -m securemailscope "$@"

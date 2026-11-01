#!/usr/bin/env bash
# Run from any directory; all generated files stay in this checkout.
set -euo pipefail
cd "$(dirname "$0")"

notebooks=true
if [[ "${1:-}" == "--notebooks" ]]; then
  notebooks=true
  shift
fi

if [[ "${1:-}" == "--duckdb-ui" ]]; then
  notebooks=false
  shift
fi
if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: ./setup.sh [--notebooks] [JupyterLab options]"
  echo "       ./setup.sh --duckdb-ui [--prepare-only] [--port 4213]"
  echo "Default: install dependencies and open notebooks/00_Start_here.ipynb in JupyterLab."
  exit 0
fi

python_bin="${WORKSHOP_PYTHON:-python3}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "Python 3.10+ is required. Install it from https://www.python.org/downloads/ and rerun ./setup.sh." >&2
  exit 1
fi
"$python_bin" -c 'import sys; sys.exit("Python 3.10+ is required.") if sys.version_info < (3, 10) else None'

# Native SQL workshop uses an existing CLI directly, avoiding unnecessary pip downloads.
if [[ "$notebooks" == false ]] && { command -v duckdb >/dev/null 2>&1 || [[ -n "${WORKSHOP_DUCKDB:-}" ]]; }; then
  exec "$python_bin" -m workshop.launch "$@"
fi

install_packages() {
  if .workshop-venv/bin/python -m pip install --disable-pip-version-check --retries 1 --timeout 15 "$@"; then
    return 0
  fi
  .workshop-venv/bin/python - <<'PY'
import ipaddress
import socket
import sys

print("\nPackage installation failed; workshop setup has not completed.", file=sys.stderr)
try:
    addresses = {r[4][0] for r in socket.getaddrinfo("pypi.org", 443, type=socket.SOCK_STREAM)}
except OSError:
    addresses = set()
if addresses and all(ipaddress.ip_address(a).is_loopback for a in addresses):
    print("pypi.org resolves to localhost on this machine. Check /etc/hosts or managed DNS settings.", file=sys.stderr)
    print("Use your organization's approved package mirror, or ask your administrator for PyPI access.", file=sys.stderr)
else:
    print("Check internet access, your approved package index, and proxy settings, then rerun setup.", file=sys.stderr)
PY
  return 1
}

if [[ ! -x .workshop-venv/bin/python ]]; then
  echo "Creating the workshop Python environment..."
  "$python_bin" -m venv .workshop-venv
fi
if ! .workshop-venv/bin/python -c 'import duckdb; assert duckdb.__version__ == "2.0.0"' >/dev/null 2>&1; then
  echo "Installing DuckDB 2.0.0..."
  install_packages 'duckdb==2.0.0'
fi
if [[ "$notebooks" == true ]]; then
  if ! .workshop-venv/bin/python -c 'import pandas, itables, jupyterlab, ipykernel, nbformat, nbclient' >/dev/null 2>&1; then
    echo "Installing tutorial notebook dependencies..."
    install_packages -r requirements-notebooks.txt
  fi
  .workshop-venv/bin/python -m ipykernel install --sys-prefix --name python3 --display-name "Python 3 (workshop)"
  echo "Opening JupyterLab at notebook 00. Keep this terminal open."
  exec .workshop-venv/bin/python -m jupyterlab --notebook-dir="$PWD" --ServerApp.default_url=/lab/tree/notebooks/00_Start_here.ipynb "$@"
fi
exec .workshop-venv/bin/python -m workshop.ui "$@"

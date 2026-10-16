#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if ! command -v python3 >/dev/null 2>&1; then echo "Python 3 is required." >&2; exit 1; fi
if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: ./install.sh [--dns]"
  echo "Core launcher installation is local-only. --dns installs optional dnspython in a project venv."
  exit 0
fi
if [[ "${1:-}" == "--dns" ]]; then
  python3 -m venv .venv
  "$ROOT/.venv/bin/python" -m pip install -e '.[dns]'
fi
USER_BIN="$HOME/.local/bin"
mkdir -p "$USER_BIN"
WRAPPER="$USER_BIN/noxtrace"
if [[ -e "$WRAPPER" ]] && ! grep -q 'NOXTRACE_ROOT' "$WRAPPER" 2>/dev/null; then
  printf 'Not replacing existing %s. Use %s/noxtrace instead.\n' "$WRAPPER" "$ROOT"
else
  {
    printf '#!/usr/bin/env bash\nROOT=%q\n' "$ROOT"
    cat <<'EOF_WRAPPER'
export NOXTRACE_ROOT="$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  exec "$ROOT/.venv/bin/python" -m noxtrace "$@"
fi
exec python3 -m noxtrace "$@"
EOF_WRAPPER
  } > "$WRAPPER"
  chmod +x "$WRAPPER"
  printf '\nInstalled launcher: %s\n' "$WRAPPER"
fi
printf 'Project-local launcher: %s/noxtrace\n' "$ROOT"
if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
  printf 'Add this to ~/.zshrc to use `noxtrace` anywhere: export PATH="%s:$PATH"\n' "$USER_BIN"
else
  printf 'You can now run `noxtrace` by name from any directory.\n'
fi
printf 'Optional richer DNS records: ./install.sh --dns\n'

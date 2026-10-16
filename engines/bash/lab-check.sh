#!/usr/bin/env bash
# Local environment readiness check. Does not scan hosts or change the system.
set -u
BLUE=''; GRAY=''; RESET=''
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then BLUE=$'\033[38;5;75m'; GRAY=$'\033[90m'; RESET=$'\033[0m'; fi
printf '%sNOXTRACE :: local lab readiness%s\n' "$BLUE" "$RESET"
printf '%sThis script only checks local command availability and runtime versions.%s\n\n' "$GRAY" "$RESET"
for cmd in python3 git cc go rustc cargo java javac openssl; do
  if command -v "$cmd" >/dev/null 2>&1; then printf '  [ OK ] %-10s %s\n' "$cmd" "$(command -v "$cmd")";
  else printf '  [ -- ] %-10s not installed (optional engine/tool)\n' "$cmd"; fi
done
printf '\nPython: '; python3 --version 2>&1 || true
printf 'Git: '; git --version 2>&1 || true
printf 'Kernel: '; uname -sr 2>/dev/null || true
printf '\n%sNo packages were installed and no network request was made.%s\n' "$GRAY" "$RESET"

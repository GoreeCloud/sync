#!/bin/sh
# Verify that the native Linux window process survives startup under Xvfb.
# This is not an accessibility, visual-design, or physical-device acceptance test.
set -eu

app="${1:-/tmp/goreecloud-sync}"
if [ ! -x "$app" ]; then
  echo "native executable missing or not executable: $app" >&2
  exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/config"
HOME="$work" XDG_CONFIG_HOME="$work/config" xvfb-run -a -s '-screen 0 1280x800x24' sh -c '
  app="$1"
  log="$2"
  "$app" >"$log" 2>&1 &
  pid=$!
  trap '\''kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true'\'' EXIT
  sleep 5
  status=$(ps -o stat= -p "$pid" 2>/dev/null || true)
  case "$status" in
    ""|Z*)
      echo "Native app terminated before startup smoke interval completed" >&2
      cat "$log" >&2
      exit 1
      ;;
  esac
  echo "Native Linux window stayed alive during the startup smoke interval"
' sh "$app" "$work/app.log"

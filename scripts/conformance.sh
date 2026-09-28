#!/usr/bin/env bash
# ACP conformance profile for a launch description (any ACP stdio CLI).
#
#   scripts/conformance.sh                                   # opencode (pinned), no credentials
#   scripts/conformance.sh conformance/opencode.launch.yaml  # explicit launch file
#   ACP_CONFORMANCE_AUTH_JSON=~/.acp/openai-auth.json scripts/conformance.sh   # LIVE: real key
#
# The CLIs pinned in images/runner/package-lock.json are installed into .cache/clis (npm ci),
# so the profile is recorded against exactly the version the image ships. The report goes to
# conformance/<name>.json; copy its findings into drivers.lock.yaml (profiles).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LAUNCH=${1:-$ROOT/conformance/opencode.launch.yaml}
CLIS="$ROOT/.cache/clis"
if [ ! -f "$CLIS/.lock-sha" ] || [ "$(sha256sum "$ROOT/images/runner/package-lock.json" | cut -d' ' -f1)" != "$(cat "$CLIS/.lock-sha")" ]; then
  rm -rf "$CLIS" && mkdir -p "$CLIS"
  cp "$ROOT/images/runner/package.json" "$ROOT/images/runner/package-lock.json" "$CLIS/"
  (cd "$CLIS" && npm ci --omit=dev --no-audit --no-fund >/dev/null)
  sha256sum "$ROOT/images/runner/package-lock.json" | cut -d' ' -f1 > "$CLIS/.lock-sha"
fi
cargo build -q --manifest-path "$ROOT/Cargo.toml" -p acp-conformance
CMD=$(sed -n 's/^command: *//p' "$LAUNCH" | head -1)
VER=$(PATH="$CLIS/node_modules/.bin:$PATH" HOME=$(mktemp -d) "$CMD" --version 2>/dev/null | tail -1 || echo unknown)
ARGS=(--launch "$LAUNCH" --timeout 90 --grace 15 --path "$CLIS/node_modules/.bin:$(dirname "$(command -v node)"):/usr/local/bin:/usr/bin:/bin")
if [ -n "${ACP_CONFORMANCE_AUTH_JSON:-}" ]; then
  NAME="$(basename "$CMD")-$VER-live"
  ARGS+=(--home-file ".local/share/opencode/auth.json=$ACP_CONFORMANCE_AUTH_JSON"
         --prompt "Reply with the single word ok." --cancel-prompt "Count slowly from 1 to 1000, one number per line.")
  [ -n "${ACP_CONFORMANCE_PROXY:-}" ] && ARGS+=(--https-proxy "$ACP_CONFORMANCE_PROXY")
else
  NAME="$(basename "$CMD")-$VER-noauth"
  ARGS+=(--prompt "Reply with the single word ok.")
fi
"$ROOT/target/debug/acp-conformance" "${ARGS[@]}" --name "$NAME" --out "$ROOT/conformance/$NAME.json" >/dev/null
echo "conformance profile written: conformance/$NAME.json"

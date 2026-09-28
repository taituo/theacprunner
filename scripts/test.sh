#!/usr/bin/env bash
# All deterministic tests (no provider accounts needed).
#
#   scripts/test.sh              unit + integration tests; PostgreSQL-backed tests run when
#                                ACP_TEST_DATABASE_URL is set, Kubernetes e2e when
#                                ACP_E2E_KUBECONFIG is set (scripts/envtest-up.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check || echo "warning: rustfmt differences"
cargo clippy --workspace --all-targets -q -- -D warnings
cargo build -q -p fake-acp-agent -p runnerd -p agentd -p acp-runner-controller -p acp-egress-proxy -p acp-openai-shim
LOG=$(mktemp)
set +e
cargo test --workspace -q 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e
if [ "$rc" -ne 0 ]; then
  # surface the failures as annotations (readable without downloading the job log)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    grep -E "^test .* FAILED$|panicked at|^error|^---- .* stdout ----" "$LOG" | head -30 | while IFS= read -r l; do
      echo "::error title=test failure::${l//::/: :}"
    done
    grep -A6 "panicked at" "$LOG" | head -60 | tr '\n' ' ' | cut -c1-3500 | sed 's/^/::error title=panic detail::/'
  fi
  exit "$rc"
fi
if [ -z "${ACP_TEST_DATABASE_URL:-}" ]; then
  echo "NOTE: ACP_TEST_DATABASE_URL unset — journal/engine/kube e2e tests were skipped (scripts/dev-postgres.sh)"
fi
if [ -z "${ACP_E2E_KUBECONFIG:-}" ]; then
  echo "NOTE: ACP_E2E_KUBECONFIG unset — Kubernetes e2e test was skipped (scripts/envtest-up.sh)"
fi

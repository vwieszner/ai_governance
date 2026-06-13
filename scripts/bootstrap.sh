#!/usr/bin/env bash
# One-shot fresh-machine bring-up for the AGT federated-RAG product (Linux/macOS).
# The bash twin of scripts/bootstrap.ps1 (Windows) — same steps, same idempotency.
#
#   ./scripts/bootstrap.sh                 # alpha + beta (the demo pair)
#   ./scripts/bootstrap.sh --three         # + gamma
#   ./scripts/bootstrap.sh --skip-deps     # infra only (venv/npm already done)
#
# Prereqs: python3.11+, node 18+, a running Docker daemon, and an NVIDIA_API_KEY (or any
# OpenAI-compatible key) in ./.env. Everything else is done here, idempotently.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

THREE=0; SKIP_DEPS=0
for a in "$@"; do
  case "$a" in
    --three) THREE=1 ;;
    --skip-deps) SKIP_DEPS=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

fail() { echo -e "\n[bootstrap] FATAL: $*" >&2; exit 1; }
step() { echo -e "\n=== $* ==="; }

# ── 1. Prerequisites ──────────────────────────────────────────────────────────
step "Checking prerequisites"
PY=""
for c in python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then
    v="$("$c" -c 'import sys;print(sys.version_info[0]*100+sys.version_info[1])')"
    if [ "$v" -ge 311 ]; then PY="$c"; break; fi
  fi
done
[ -n "$PY" ] || fail "Python 3.11+ not found on PATH."
echo "  python : $PY ($("$PY" --version))"

command -v node >/dev/null 2>&1 || fail "Node 18+ not found on PATH."
nodemajor="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
[ "$nodemajor" -ge 18 ] || fail "Node 18+ required, found $(node --version)."
echo "  node   : $(node --version)"

docker info >/dev/null 2>&1 || fail "Docker daemon not reachable. Start Docker and re-run."
echo "  docker : OK"

if ! { [ -f .env ] && grep -qE 'NVIDIA_API_KEY\s*=\s*\S' .env; } && [ -z "${NVIDIA_API_KEY:-}" ]; then
  fail "No LLM key. Put NVIDIA_API_KEY=<key> in $ROOT/.env (any OpenAI-compatible key)."
fi
echo "  LLM key: present"

VENV_PY="$ROOT/.venv/bin/python"

# ── 2. Python venv + pinned deps ──────────────────────────────────────────────
if [ "$SKIP_DEPS" -eq 0 ]; then
  step "Python venv + dependencies (pinned: agt-federated-rag/requirements.lock.txt)"
  [ -x "$VENV_PY" ] || "$PY" -m venv "$ROOT/.venv"
  "$VENV_PY" -m pip install --quiet --upgrade pip
  "$VENV_PY" -m pip install --quiet -r "$ROOT/agt-federated-rag/requirements.lock.txt" \
    || fail "Python dependency install failed."
  echo "  venv ready: $VENV_PY"

  # ── 3. UI deps ──────────────────────────────────────────────────────────────
  step "UI dependencies (npm install)"
  ( cd "$ROOT/ui" && npm install --no-audit --no-fund >/dev/null 2>&1 ) || fail "npm install failed."
  if [ ! -f "$ROOT/ui/.env.prod" ]; then
    cp "$ROOT/ui/.env.example" "$ROOT/ui/.env.prod"
    key="${NVIDIA_API_KEY:-$(grep -E '^NVIDIA_API_KEY=' .env 2>/dev/null | head -1 | cut -d= -f2-)}"
    [ -n "$key" ] && sed -i.bak "s|^NVIDIA_API_KEY=$|NVIDIA_API_KEY=$key|" "$ROOT/ui/.env.prod" && rm -f "$ROOT/ui/.env.prod.bak"
    echo "  created ui/.env.prod from .env.example (gitignored)"
  fi
fi

# ── 4. Onboard divisions (idempotent) ─────────────────────────────────────────
DIVS=(alpha beta); [ "$THREE" -eq 1 ] && DIVS+=(gamma)
for d in "${DIVS[@]}"; do
  step "Onboarding division '$d' (Docker stack + Keycloak/OpenFGA/DID/ingest)"
  "$VENV_PY" "$ROOT/scripts/onboard_division.py" "$ROOT/infra/divisions/$d.yml" \
    || fail "Onboarding '$d' failed."
done

# ── 5. Federate ───────────────────────────────────────────────────────────────
step "Federating divisions (${DIVS[*]})"
"$VENV_PY" "$ROOT/scripts/federate_divisions.py" --only "${DIVS[@]}" || fail "Federation failed."

# ── 6. Start agents + workers ─────────────────────────────────────────────────
# Linux has no clusters.ps1; launch each division's agent + worker as background procs.
step "Starting agents + Temporal workers"
mkdir -p "$ROOT/logs"
for d in "${DIVS[@]}"; do
  ( cd "$ROOT/agt-federated-rag" && RAG_ENV_FILE=".env.$d" nohup "$VENV_PY" -m api.main \
      >"$ROOT/logs/$d-api.out" 2>&1 & echo $! >"$ROOT/logs/$d-api.pid" )
  ( cd "$ROOT/agt-federated-rag" && RAG_ENV_FILE=".env.$d" nohup "$VENV_PY" -m workflow.worker \
      >"$ROOT/logs/$d-worker.out" 2>&1 & echo $! >"$ROOT/logs/$d-worker.pid" )
  echo "  started $d (.env.$d)"
done
sleep 6
for d in "${DIVS[@]}"; do
  base=$("$VENV_PY" -c "import yaml;print(yaml.safe_load(open('$ROOT/infra/divisions/$d.yml'))['port_base'])")
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:$base/health" || echo DOWN)
  echo "  $d :$base/health -> $code"
done

# ── 7. Done ───────────────────────────────────────────────────────────────────
step "DONE — next steps"
cat <<EOF
  UI:        cd ui && npm run start        ->  http://localhost:5173
  Logins:    alice  (infra/generated/alpha/secrets.json -> seed_user_password)
             bob    (infra/generated/beta/secrets.json  -> seed_user_password)
  Verify:    cd agt-federated-rag && ../.venv/bin/python -m pytest tests -q
  Stop:      kill \$(cat logs/*-api.pid logs/*-worker.pid)
  TIP:       run one throwaway query per pane first — the free-tier LLM cold-starts.
EOF

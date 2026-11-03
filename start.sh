#!/usr/bin/env bash
# Load the SOC. Run on the sandbox VM, from the folder you cloned:
#
#     sudo ./start.sh
#
# 1. scripts/sandbox_env.py finds your cluster and writes env.sh (your own API key, root-only).
# 2. Two background jobs load the workshop in parallel (see ./soc-status):
#       vgi-pipeline  data, detection rules, machine learning, the attack, the GuardDuty archive
#       vgi-agentic   LLM connectors, the GLaDOS agent, cases, Wiz exposure, TARS + MOTHER workflows
# They keep running if you close the terminal. Re-running this script is safe (it resumes).
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E "$0" "$@"          # kubectl and the VM's LLM key are root-only
fi

echo "==> Finding your cluster and creating a key for it"
python3 scripts/sandbox_env.py
mkdir -p .state
chmod 755 .state

for lane in pipeline agentic; do
  unit="vgi-$lane"
  if systemctl is-active --quiet "$unit"; then
    echo "==> $unit is already running"
    continue
  fi
  systemctl reset-failed "$unit" 2>/dev/null || true
  systemd-run --quiet --unit "$unit" --collect \
    --working-directory "$PWD" \
    --setenv=PYTHONUNBUFFERED=1 \
    --property=StandardOutput="append:$PWD/.state/$lane.log" \
    --property=StandardError="append:$PWD/.state/$lane.log" \
    bash -c "set -a; . ./env.sh; set +a; exec python3 deploy.py $lane"
  echo "==> started $unit  (log: .state/$lane.log)"
done

chmod -R a+rX .state 2>/dev/null || true
echo
echo "Loading has started. It takes a while; it keeps going if you close this terminal."
echo "  ./soc-status                 what is done, running or failed"
echo "  tail -f .state/pipeline.log  the data and detections"
echo "  tail -f .state/agentic.log   the AI side"

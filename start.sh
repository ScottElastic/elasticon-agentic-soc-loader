#!/usr/bin/env bash
# Load the SOC. Run on the sandbox VM, from the folder you cloned (~/soc):
#
#     ./start.sh
#
# 1. scripts/sandbox_env.py finds your cluster and writes env.sh (a key that works only on your cluster).
# 2. It asks systemd to start two background jobs as you. They keep going if you close the terminal
#    or move to the next challenge. See ./soc-status:
#       pipeline  data, detection rules, machine learning, the attack, the GuardDuty archive
#       agentic   the GLaDOS agent, cases, Wiz exposure data, the TARS and MOTHER workflows
# Re-running is safe: it resumes where a failed job stopped and never restarts one that is running.
set -euo pipefail
cd "$(dirname "$0")"

if [ "$PWD" != "/home/elastic/soc" ]; then
  echo "Please clone the repo into ~/soc (git clone <url> soc) so the background jobs can find it." >&2
  echo "You are in: $PWD" >&2
  exit 1
fi
if [ ! -f /opt/vgi/ready ]; then
  echo "The sandbox is still being prepared. Wait a minute, then run ./start.sh again." >&2
  exit 1
fi

echo "==> Finding your cluster and creating a key for it"
python3 scripts/sandbox_env.py
mkdir -p .state
chmod 755 .state

for lane in pipeline agentic; do
  state=$(systemctl show -p ActiveState --value "vgi-$lane.service" 2>/dev/null || echo unknown)
  if [ "$state" = "active" ] || [ "$state" = "activating" ]; then
    echo "==> $lane is already running"
  else
    : > ".state/$lane.log"
    touch ".state/start-$lane"
    echo "==> started $lane  (log: .state/$lane.log)"
  fi
done

echo
echo "Loading has started. It takes a while and keeps going if you close this terminal."
echo "  ./soc-status                 what is done, running or failed"
echo "  tail -f .state/pipeline.log  the data and detections"
echo "  tail -f .state/agentic.log   the AI side"

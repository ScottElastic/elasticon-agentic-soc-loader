#!/usr/bin/env python3
"""Root-only sandbox preparation. Run ONCE as root, by the track's challenge-1 setup script.

The managed Elastic preset deliberately gives the learner an unprivileged shell (user `elastic`: no
sudo, no kubectl) while root's environment holds the curriculum team's secrets. This script respects
that boundary. It does only the things that need root, puts the results where the learner can read
them (and nothing secret), and installs two systemd *path* units that start the loader as the
learner, never as root, when the learner runs ./start.sh.

  1. /opt/vgi/elastic-lab-ca.crt      the cluster CA (a certificate, world-readable)
     /opt/vgi/public-kibana-url        the URL the learner's browser uses for Kibana
     /opt/vgi/env.sh                   a root-only API key for the steps below (mode 0600)
  2. phase `llm`         the LLM connectors + ES|QL COMPLETION endpoints (the LLM key stays root-only)
  3. phase `federation`  the S3 server (kubectl) that will hold the GuardDuty archive
     Both phases are recorded in /opt/vgi/state/<phase>.json, which deploy.py treats as "already done".
  4. systemd: vgi-pipeline.path / vgi-agentic.path. Touching ~/soc/.state/start-<lane> starts that lane
     as user `elastic` (see start.sh). Systemd keeps it running across challenge boundaries.

Idempotent. Prints no secrets.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_DIR = "/opt/vgi"
STATE_DIR = f"{SYSTEM_DIR}/state"
LEARNER = os.environ.get("VGI_LEARNER", "elastic")
SOC_DIR = f"/home/{LEARNER}/soc"           # where the learner clones the loader (the track tells them to)
LANES = ("pipeline", "agentic")


def say(msg: str) -> None:
    print(msg, flush=True)


def mark(name: str, status: str, started: float, error: str = "") -> None:
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    tmp = f"{STATE_DIR}/{name}.json.tmp"
    with open(tmp, "w") as f:
        json.dump({"status": status, "started": started, "finished": time.time(), "error": error}, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, f"{STATE_DIR}/{name}.json")


def run_with_env(script: str, *args: str) -> int:
    """Run a loader script with /opt/vgi/env.sh sourced (root's key; never printed)."""
    cmd = f"set -a; . {SYSTEM_DIR}/env.sh; set +a; exec python3 {os.path.join(KIT, 'scripts', script)} {' '.join(args)}"
    return subprocess.run(["bash", "-c", cmd], cwd=KIT).returncode


UNIT_SERVICE = """[Unit]
Description=GLaDOS vs. Skynet loader: {lane} lane (runs as {user})

[Service]
Type=oneshot
User={user}
Group={user}
WorkingDirectory={soc}
Environment=PYTHONUNBUFFERED=1
ExecStartPre=-/bin/rm -f {soc}/.state/start-{lane}
ExecStart=/bin/bash -c 'set -a; . ./env.sh; set +a; exec python3 deploy.py {lane}'
StandardOutput=append:{soc}/.state/{lane}.log
StandardError=append:{soc}/.state/{lane}.log
TimeoutStartSec=infinity
"""

UNIT_PATH = """[Unit]
Description=Start the {lane} lane when the learner runs ./start.sh

[Path]
PathExists={soc}/.state/start-{lane}
Unit=vgi-{lane}.service

[Install]
WantedBy=multi-user.target
"""


def install_units() -> None:
    for lane in LANES:
        with open(f"/etc/systemd/system/vgi-{lane}.service", "w") as f:
            f.write(UNIT_SERVICE.format(lane=lane, user=LEARNER, soc=SOC_DIR))
        with open(f"/etc/systemd/system/vgi-{lane}.path", "w") as f:
            f.write(UNIT_PATH.format(lane=lane, soc=SOC_DIR))
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", *[f"vgi-{l}.path" for l in LANES]], check=True)


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("sandbox_prep.py must run as root (it is run by the track's challenge-1 setup script).")
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    os.chmod(SYSTEM_DIR, 0o755)

    say("== 1. cluster CA, public Kibana URL, root API key")
    if subprocess.run([sys.executable, os.path.join(KIT, "scripts", "sandbox_env.py"), "--system"]).returncode != 0:
        return 1
    r = subprocess.run("kubectl get kibana -n default -o jsonpath='{.items[0].spec.config.server\\.publicBaseUrl}'",
                       shell=True, capture_output=True, text=True)
    url = r.stdout.strip().strip("'")
    if url.startswith("http"):
        with open(f"{SYSTEM_DIR}/public-kibana-url", "w") as f:
            f.write(url + "\n")
        os.chmod(f"{SYSTEM_DIR}/public-kibana-url", 0o644)
        say(f"   public Kibana URL: {url}")
    else:
        say("   (no server.publicBaseUrl on the Kibana resource; links will use the internal URL)")

    failed = 0
    for phase, script, args in (("llm", "sandbox_llm.py", ()), ("federation", "sandbox_s3.py", ("up",))):
        say(f"== phase {phase}")
        t = time.time()
        rc = run_with_env(script, *args)
        mark(phase, "done" if rc == 0 else "failed", t, "" if rc == 0 else f"exit {rc}")
        failed += rc != 0

    say("== systemd: path units that start the loader as the learner")
    install_units()
    with open(f"{SYSTEM_DIR}/ready", "w") as f:
        f.write(time.strftime("%FT%TZ", time.gmtime()) + "\n")
    os.chmod(f"{SYSTEM_DIR}/ready", 0o644)
    say("== sandbox prepared" + (f" ({failed} phase(s) failed; see above)" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Instruqt sandbox bootstrap: find the cluster and write an env.sh for the loader.

Two ways to run it, picked automatically:

  * As the LEARNER (user `elastic`, no root, no kubectl): this is what `./start.sh` does.
        python3 scripts/sandbox_env.py            # writes <repo>/env.sh (mode 0600, git-ignored)
    The `elastic` password is read from /home/kubernetes-vm/env (the preset makes it readable to
    the learner) and the cluster CA from /opt/vgi/elastic-lab-ca.crt (copied there by sandbox_prep.py).

  * As ROOT, once, from the track's challenge-1 setup (via sandbox_prep.py):
        python3 scripts/sandbox_env.py --system   # writes /opt/vgi/env.sh (root-only) + the CA
    Reads both from the Kubernetes secrets the managed preset creates.

Either way it mints ONE API key inside this sandbox's own throwaway cluster, so the kit's scripts
(which authenticate with `Authorization: ApiKey ...`) work unchanged. The key lives only in this
sandbox. The password is used once, in memory. Nothing secret is printed. Re-running reuses the key
while it still authenticates.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_DIR = "/opt/vgi"
SYSTEM_CA = f"{SYSTEM_DIR}/elastic-lab-ca.crt"
VM_ENV_FILE = "/home/kubernetes-vm/env"
ES = os.environ.get("ELASTICSEARCH_URL_ELASTIC_LAB", "https://es.elastic.lab").rstrip("/")
KB = os.environ.get("KIBANA_URL_ELASTIC_LAB", "https://kb.elastic.lab").rstrip("/")
KEY_LIFETIME = "30d"          # sandboxes last hours; this just bounds a forgotten key


def kubectl_works() -> bool:
    try:
        return subprocess.run(["kubectl", "get", "ns", "default"], capture_output=True).returncode == 0
    except OSError:
        return False


def kubectl(*args: str) -> str:
    r = subprocess.run(["kubectl", *args], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {r.stderr.strip()[:200]}")
    return r.stdout


def read_env_file(path: str) -> dict:
    out = {}
    try:
        for line in open(path, errors="replace"):
            line = line.strip()
            line = line[7:] if line.startswith("export ") else line
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
    except OSError:
        pass
    return out


def get_ca(system: bool, ca_path: str) -> str:
    """Return the path of a CA file that verifies the cluster's certificate."""
    if not system and os.path.exists(SYSTEM_CA):
        return SYSTEM_CA                           # put there by sandbox_prep.py
    if kubectl_works():
        b64 = kubectl("get", "secret", "elastic-lab-tls", "-n", "default", "-o", "jsonpath={.data.tls\\.crt}")
        os.makedirs(os.path.dirname(ca_path), exist_ok=True)
        with open(ca_path, "wb") as f:
            f.write(base64.b64decode(b64))
        os.chmod(ca_path, 0o644)                   # a certificate, not a secret
        return ca_path
    sys.exit(f"No cluster CA: {SYSTEM_CA} is missing and kubectl is not available.\n"
             "The sandbox setup has not finished yet; wait a minute and try again.")


def get_password() -> str:
    if kubectl_works():
        return kubectl("get", "secret", "elasticsearch-es-elastic-user", "-n", "default",
                       "-o", "go-template={{.data.elastic | base64decode}}")
    pw = read_env_file(VM_ENV_FILE).get("ELASTICSEARCH_PASSWORD", "")
    if not pw:
        sys.exit(f"Could not find the cluster password in {VM_ENV_FILE}.")
    return pw


def call(path: str, auth: str, ca: str, method="GET", body=None, base=ES):
    ctx = ssl.create_default_context(cafile=ca)
    req = urllib.request.Request(base + path, method=method, headers={
        "Authorization": auth, "Content-Type": "application/json", "kbn-xsrf": "true"},
        data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:                                  # not ready yet, DNS, TLS ...
        return 0, {"error": str(e)}


def existing_key(env_file: str, ca: str) -> str:
    """The key from a previous run, if env.sh is there and the key still authenticates."""
    if not os.path.exists(env_file):
        return ""
    for line in open(env_file):
        if line.startswith("export ELASTICSEARCH_API_KEY="):
            key = line.split("=", 1)[1].strip().strip('"')
            status, _ = call("/_security/_authenticate", f"ApiKey {key}", ca)
            return key if status == 200 else ""
    return ""


def mint_key(name: str, ca: str) -> str:
    basic = "Basic " + base64.b64encode(f"elastic:{get_password()}".encode()).decode()
    # No role_descriptors: the key inherits the `elastic` superuser's privileges.
    status, body = call("/_security/api_key", basic, ca, "POST", {"name": name, "expiration": KEY_LIFETIME})
    if status != 200 or "encoded" not in body:
        sys.exit(f"could not mint an API key (HTTP {status}); is Elasticsearch up? ({str(body.get('error', ''))[:120]})")
    return body["encoded"]


def public_kibana_url() -> str:
    """The URL the learner's browser uses for Kibana, if the sandbox tells us."""
    try:
        v = open(f"{SYSTEM_DIR}/public-kibana-url").read().strip()
        if v.startswith("http"):
            return v.rstrip("/")
    except OSError:
        pass
    v = read_env_file(VM_ENV_FILE).get("KIBANA_URL_UI", "")
    return v.rstrip("/") if v.startswith("http") else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", action="store_true", help="root: write /opt/vgi/env.sh and the CA (used by sandbox_prep.py)")
    a = ap.parse_args()
    if a.system:
        if os.geteuid() != 0:
            sys.exit("--system must run as root")
        os.makedirs(SYSTEM_DIR, mode=0o755, exist_ok=True)
        env_file, ca_path, key_name = f"{SYSTEM_DIR}/env.sh", SYSTEM_CA, "vgi-root"
    else:
        env_file, ca_path, key_name = os.path.join(KIT, "env.sh"), os.path.join(KIT, ".elastic-lab-ca.crt"), "vgi-loader"
    ca = get_ca(a.system, ca_path)
    key = existing_key(env_file, ca)
    reused = bool(key)
    if not key:
        key = mint_key(key_name, ca)
    lines = [
        "# Written by scripts/sandbox_env.py for THIS sandbox only. Git-ignored. Never commit or paste it.",
        f'export ELASTICSEARCH_URL="{ES}"',
        f'export KIBANA_URL="{KB}"',
        f'export ELASTICSEARCH_API_KEY="{key}"',
        'export KIBANA_API_KEY="$ELASTICSEARCH_API_KEY"',
        f'export SSL_CERT_FILE="{ca}"',
        f'export REQUESTS_CA_BUNDLE="{ca}"',
        'export VGI_RULES="${VGI_RULES:-story}"       # 3 small nodes: the 26 story rules, not ~700',
    ]
    pub = public_kibana_url()
    if pub:
        lines.append(f'export KIBANA_PUBLIC_URL="{pub}"')
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(env_file, 0o600)
    status, who = call("/_security/_authenticate", f"ApiKey {key}", ca)
    kb_status, _ = call("/api/status", f"ApiKey {key}", ca, base=KB)
    print(f"{env_file} written ({'reused' if reused else 'new'} API key); "
          f"Elasticsearch auth HTTP {status}, Kibana HTTP {kb_status}; "
          f"authenticated as '{who.get('username', '?')}'")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())

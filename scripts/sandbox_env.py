#!/usr/bin/env python3
"""Instruqt sandbox bootstrap, step 1: find the cluster and write ./env.sh.

Run once, on the sandbox VM, before deploy.py:

    python3 scripts/sandbox_env.py          # writes <repo>/env.sh (mode 0600, git-ignored)
    set -a; . ./env.sh; set +a

What it does (all idempotent):
  1. Reads the cluster CA and the `elastic` password from the Kubernetes secrets the managed
     Elastic preset creates. The password is used once, in memory, and never written anywhere.
  2. Mints ONE API key inside this sandbox's own throwaway cluster, so the kit's scripts (which
     authenticate with `Authorization: ApiKey ...`) work unchanged. The key exists only in this
     sandbox and dies with it.
  3. Writes env.sh with the endpoints, the key and SSL_CERT_FILE (so Python trusts the cluster CA).
  4. Re-running reuses the key while it still authenticates; it mints a new one only if it doesn't.

It prints no secret values. Needs `kubectl` access (run as root, or via `sudo`).
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(KIT, "env.sh")
CA_FILE = os.path.join(KIT, ".elastic-lab-ca.crt")
ES = os.environ.get("ELASTICSEARCH_URL_ELASTIC_LAB", "https://es.elastic.lab").rstrip("/")
KB = os.environ.get("KIBANA_URL_ELASTIC_LAB", "https://kb.elastic.lab").rstrip("/")
KEY_NAME = "vgi-loader"
KEY_LIFETIME = "30d"          # sandboxes last hours; this just bounds a forgotten key


def kubectl(*args: str) -> str:
    r = subprocess.run(["kubectl", *args], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {r.stderr.strip()[:200]}\n"
                 "Run this as root (or with sudo) on the sandbox VM.")
    return r.stdout


def write_ca() -> None:
    b64 = kubectl("get", "secret", "elastic-lab-tls", "-n", "default", "-o", "jsonpath={.data.tls\\.crt}")
    with open(CA_FILE, "wb") as f:
        f.write(base64.b64decode(b64))
    os.chmod(CA_FILE, 0o644)               # a certificate, not a secret


def call(path: str, auth: str, method="GET", body=None, base=ES):
    ctx = ssl.create_default_context(cafile=CA_FILE)
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


def existing_key() -> str:
    """The key from a previous run, if env.sh is there and the key still authenticates."""
    if not os.path.exists(ENV_FILE):
        return ""
    for line in open(ENV_FILE):
        if line.startswith("export ELASTICSEARCH_API_KEY="):
            key = line.split("=", 1)[1].strip().strip('"')
            status, _ = call("/_security/_authenticate", f"ApiKey {key}")
            return key if status == 200 else ""
    return ""


def mint_key() -> str:
    password = kubectl("get", "secret", "elasticsearch-es-elastic-user", "-n", "default",
                       "-o", "go-template={{.data.elastic | base64decode}}")
    basic = "Basic " + base64.b64encode(f"elastic:{password}".encode()).decode()
    # No role_descriptors: the key inherits the `elastic` superuser's privileges.
    status, body = call("/_security/api_key", basic, "POST", {"name": KEY_NAME, "expiration": KEY_LIFETIME})
    if status != 200 or "encoded" not in body:
        sys.exit(f"could not mint an API key (HTTP {status}); is Elasticsearch up? ({body.get('error', '')[:120]})")
    return body["encoded"]


def main() -> int:
    write_ca()
    key = existing_key()
    reused = bool(key)
    if not key:
        key = mint_key()
    lines = [
        "# Written by scripts/sandbox_env.py for THIS sandbox only. Git-ignored. Never commit or paste it.",
        f'export ELASTICSEARCH_URL="{ES}"',
        f'export KIBANA_URL="{KB}"',
        f'export ELASTICSEARCH_API_KEY="{key}"',
        'export KIBANA_API_KEY="$ELASTICSEARCH_API_KEY"',
        f'export SSL_CERT_FILE="{CA_FILE}"',
        f'export REQUESTS_CA_BUNDLE="{CA_FILE}"',
        'export VGI_RULES="${VGI_RULES:-story}"       # 3 small nodes: the 26 story rules, not ~700',
    ]
    fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(ENV_FILE, 0o600)
    # Prove it works, without printing anything secret.
    status, who = call("/_security/_authenticate", f"ApiKey {key}")
    kb_status, _ = call("/api/status", f"ApiKey {key}", base=KB)
    print(f"env.sh written ({'reused' if reused else 'new'} API key); "
          f"Elasticsearch auth HTTP {status}, Kibana HTTP {kb_status}; "
          f"authenticated as '{who.get('username', '?')}'")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Give this sandbox's Elastic stack its LLMs (the Serverless kit assumed Elastic-managed ones).

The managed Elastic preset hands every sandbox a budget-capped key for a LiteLLM proxy and a helper
that registers one connector. This script builds on that, using only things verified in a sandbox:

  1. runs the preset helper once, which creates the base connector `openai-connector`;
  2. clones it into the workshop's connectors (ids are fixed so workflows and the guide can name them):
         vgi-opus    Claude Opus 4.8     Attack Discovery, GLaDOS, Alert analysis
         vgi-sonnet  Claude Sonnet 5     TARS / MOTHER AI steps (cheap and fast)
  3. smoke-tests each connector with a real call (`invokeAI`);
  4. creates the Elasticsearch inference endpoints that ES|QL `COMPLETION` needs:
         vgi-completion (Sonnet)         the Host truth lab
         vgi-triage     (Opus)           the Deep Thought federation step
  5. sets the Agent Builder "Main models" and the default AI connector.

Run after `source env.sh`, as root on the VM (the key lives in the VM environment, root-only):
    python3 scripts/sandbox_llm.py

It never prints the LLM key. Idempotent.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ES = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
KB = os.environ.get("KIBANA_URL", "").rstrip("/")
KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")
HELPER = "/opt/workshops/elastic-llm.sh"
BASE_NAME = "openai-connector"
BASE_MODEL = "gemini-3.1-pro"          # the helper's own default; our connectors are clones with other models

CONNECTORS = [  # id, display name, model
    ("vgi-opus", "VGI · Claude Opus 4.8", "claude-opus-4.8"),
    ("vgi-sonnet", "VGI · Claude Sonnet 5", "claude-sonnet-5"),
]
INFERENCE = [  # id, model
    ("vgi-completion", "claude-sonnet-5"),
    ("vgi-triage", "claude-opus-4.8"),
]
DEFAULT_CONNECTOR = "vgi-opus"


def say(msg: str) -> None:
    print(msg, flush=True)


def call(base: str, method: str, path: str, body=None, version: str | None = None, timeout: int = 150):
    headers = {"Authorization": f"ApiKey {KEY}", "Content-Type": "application/json",
               "kbn-xsrf": "true", "x-elastic-internal-origin": "Kibana"}
    if version:
        headers["elastic-api-version"] = version
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw[:400]
    except Exception as e:                                           # noqa: BLE001
        return 0, str(e)


kb = lambda m, p, b=None, **k: call(KB, m, p, b, **k)      # noqa: E731
es = lambda m, p, b=None, **k: call(ES, m, p, b, **k)      # noqa: E731


def vm_env() -> dict:
    """This process's env plus the preset's env files (where LLM_APIKEY and friends live)."""
    env = dict(os.environ)
    for path in ("/root/.env", "/home/kubernetes-vm/env"):
        if not os.path.exists(path):
            continue
        try:
            for line in open(path, errors="replace"):
                line = line.strip()
                line = line[7:] if line.startswith("export ") else line
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env.setdefault(k.strip(), v.strip().strip("'\""))
        except PermissionError:
            pass
    return env


def scrub(text: str, secret: str) -> str:
    return text.replace(secret, "<redacted>") if secret else text


def base_connector() -> dict | None:
    status, conns = kb("GET", "/api/actions/connectors")
    if status != 200 or not isinstance(conns, list):
        sys.exit(f"cannot list connectors: HTTP {status} {str(conns)[:160]}")
    return next((c for c in conns if c.get("name") == BASE_NAME), None)


def ensure_base(env: dict) -> dict:
    base = base_connector()
    if base:
        say(f"  base connector present ({BASE_NAME})")
        return base
    if not os.path.exists(HELPER):
        sys.exit(f"{HELPER} not found: this is not a managed Elastic sandbox")
    say("  running the preset LLM helper ...")
    run_env = dict(env, KIBANA_URL=KB, NODE_EXTRA_CA_CERTS=env.get("SSL_CERT_FILE", ""),
                   CURL_CA_BUNDLE=env.get("SSL_CERT_FILE", ""))
    r = subprocess.run([HELPER, "-m", BASE_MODEL, "-k", "false"], capture_output=True, text=True,
                       env=run_env, timeout=420)
    tail = "\n".join(l for l in (r.stdout + r.stderr).splitlines()[-6:])
    if r.returncode != 0:
        sys.exit(f"helper failed ({r.returncode}):\n{scrub(tail, env.get('LLM_APIKEY', ''))}")
    base = base_connector()
    if not base:
        sys.exit("helper ran but openai-connector does not exist")
    return base


def smoke(connector_id: str, model: str) -> bool:
    for attempt in range(3):
        status, body = kb("POST", f"/api/actions/connector/{connector_id}/_execute", {
            "params": {"subAction": "invokeAI", "subActionParams": {
                "model": model, "messages": [{"role": "user", "content": "Reply with exactly VGI_READY."}]}}})
        if status == 200 and "VGI_READY" in json.dumps(body):
            return True
        time.sleep(5)
    return False


def ensure_connectors(env: dict, base: dict) -> None:
    key = env.get("LLM_APIKEY") or next((v for k, v in env.items() if re.search(r"(OPENAI|LLM).*KEY", k, re.I)
                                         and not re.search(r"DURATION|BUDGET|MODELS", k, re.I) and v), "")
    if not key:
        sys.exit("the sandbox LLM key (LLM_APIKEY) is not visible; run as root on the VM")
    detail = kb("GET", f"/api/actions/connector/{base['id']}")[1]
    for cid, name, model in CONNECTORS:
        body = {"name": name, "config": dict(detail.get("config") or {}, defaultModel=model), "secrets": {"apiKey": key}}
        status, cur = kb("GET", f"/api/actions/connector/{cid}")
        if status == 200:
            status, out = kb("PUT", f"/api/actions/connector/{cid}", body)
        else:
            status, out = kb("POST", f"/api/actions/connector/{cid}",
                             dict(body, connector_type_id=detail.get("connector_type_id")))
        if status not in (200, 201):
            sys.exit(f"connector {cid}: HTTP {status} {scrub(str(out)[:200], key)}")
        say(f"  {'✅' if smoke(cid, model) else '❌'} connector {cid} ({model})")
    env["_LLM_KEY"] = key


def ensure_inference(env: dict) -> None:
    host = (env.get("LLM_PROXY_URL") or "").replace("https://", "").replace("http://", "").strip("/")
    key = env["_LLM_KEY"]
    if not host:
        say("  ⚠️  LLM_PROXY_URL not visible: skipping the ES|QL COMPLETION endpoints")
        return
    for iid, model in INFERENCE:
        body = {"service": "openai", "service_settings": {
            "api_key": key, "model_id": model, "url": f"https://{host}/v1/chat/completions"}}
        status, out = es("PUT", f"/_inference/completion/{iid}", body)
        if status == 400 and "already exists" in str(out):
            status = 200
        say(f"  {'✅' if status == 200 else '❌'} inference endpoint {iid} ({model}) HTTP {status}"
            + ("" if status == 200 else " " + scrub(str(out)[:160], key)))
    status, out = es("POST", "/_query", {"query": 'ROW prompt = "Reply with exactly VGI_READY" | COMPLETION a = prompt '
                                                  'WITH { "inference_id": "vgi-completion" } | KEEP a'})
    ok = status == 200 and "VGI_READY" in json.dumps(out)
    say(f"  {'✅' if ok else '❌'} ES|QL COMPLETION through vgi-completion")


def ensure_agent_models() -> None:
    hdr = "1"
    status, current = kb("GET", "/internal/search_inference_endpoints/settings", version=hdr)
    status2, registry = kb("GET", "/internal/search_inference_endpoints/features", version=hdr)
    if status != 200 or status2 != 200:
        say(f"  ⚠️  Agent Builder model settings unavailable (HTTP {status}/{status2}); set Main models in the UI")
        return
    feats = registry.get("features", [])
    parent = next((f for f in feats if re.fullmatch(r"agent builder", f.get("featureName", ""), re.I)
                   and not f.get("parentFeatureId")), None) or \
        next((f for f in feats if f.get("featureId") == "agent_builder" and not f.get("parentFeatureId")), None)
    main = next((f for f in feats if parent and f.get("parentFeatureId") == parent["featureId"]
                 and re.search("main", f.get("featureName", ""), re.I)), None)
    if not main:
        say("  ⚠️  Agent Builder 'Main models' feature not found; set it in the UI")
        return
    desired = {"features": [f for f in current.get("data", {}).get("features", [])
                            if f.get("feature_id") != main["featureId"]]
               + [{"feature_id": main["featureId"], "endpoints": [{"id": c[0]} for c in CONNECTORS]}]}
    status, out = kb("PUT", "/internal/search_inference_endpoints/settings", desired, version=hdr)
    say(f"  {'✅' if status == 200 else '❌'} Agent Builder main models = {[c[0] for c in CONNECTORS]} (HTTP {status})")


def set_defaults() -> None:
    status, out = kb("POST", "/internal/kibana/settings", {"changes": {
        "genAiSettings:defaultAIConnector": DEFAULT_CONNECTOR}}, version="1")
    say(f"  {'✅' if status == 200 else '⚠️ '} default AI connector = {DEFAULT_CONNECTOR} (HTTP {status})")


def main() -> int:
    if not (ES and KB and KEY):
        sys.exit("source env.sh first (ELASTICSEARCH_URL, KIBANA_URL, ELASTICSEARCH_API_KEY)")
    env = vm_env()
    base = ensure_base(env)
    ensure_connectors(env, base)
    ensure_inference(env)
    ensure_agent_models()
    set_defaults()
    return 0


if __name__ == "__main__":
    sys.exit(main())

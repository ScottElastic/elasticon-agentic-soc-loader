#!/usr/bin/env python3
"""GLaDOS vs. Skynet: loader for the Instruqt sandbox (Elastic 9.5.x on ECK).

One entry point, in the order things must happen. Every phase is idempotent: re-running it
is safe, and a phase that fails can be re-run on its own with --only.

    git clone --depth 1 --branch <tag> <this repo> soc && cd soc
    ./start.sh                       # writes env.sh, then asks systemd to run both lanes below as you
    ./soc-status                     # what is done, running or failed

Under the hood (all stdlib Python 3; `source env.sh` first):

    python3 deploy.py check          # read-only preconditions
    python3 deploy.py pipeline       # lane 1: data, rules, ML, the campaign, the GuardDuty archive
    python3 deploy.py agentic        # lane 2: LLMs, GLaDOS, cases, Wiz, S3, TARS + MOTHER (runs in parallel)
    python3 deploy.py load           # both lanes concurrently, in the foreground
    python3 deploy.py status         # phase table from .state/
    python3 deploy.py verify         # exit 0 = go
    python3 deploy.py seed           # re-seed an already-loaded sandbox (new campaign relative to now)

    python3 deploy.py pipeline --only rules     # one phase
    python3 deploy.py pipeline --from ml        # resume a lane from a phase
    python3 deploy.py --list                    # every phase, in order

A phase that needs another lane's output waits for it (see NEEDS); progress lives in .state/*.json,
which is what the track's per-challenge scripts poll.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KIT = os.path.dirname(os.path.abspath(__file__))       # seed-kit/
SCRIPTS = os.path.join(KIT, "scripts")
GEN = os.environ.get("VGI_GENERATOR") or os.path.join(KIT, "generator")
ASSETS = os.path.join(KIT, "assets")
STATE_DIR = os.environ.get("VGI_STATE_DIR") or os.path.join(KIT, ".state")          # one json file per phase

ES = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
KB = os.environ.get("KIBANA_URL", "").rstrip("/")
ES_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")
KB_KEY = os.environ.get("KIBANA_API_KEY", "") or ES_KEY
# Kibana space for everything the kit creates. Log data is cluster-wide; rules, alerts, entities,
# agent, workflows and cases live in the space. Scripts run from here inherit the /s/<space> URL.
SPACE = os.environ.get("KIBANA_SPACE", "default")
if SPACE != "default" and "/s/" not in KB:
    KB = f"{KB}/s/{SPACE}"
    os.environ["KIBANA_URL"] = KB
os.environ["KIBANA_SPACE"] = SPACE
ALERTS = f".alerts-security.alerts-{SPACE}"
# Shared clusters: VGI_RULES=story enables only the story rules (not ~700 by data source), and
# VGI_EXCLUDE_NAMESPACES=a,b attaches an exception so they ignore other teams' data streams.
RULES_SCOPE = os.environ.get("VGI_RULES", "all")
EXCLUDE_NS = [n.strip() for n in os.environ.get("VGI_EXCLUDE_NAMESPACES", "").split(",") if n.strip()]
# The data streams the kit writes, by type, and the namespaces only the kit uses.
KIT_STREAMS = {"logs": ["aws.cloudtrail", "aws.waf", "crowdstrike.fdr", "system.auth", "kubernetes.audit_logs",
                        "kubernetes.container_logs", "panw.panos"],
               "metrics": ["system.process"]}
KIT_NAMESPACES = ["prod_uswest", "dev_uswest", "prod_eucentral", "prod_mfg"]

HERO = "gridvault-usw2-01"
TARS_NAME = "TARS — Attendee Safe Response (Simulated Containment)"
MOTHER_NAME = "MOTHER — Daily Threat Hunt: IOC Watchlist Sweep"
RDS_RULE = "AWS RDS Snapshot Export"
ML_JOBS = ["auth_high_count_logon_fails_ea", "auth_rare_source_ip_for_a_user_ea",
           "suspicious_login_activity_ea"]
# Connector ids created by scripts/sandbox_llm.py (the Serverless kit used Elastic-managed ids).
LLM_CONNECTOR = os.environ.get("LLM_CONNECTOR", "vgi-sonnet")                          # TARS + MOTHER pin it
ALERT_ANALYSIS_CONNECTOR = os.environ.get("ALERT_ANALYSIS_CONNECTOR", "vgi-opus")      # Alert analysis


# ---------------------------------------------------------------- http
def _req(base, key, method, path, body=None, version="2023-10-31", timeout=180):
    h = {"Authorization": f"ApiKey {key}", "Content-Type": "application/json", "kbn-xsrf": "true",
         "x-elastic-internal-origin": "Kibana"}
    if version:
        h["elastic-api-version"] = version
    r = urllib.request.Request(base + path, method=method, headers=h,
                               data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:600]
    except urllib.error.URLError as e:
        return 0, str(e.reason)
    except TimeoutError as e:
        return 0, f"timeout: {e}"


def es(method, path, body=None, **kw):
    return _req(ES, ES_KEY, method, path, body, version=None, **kw)


def kb(method, path, body=None, **kw):
    return _req(KB, KB_KEY, method, path, body, **kw)


def ok(msg):
    print(f"  ✅ {msg}")


def warn(msg):
    print(f"  ⚠️  {msg}")


def fail(msg):
    print(f"  ❌ {msg}")


def run(*cmd, cwd=SCRIPTS, check=True):
    """Run an existing workshop script with this environment. Streams its output."""
    env = dict(os.environ, VGI_GENERATOR=GEN, PYTHONUNBUFFERED="1")
    print(f"  $ {' '.join(cmd)}")
    r = subprocess.run(list(cmd), cwd=cwd, env=env)
    if check and r.returncode != 0:
        raise SystemExit(f"  ❌ {' '.join(cmd[:3])} exited {r.returncode} — fix and re-run this phase with --only")
    return r.returncode


def py(*args, **kw):
    return run(sys.executable, *args, **kw)


# ---------------------------------------------------------------- phase state (one file per phase)
# Two lanes run at once, so each phase writes its own file: no shared file, no locking.
def _state_file(name):
    return os.path.join(STATE_DIR, f"{name}.json")


def mark(name, status, **extra):
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(_state_file(name)) as f:
            cur = json.load(f)
    except (OSError, ValueError):
        cur = {}
    cur.update(status=status, **extra)
    cur.setdefault("started", time.time())
    tmp = _state_file(name) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cur, f)
    os.replace(tmp, _state_file(name))


SYSTEM_STATE_DIR = "/opt/vgi/state"      # phases the sandbox setup (root) already did: llm, federation
PREPARED = ("llm", "federation")


def read_state(name):
    for d in (STATE_DIR, SYSTEM_STATE_DIR):
        try:
            with open(os.path.join(d, f"{name}.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return None


def wait_for(*names, timeout=3600):
    """Block until every named phase (possibly in the other lane) is done. Fails if one failed."""
    t0, said = time.time(), 0
    pending = list(names)
    while pending:
        for n in list(pending):
            st = (read_state(n) or {}).get("status")
            if st == "done":
                pending.remove(n)
            elif st == "failed":
                raise SystemExit(f"  ❌ cannot continue: phase '{n}' failed (see its log)")
        if not pending:
            return
        if time.time() - t0 > timeout:
            raise SystemExit(f"  ❌ timed out after {timeout // 60} min waiting for: {', '.join(pending)}")
        if time.time() - said > 120:
            print(f"  … waiting for {', '.join(pending)}", flush=True)
            said = time.time()
        time.sleep(10)


# ---------------------------------------------------------------- phase: check
def check():
    """Preconditions. Changes nothing. Every ❌ means the sandbox is not ready for the loader."""
    bad = 0
    for v in ("ELASTICSEARCH_URL", "KIBANA_URL", "ELASTICSEARCH_API_KEY"):
        if not os.environ.get(v):
            fail(f"{v} is not set (run scripts/sandbox_env.py, then `set -a; . ./env.sh; set +a`)")
            bad += 1
    if bad:
        raise SystemExit(1)
    s, b = es("GET", "/")
    if s != 200:
        fail(f"Elasticsearch unreachable: HTTP {s} {b}")
        raise SystemExit(1)
    ok(f"Elasticsearch {b.get('version', {}).get('number')} ({b.get('version', {}).get('build_flavor')})")
    s, b = kb("GET", "/api/status")
    (ok if s == 200 else fail)(f"Kibana reachable (HTTP {s})")
    bad += s != 200
    s, lic = es("GET", "/_license")
    ltype = lic.get("license", {}).get("type") if isinstance(lic, dict) else None
    (ok if ltype in ("trial", "enterprise", "platinum") else fail)(f"license: {ltype} (ML, Attack Discovery, Agent Builder, Workflows, federation need it)")
    bad += ltype not in ("trial", "enterprise", "platinum")
    s, b = es("GET", "/_query/data_source")
    (ok if s == 200 else warn)(f"ES|QL data federation API (HTTP {s})" + ("" if s == 200 else " — the GuardDuty step falls back to plain indices"))
    s, b = es("GET", "/_ml/anomaly_detectors")
    (ok if s == 200 else fail)(f"Machine learning available (HTTP {s})")
    bad += s != 200
    s, b = kb("GET", "/api/fleet/agent_policies?perPage=1")
    (ok if s == 200 else fail)(f"Fleet available (HTTP {s})")
    bad += s != 200
    s, b = kb("GET", "/api/workflows?size=1")
    (ok if s == 200 else fail)(f"Workflows API (HTTP {s})")
    bad += s != 200
    s, b = kb("GET", "/api/agent_builder/agents")
    (ok if s == 200 else fail)(f"Agent Builder API (HTTP {s})")
    bad += s != 200
    for p_ in PREPARED:
        st = (read_state(p_) or {}).get("status")
        (ok if st == "done" else warn)(f"sandbox setup phase '{p_}': {st or 'not recorded'}"
                                       + ("" if st == "done" else " — run as root: python3 scripts/sandbox_prep.py"))
    if not os.path.isdir(os.path.join(GEN, "vgi_sim")):
        fail(f"generator package not found at {GEN}")
        bad += 1
    if bad:
        raise SystemExit(f"\n{bad} blocking precondition(s).")


# ---------------------------------------------------------------- setup phases
def settings():
    """Kibana advanced settings the guide assumes."""
    s, b = kb("POST", "/internal/kibana/settings", {"changes": {"dateFormat:tz": "UTC", "enableESQL": True}},
              version="1")
    (ok if s == 200 else warn)(f"advanced settings: dateFormat:tz=UTC, enableESQL (HTTP {s})")


def llm():
    """The sandbox LLMs: connectors vgi-opus / vgi-sonnet, ES|QL COMPLETION endpoints, Agent Builder models."""
    py("sandbox_llm.py")


def integrations():
    """Fleet packages (mappings/pipelines — mandatory before any data) + prebuilt rules."""
    py(os.path.join(GEN, "run.py"), "install")


def templates():
    """Where another template outranks Fleet's for the kit's data streams, a clone of Fleet's above it."""
    s, b = es("GET", "/_index_template")
    if s != 200:
        fail(f"index templates: HTTP {s}")
        return 1
    tpls = {t["name"]: t["index_template"] for t in b["index_templates"]}
    for typ, datasets in KIT_STREAMS.items():
        for ds in datasets:
            fleet, mine = f"{typ}-{ds}", f"vgi-{typ}-{ds}"
            if fleet not in tpls:
                warn(f"{fleet}: no Fleet template (package not installed?)")
                continue
            streams = [f"{typ}-{ds}-{ns}" for ns in KIT_NAMESPACES]
            rivals = [(t.get("priority", 0), n) for n, t in tpls.items() if n not in (fleet, mine)
                      and any(fnmatch.fnmatch(st, p) for st in streams for p in t["index_patterns"])]
            top = max(rivals, default=(0, None))
            if top[0] < tpls[fleet].get("priority", 0):
                ok(f"{fleet}: Fleet template applies")
                continue
            body = {k: v for k, v in tpls[fleet].items() if k not in ("index_patterns", "priority", "_meta", "version")
                    and not k.endswith(("_date", "_date_millis"))}
            body.update(index_patterns=[f"{st}*" for st in streams], priority=top[0] + 10,
                        _meta={"managed_by": "vgi-seed-kit", "cloned_from": fleet,
                               "description": f"Outranks {top[1]} for the seed kit's namespaces only"})
            s, r = es("PUT", f"/_index_template/{mine}", body)
            (ok if s == 200 else fail)(f"{mine} (priority {top[0] + 10}, over {top[1]}) for {', '.join(KIT_NAMESPACES)}"
                                       + ("" if s == 200 else f": HTTP {s} {str(r)[:200]}"))
            s, live = es("GET", f"/_data_stream/{','.join(st + '*' for st in streams)}?expand_wildcards=all")
            for d in (live.get("data_streams", []) if s == 200 else []):
                if d.get("template") != mine:
                    warn(f"{d['name']} already exists on {d.get('template')}: roll it over to pick up {mine}")


def entity():
    """Entity Store v2 + risk scoring, and asset criticality for the three named hosts."""
    s, b = kb("GET", "/api/security/entity_store/status")
    if isinstance(b, dict) and b.get("status") == "running":
        ok("Entity Store already running")
    else:
        s, b = kb("POST", "/api/security/entity_store/enable", {})
        if s == 404:                                    # 9.5: the v2 store installs via /install
            s, b = kb("POST", "/api/security/entity_store/install", {})
        s = 200 if s == 201 else s
        (ok if s == 200 else warn)(f"Entity Store enable: HTTP {s} {'' if s == 200 else str(b)[:160]}"
                                   + ("" if s == 200 else " — enable it in the UI (CHECKLIST §2)"))
    for host, level in (("gridvault-usw2-01", "extreme_impact"), ("VGI-LT-4471", "high_impact"),
                        ("gridvault-bastion-usw2-01", "high_impact")):
        s, b = kb("POST", "/api/asset_criticality", {"id_field": "host.name", "id_value": host,
                                                     "criticality_level": level})
        (ok if s == 200 else warn)(f"asset criticality {host} = {level} (HTTP {s})")


def baseline():
    """30 days of thinned history + 15 minutes of steady-state traffic. BEFORE enabling rules:
    the Fleet final pipeline stamps event.ingested=now, so override rules would fire on history."""
    py(os.path.join(GEN, "run.py"), "seed", "--days", "30")
    py(os.path.join(GEN, "run.py"), "background", "--minutes", "15")


def rules():
    """Prebuilt rules by data source, then every rule the story needs by id, then the custom lead rule."""
    if RULES_SCOPE == "story":
        ok("VGI_RULES=story: skipping the ~700 rules by data source; story rules only")
    else:
        py(os.path.join(GEN, "run.py"), "enable-rules")
    req = json.load(open(os.path.join(ASSETS, "required-rules.json")))
    missing = []
    for r in req:
        s, b = kb("GET", f"/api/detection_engine/rules?rule_id={urllib.parse.quote(r['rule_id'])}")
        if s != 200:
            missing.append(r["name"])
            continue
        if not b.get("enabled"):
            kb("PATCH", "/api/detection_engine/rules", {"rule_id": r["rule_id"], "enabled": True})
    (ok if not missing else fail)(f"{len(req) - len(missing)}/{len(req)} required rules installed + enabled"
                                  + (f" — missing: {missing}" if missing else ""))
    custom = json.load(open(os.path.join(ASSETS, "rule-vgi-lab3-shell-from-package-manager.json")))
    s, b = kb("GET", f"/api/detection_engine/rules?rule_id={custom['rule_id']}")
    if s == 200:
        s, b = kb("PUT", "/api/detection_engine/rules", custom)
    else:
        s, b = kb("POST", "/api/detection_engine/rules", custom)
    (ok if s == 200 else fail)(f"custom rule '{custom['name']}' (HTTP {s}{'' if s == 200 else ' ' + str(b)[:200]})")
    if EXCLUDE_NS:
        _exclude_namespaces([r["rule_id"] for r in req] + [custom["rule_id"]])


EXCLUDE_LIST = "vgi-foreign-namespaces"


def _exclude_namespaces(rule_ids):
    """A shared exception list (data_stream.namespace is one of VGI_EXCLUDE_NAMESPACES) on the story rules."""
    s, lst = kb("GET", f"/api/exception_lists?list_id={EXCLUDE_LIST}&namespace_type=single")
    if s == 404:
        s, lst = kb("POST", "/api/exception_lists", {
            "list_id": EXCLUDE_LIST, "type": "detection", "namespace_type": "single",
            "name": "VGI — other teams' data on this cluster",
            "description": "Added by the ElastiCon seed kit: the story rules ignore these data stream namespaces."})
    if s != 200:
        fail(f"exception list {EXCLUDE_LIST}: HTTP {s} {str(lst)[:200]}")
        return
    item = {"list_id": EXCLUDE_LIST, "item_id": f"{EXCLUDE_LIST}-item", "type": "simple", "namespace_type": "single",
            "name": "Other teams' namespaces", "description": "Seed kit: VGI_EXCLUDE_NAMESPACES",
            "entries": [{"field": "data_stream.namespace", "operator": "included", "type": "match_any",
                         "value": EXCLUDE_NS}]}
    s, b = kb("POST", "/api/exception_lists/items", item)
    if s == 409:
        s, b = kb("PUT", "/api/exception_lists/items", {k: v for k, v in item.items() if k != "list_id"})
    (ok if s == 200 else fail)(f"exception: data_stream.namespace is one of {EXCLUDE_NS} (HTTP {s})")
    ref = {"id": lst["id"], "list_id": EXCLUDE_LIST, "type": "detection", "namespace_type": "single"}
    done = 0
    for rid in rule_ids:
        s, r = kb("GET", f"/api/detection_engine/rules?rule_id={urllib.parse.quote(rid)}")
        if s != 200:
            continue
        have = r.get("exceptions_list") or []
        patch = {}
        if not any(x.get("list_id") == EXCLUDE_LIST for x in have):
            patch["exceptions_list"] = have + [ref]
        # EQL verifies mappings across every index it reads before exceptions apply: one conflicting
        # field in another team's stream (text vs keyword) fails the rule. Drop those streams from its index.
        idx = r.get("index") or []
        drop = [f"-*-{ns}" for ns in EXCLUDE_NS if f"-*-{ns}" not in idx]
        if r.get("type") == "eql" and idx and drop:
            patch["index"] = idx + drop
        if not patch:
            done += 1
            continue
        s, r = kb("PATCH", "/api/detection_engine/rules", {"rule_id": rid, **patch})
        done += s == 200
        if s != 200:
            warn(f"exception not attached to {rid}: HTTP {s} {str(r)[:160]}")
    (ok if done == len(rule_ids) else warn)(f"namespace exception on {done}/{len(rule_ids)} story rules")


def ml():
    """The prebuilt security_auth module over logs-*, its three workshop jobs open and running."""
    s, b = es("GET", "/_ml/anomaly_detectors/_all")
    have = {j["job_id"] for j in b.get("jobs", [])} if s == 200 else set()
    if not set(ML_JOBS) <= have:
        s, b = kb("POST", "/internal/ml/modules/setup/security_auth", {
            "indexPatternName": "logs-*", "startDatafeed": False,
            "groups": ["security", "authentication"], "useDedicatedIndex": False}, version="1")
        (ok if s == 200 else fail)(f"ML module security_auth set up (HTTP {s}{'' if s == 200 else ' ' + str(b)[:200]})")
    start = int((time.time() - 35 * 86400) * 1000)
    for j in ML_JOBS:
        es("POST", f"/_ml/anomaly_detectors/{j}/_open", timeout=600)
        s, b = es("POST", f"/_ml/datafeeds/datafeed-{j}/_start", {"start": str(start)}, timeout=600)
        ok(f"{j}: open, datafeed {'started' if s == 200 else 'already running' if s == 409 else f'HTTP {s}'}")


def exposure():
    """Wiz package + findings + transforms + the vgi-asset-exposure lookup index."""
    py("wiz_seed.py")


def agent():
    """GLaDOS: 6 AWS tools, the agent, 3 cross-domain tools, the re-skin, and the Wiz exposure tool."""
    py("glados_aws_tools.py")
    py("glados_agent.py")
    py("elasticon_tools.py")
    py("reskin_glados.py")
    py("wiz_tool.py")


def public_kibana_url():
    """The Kibana URL a learner's browser uses (the sandbox setup records it in env.sh as KIBANA_PUBLIC_URL)."""
    url = os.environ.get("KIBANA_PUBLIC_URL", "").strip()
    return url.rstrip("/") if url.startswith("http") else KB


def _find_workflow(name):
    s, wl = kb("GET", "/api/workflows?size=100")
    return next((w for w in wl.get("results", []) if w["name"] == name), None) if s == 200 else None


def _deploy_workflow(path, name, subs=None):
    y = open(path).read()
    for a, b in (subs or {}).items():
        y = y.replace(a, b)
    cur = _find_workflow(name)
    if cur:
        s, b = kb("PUT", f"/api/workflows/workflow/{cur['id']}", {"yaml": y})
        (ok if s == 200 else fail)(f"workflow updated: {name} ({cur['id']}, HTTP {s}{'' if s == 200 else ' ' + str(b)[:200]})")
        return cur["id"]
    s, b = kb("POST", "/api/workflows", {"workflows": [{"yaml": y}]})
    (ok if s == 200 else fail)(f"workflow created: {name} (HTTP {s}{'' if s == 200 else ' ' + str(b)[:200]})")
    return None


def _enable_workflow(name):
    """Workflows are created disabled. On 9.5.x `PUT {enabled: true}` turns them on (no UI step)."""
    w = _find_workflow(name)
    if not w:
        fail(f"cannot enable '{name}': not found")
        return
    if w.get("enabled"):
        ok(f"already enabled: {name}")
        return
    s, b = kb("PUT", f"/api/workflows/workflow/{w['id']}", {"enabled": True})
    now = _find_workflow(name)
    good = bool(now and now.get("enabled"))
    (ok if good else fail)(f"enabled: {name} (HTTP {s})")
    if not good:
        why = b if isinstance(b, str) else {k: b.get(k) for k in ("enabled", "valid", "validationErrors") if k in b}
        print(f"     response: {str(why)[:600]}")
        print(f"     workflow now: {str({k: (now or {}).get(k) for k in ('enabled', 'valid')})}")


def workflows():
    """TARS and MOTHER (this sandbox's connector + Kibana URL, both enabled), then the managed Alert analysis workflow."""
    llm = {"Anthropic-Claude-Sonnet-4-5": LLM_CONNECTOR, ".alerts-security.alerts-default": ALERTS}
    _deploy_workflow(os.path.join(KIT, "workflows", "attendee-safe-response.yaml"), TARS_NAME, llm)
    _deploy_workflow(os.path.join(KIT, "workflows", "mother-daily-hunt.yaml"), MOTHER_NAME,
                     {**llm, "__KIBANA_URL__": public_kibana_url()})
    _enable_workflow(TARS_NAME)
    _enable_workflow(MOTHER_NAME)
    settings_body = {"workflowEnabled": True, "autoCloseEnabled": True,
                     "autoCloseConfidenceScoreMinThreshold": 0.7, "autoCloseConfidenceScoreMaxThreshold": 1,
                     "connectorId": ALERT_ANALYSIS_CONNECTOR, "agentId": "elastic-ai-agent",
                     "createConversation": True, "tagPrefix": "alert-analysis"}
    s, b = kb("PUT", "/internal/security_solution/alert_analysis_workflow/settings", settings_body, version="1")
    (ok if s == 200 else fail)(f"Alert analysis: enabled, auto-close ≥ 0.70, connector {ALERT_ANALYSIS_CONNECTOR} (HTTP {s})")
    s, b = kb("GET", f"/internal/security_solution/alert_analysis_workflow/rules?search={urllib.parse.quote(RDS_RULE)}",
              version="1")
    rule = next((r for r in (b.get("rules", []) if isinstance(b, dict) else []) if r["name"] == RDS_RULE), None)
    if not rule:
        fail(f"'{RDS_RULE}' not found for Alert analysis — run the rules phase first")
        return 1
    if rule.get("attached"):
        ok(f"Alert analysis attached to '{RDS_RULE}'")
        return
    s, b = kb("POST", "/internal/security_solution/alert_analysis_workflow/rules/_update",
              {"attachRuleIds": [rule["id"]]}, version="1")
    (ok if s == 200 else fail)(f"Alert analysis attached to '{RDS_RULE}' (HTTP {s})")


def cases():
    """The case template (SOC playbook) and the custom observable types."""
    py("case_setup.py")


def roles():
    """elasticon-attendee (no isolate) and elasticon-facilitator."""
    py("create_roles.py")


def fp_history():
    """The known-false-positive corpus: one real RDS export alert, closed, cloned onto 28 prior nights."""
    s, b = es("POST", f"/{ALERTS}/_count",
              {"query": {"bool": {"filter": [{"term": {"kibana.alert.rule.name": RDS_RULE}},
                                             {"term": {"kibana.alert.workflow_status": "closed"}}]}}})
    if s == 200 and b.get("count", 0) >= 20:
        ok(f"{b['count']} closed RDS export alerts already present")
        return
    py("fp_rds_export.py", "--live")
    py("fp_rds_export.py", "--wait-alert")
    py("fp_rds_export.py", "--close-latest")
    py("fp_rds_export.py", "--history", "28")


def federation():
    """Start the S3 server inside the sandbox that will hold the GuardDuty archive (image pull happens now, in parallel)."""
    rc = run(sys.executable, os.path.join(SCRIPTS, "sandbox_s3.py"), "up", check=False)
    if rc:
        warn("no S3 server could be started: the GuardDuty step will load plain indices instead")


# ---------------------------------------------------------------- seed phases (every session)
def campaign():
    """The crown-jewel campaign relative to now, the ML relearn, and a wait until the rules fire."""
    py("crownjewel_seed.py", "--ml-reset", "--wait", os.environ.get("SEED_WAIT", "1500"))


def hunt():
    """MOTHER's overnight-hunt data (IOC watchlist + beacons), fresh inside her 24 h look-back."""
    py(os.path.join(GEN, "run.py"), "scenario", "axios_c2")


def guardduty():
    """Rebuild the GuardDuty archive around today's campaign, put it on the S3 server and wire ES|QL federation
    to it (no credentials). If that fails for any reason, load the same findings as plain indices."""
    rc = py("guardduty_seed.py", check=False)
    if rc == 0:
        rc = py("guardduty_seed.py", "--wire", check=False)
    if rc != 0:
        warn("federation over S3 did not work: loading the findings as plain indices (queries are unchanged)")
        py("guardduty_seed.py", "--as-index")


def wiz_refresh():
    """Wiz misconfigurations expire ~26 h after seeding: refresh them every session."""
    py("wiz_seed.py", "--skip-install")


def verify():
    """The kit's own data checks, the lanes' state, and that TARS + MOTHER are on. Exit 0 = go."""
    rc = 0
    for lane, phases in LANES.items():
        names = [n for n, _ in phases if n != "check"]
        bad = [n for n in names if (read_state(n) or {}).get("status") != "done"]
        (ok if not bad else fail)(f"lane {lane}: {len(names) - len(bad)}/{len(names)} phases done"
                                  + (f" (not done: {', '.join(bad)})" if bad else ""))
        rc |= bool(bad)
    fired = run(sys.executable, "crownjewel_seed.py", "--status", check=False)
    for label, q in (
            ("GuardDuty findings readable", "FROM guardduty_findings | STATS n = COUNT(*)"),
            ("Wiz misconfigurations present", "FROM security_solution-wiz.misconfiguration_latest | STATS n = COUNT(*)"),
            ("MOTHER watchlist present", "FROM vgi-threat-intel | STATS n = COUNT(*)"),
            ("closed RDS false positives",
             f'FROM {ALERTS} | WHERE kibana.alert.rule.name == "AWS RDS Snapshot Export" '
             'AND kibana.alert.workflow_status == "closed" | STATS n = COUNT(*)')):
        s_, b = es("POST", "/_query", {"query": q})
        n = b["values"][0][0] if s_ == 200 and b.get("values") else 0
        (ok if n else fail)(f"{label}: {n}")
        rc |= not n
    for name in (TARS_NAME, MOTHER_NAME):
        w = _find_workflow(name)
        (ok if w and w.get("enabled") else fail)(f"{name.split(' — ')[0]} {'enabled' if w and w.get('enabled') else 'missing or DISABLED'}")
        rc |= not (w and w.get("enabled"))
    return rc or fired


def status():
    """Phase table from .state/ (what the track's scripts poll)."""
    names = [n for lane in LANES.values() for n, _ in lane if n != "check"]
    now = time.time()
    print(f"{'phase':<14}{'lane':<10}{'status':<10}{'minutes':>8}")
    for lane, phases in LANES.items():
        for n, _ in phases:
            if n == "check":
                continue
            st = read_state(n) or {}
            t0, t1 = st.get("started"), st.get("finished")
            mins = f"{((t1 or now) - t0) / 60:.1f}" if t0 and st.get("status") in ("running", "done", "failed") else ""
            print(f"{n:<14}{lane:<10}{st.get('status', '-'):<10}{mins:>8}" + (f"  {st['error']}" if st.get("error") else ""))
    done = sum((read_state(n) or {}).get("status") == "done" for n in names)
    print(f"\n{done}/{len(names)} phases done")
    return 0 if done == len(names) else 1


# ---------------------------------------------------------------- lanes
# Two lanes run at the same time. The pipeline lane builds the data and detections; the agentic lane
# builds everything that talks to an LLM or reads the data. A phase listed in NEEDS waits for others.
LANES = {
    "pipeline": [("check", check), ("settings", settings), ("integrations", integrations), ("templates", templates),
                 ("entity", entity), ("baseline", baseline), ("rules", rules), ("ml", ml),
                 ("campaign", campaign), ("hunt", hunt), ("fp-history", fp_history), ("guardduty", guardduty)],
    "agentic": [("llm", llm), ("cases", cases), ("roles", roles), ("federation", federation),
                ("exposure", exposure), ("agent", agent), ("workflows", workflows)],
}
NEEDS = {
    "exposure": ["integrations"],            # both install Fleet packages: don't do it at the same time
    "agent": ["baseline", "exposure"],       # tools reference the data streams + the exposure lookup index
    "workflows": ["llm", "rules"],           # Alert analysis attaches to a rule
    "guardduty": ["campaign", "federation"], # the archive is pinned to the seeded CloudTrail events
    "fp-history": ["rules"],
}
SEED = [("check", check), ("campaign", campaign), ("hunt", hunt), ("guardduty", guardduty), ("wiz-refresh", wiz_refresh)]
GROUPS = {"check": [("check", check)], **LANES, "seed": SEED, "verify": [("verify", verify)], "status": [("status", status)]}


def run_phases(phases, skip_done=False):
    """skip_done: resume a lane. Phases already marked done are not repeated (re-running `campaign` would reseed the attack)."""
    rc = 0
    for n, f in phases:
        t = time.time()
        if skip_done and (read_state(n) or {}).get("status") == "done":
            print(f"\n\033[1m▶ {n}\033[0m — already done, skipping", flush=True)
            continue
        print(f"\n\033[1m▶ {n}\033[0m — {(f.__doc__ or '').strip().splitlines()[0]}", flush=True)
        if n in PREPARED and (read_state(n) or {}).get("status") == "done" and os.geteuid() != 0:
            print("  ✅ prepared by the sandbox setup (it needs root); nothing to do")
            continue
        if n in NEEDS:
            wait_for(*NEEDS[n])
        mark(n, "running", started=t, error="")
        try:
            r = f()
        except SystemExit as e:
            mark(n, "failed", finished=time.time(), error=str(e.code)[:300])
            raise
        mark(n, "failed" if r else "done", finished=time.time(), error="returned non-zero" if r else "")
        print(f"  ({time.time() - t:.0f} s)")
        rc = r or rc
    return rc


def load():
    """Both lanes at once in the foreground (start.sh runs them as two background units instead)."""
    log = os.path.join(STATE_DIR, "agentic.log")
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(log, "w") as lf:
        child = subprocess.Popen([sys.executable, os.path.join(KIT, "deploy.py"), "agentic"],
                                 stdout=lf, stderr=subprocess.STDOUT, env=os.environ)
        rc = run_phases(LANES["pipeline"], skip_done=True)
        rc = child.wait() or rc
    print(f"(agentic lane log: {log})")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("group", nargs="?", choices=[*GROUPS, "load"], default="check")
    ap.add_argument("--only", help="run just this phase of the group")
    ap.add_argument("--from", dest="start", help="resume the group from this phase")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for g in ("pipeline", "agentic", "seed", "verify"):
            print(f"\n{g}:")
            for n, f in GROUPS[g]:
                print(f"  {n:<13} {(f.__doc__ or '').strip().splitlines()[0]}")
        return 0
    if a.group == "load":
        return load()
    if a.group == "status":
        return status()
    phases = GROUPS[a.group]
    names = [n for n, _ in phases]
    if a.only:
        if a.only not in names:
            sys.exit(f"--only {a.only}: not a phase of {a.group} ({', '.join(names)})")
        phases = [p for p in phases if p[0] == a.only]
    elif a.start:
        if a.start not in names:
            sys.exit(f"--from {a.start}: not a phase of {a.group} ({', '.join(names)})")
        phases = phases[names.index(a.start):]
    print(f"Target: {KB or '(KIBANA_URL not set)'}  (space: {SPACE})")
    if a.group in ("check", "verify"):
        return phases[0][1]() or 0
    rc = run_phases(phases, skip_done=(a.group in LANES and not a.only and not a.start))
    if a.group == "seed":
        print("\nNext: python3 deploy.py verify")
    return rc


if __name__ == "__main__":
    sys.exit(main())

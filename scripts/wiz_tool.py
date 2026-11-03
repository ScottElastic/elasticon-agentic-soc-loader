#!/usr/bin/env python3
"""ElastiCon Workstream 1 — GLaDOS tool `vgi.asset.exposure` (Wiz asset exposure).

Creates/updates one Agent Builder ES|QL tool that answers "what was already wrong with this
host before the attacker showed up?" — open Wiz vulnerabilities + FAILED cloud-configuration
checks for a single host, worst-first, with fixed versions and exploit/KEV flags — then
attaches it to agent `vgi-glados` (GLaDOS) WITHOUT touching her other tools.

Same pattern as elasticon_tools.py (POST, PUT on conflict). Idempotent.
Requires wiz_seed.py to have run (reads security_solution-wiz.*_latest).

Env: KIBANA_URL, KIBANA_API_KEY (or ELASTICSEARCH_API_KEY).
    python3 wiz_tool.py            # create/update tool + attach to GLaDOS
    python3 wiz_tool.py --remove   # detach from GLaDOS and delete the tool
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
API_KEY = os.environ.get("KIBANA_API_KEY", "") or os.environ.get("ELASTICSEARCH_API_KEY", "")
AGENT_ID = "vgi-glados"
TOOL_ID = "vgi.asset.exposure"

QUERY = """FROM security_solution-wiz.vulnerability_latest*, security_solution-wiz.misconfiguration_latest*
| WHERE host.name == ?host_name
| EVAL finding_type = CASE(vulnerability.id IS NOT NULL, "VULNERABILITY", "MISCONFIGURATION"),
       finding = COALESCE(vulnerability.id, rule.id),
       title = COALESCE(vulnerability.description, rule.name),
       severity = COALESCE(vulnerability.severity, "FAILED_CHECK"),
       evidence = COALESCE(CONCAT(package.name, " ", package.version), result.evidence.current_value),
       fix = COALESCE(package.fixed_version, rule.remediation),
       cvss = ROUND(vulnerability.score.base, 1),
       epss_probability = ROUND(wiz.vulnerability.epss.probability, 4),
       has_public_exploit = wiz.vulnerability.has_exploit,
       in_cisa_kev = wiz.vulnerability.has_cisa_kev_exploit
| WHERE finding_type == "VULNERABILITY" OR result.evaluation == "failed"
| EVAL weaponised = CASE(has_public_exploit == true OR in_cisa_kev == true, 1, 0),
       sev_rank = CASE(severity == "CRITICAL", 4, severity == "HIGH", 3,
                       severity == "FAILED_CHECK", 3, severity == "MEDIUM", 2, 1)
| SORT weaponised DESC, sev_rank DESC, epss_probability DESC NULLS LAST, cvss DESC NULLS LAST
| KEEP finding_type, finding, severity, cvss, epss_probability, has_public_exploit,
       in_cisa_kev, evidence, fix, title
| LIMIT 25"""

TOOL = {
    "id": TOOL_ID,
    "type": "esql",
    "description": (
        "Wiz asset exposure for ONE host: every open vulnerability plus every FAILED cloud "
        "configuration check on that machine, sorted worst-first (public exploit or CISA KEV "
        "first, then severity, then EPSS probability, then CVSS). Returns finding_type "
        "(VULNERABILITY|MISCONFIGURATION), finding (CVE id or Wiz rule id such as EC2-013), "
        "severity, cvss, epss_probability, has_public_exploit, in_cisa_kev, evidence (vulnerable "
        "package+version, or the actual misconfigured value, e.g. '0.0.0.0/0:22' or "
        "'PasswordAuthentication yes'), fix (fixed package version or remediation), and title. "
        "Use this to answer 'was this host actually vulnerable to what happened to it?' — match "
        "the attacker's technique in the alerts to the pre-existing exposure (e.g. an SSH brute "
        "force against a host whose Wiz findings show SSH open to 0.0.0.0/0, password "
        "authentication enabled and an exploitable OpenSSH CVE). Data comes from the Wiz "
        "integration's latest-finding indices. Params: host_name (exact lowercase host.name, "
        "e.g. 'gridvault-usw2-01')."
    ),
    "tags": ["vgi", "wiz", "vulnerability", "cloud-posture", "exposure", "elasticon"],
    "configuration": {
        "query": QUERY,
        "params": {
            "host_name": {
                "type": "string",
                "description": "Exact host.name (lowercase), e.g. 'gridvault-usw2-01'.",
            }
        },
    },
}


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(KIBANA_URL + path, data=data, method=method)
    r.add_header("Authorization", f"ApiKey {API_KEY}")
    r.add_header("kbn-xsrf", "true")
    r.add_header("x-elastic-internal-origin", "Kibana")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r) as resp:
            txt = resp.read().decode()
            return resp.status, (json.loads(txt) if txt.strip() else {})
    except urllib.error.HTTPError as e:
        txt = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, txt


def set_agent_tools(mutate):
    """Read GLaDOS's tool list, mutate it, write it back. Never drops existing tools."""
    s, agent = req("GET", f"/api/agent_builder/agents/{AGENT_ID}")
    if s != 200:
        sys.exit(f"ERROR: GET agent {AGENT_ID} -> {s} {str(agent)[:300]}")
    groups = agent.get("configuration", {}).get("tools", [])
    ids = list(groups[0].get("tool_ids", [])) if groups else []
    before = list(ids)
    ids = mutate(ids)
    if ids == before:
        print(f"OK  agent {AGENT_ID} already correct ({len(ids)} tools)")
        return
    body = {"configuration": {**agent.get("configuration", {}), "tools": [{"tool_ids": ids}]}}
    for k in ("name", "description", "labels", "avatar_color", "avatar_symbol"):
        if agent.get(k) is not None:
            body[k] = agent[k]
    s, b = req("PUT", f"/api/agent_builder/agents/{AGENT_ID}", body)
    print(f"{'OK ' if s == 200 else 'ERR'} agent {AGENT_ID} tools {len(before)} -> {len(ids)} (http {s})")
    if s != 200:
        print("   ", str(b)[:500], file=sys.stderr)


def main():
    if not KIBANA_URL or not API_KEY:
        sys.exit("ERROR: set KIBANA_URL and KIBANA_API_KEY")
    if "--remove" in sys.argv:
        set_agent_tools(lambda ids: [i for i in ids if i != TOOL_ID])
        s, _ = req("DELETE", f"/api/agent_builder/tools/{TOOL_ID}")
        print(f"OK  deleted tool {TOOL_ID} (http {s})")
        return
    s, b = req("POST", "/api/agent_builder/tools", TOOL)
    action = "created"
    if s in (400, 409) and "already exists" in str(b):
        s, b = req("PUT", f"/api/agent_builder/tools/{TOOL_ID}",
                   {k: TOOL[k] for k in ("description", "tags", "configuration")})
        action = "updated"
    print(f"{'OK ' if s in (200, 201) else 'ERR'} {s} {action} {TOOL_ID}")
    if s not in (200, 201):
        print("   ", str(b)[:700], file=sys.stderr)
        sys.exit(1)
    set_agent_tools(lambda ids: ids if TOOL_ID in ids else ids + [TOOL_ID])


if __name__ == "__main__":
    main()

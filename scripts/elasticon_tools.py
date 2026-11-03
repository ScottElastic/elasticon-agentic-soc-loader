#!/usr/bin/env python3
"""ElastiCon workshop — cross-domain Agent Builder tools that make GLaDOS investigate the WHOLE
VGI estate, not just AWS. These are the "one platform, one query" wow: give GLaDOS an IP, a host,
or an identity and she pivots across every data source at once.

Adds three ES|QL tools:
  vgi.correlate.by_ip     — every dataset/host/user a source or destination IP touched (the
                            cross-domain kill-chain pivot — the money query).
  vgi.host.investigation  — recent activity on a host across process/network/auth/endpoint/k8s.
  vgi.identity.timeline   — everything an identity did across cloud, host, and container logs.

Run AFTER agents/create_aws_tools.py. Then run reskin_glados.py to wire them onto GLaDOS.
Env: KIBANA_URL, ELASTICSEARCH_API_KEY. Idempotent (POST, PUT-on-conflict).
"""
from __future__ import annotations
import json, os, sys, urllib.error, urllib.request

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
API_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "") or os.environ.get("KIBANA_API_KEY", "")
WINDOW = "NOW() - 14 days"

TOOLS = [
    {
        "id": "vgi.correlate.by_ip",
        "type": "esql",
        "description": (
            "THE cross-domain pivot. Given one IP address, return every Elastic data source it "
            "appears in over the last 14 days — CloudTrail, WAF, Palo Alto firewall, Kubernetes "
            "audit, system auth/SSH, CrowdStrike, and Elastic Defend endpoint — rolled up per "
            "dataset with event counts, time span, and the hosts/users/actions it touched. This is "
            "how you prove a single attacker IP walked the whole kill chain across otherwise "
            "separate tools. Run it on the alert's source IP. Params: ip (e.g. '203.0.113.66')."
        ),
        "tags": ["vgi", "correlation", "cross-domain", "elasticon"],
        "configuration": {
            "query": (
                "FROM logs-*\n"
                f"| WHERE (source.ip == ?ip OR destination.ip == ?ip) AND `@timestamp` > {WINDOW}\n"
                "| STATS events = COUNT(*), first_seen = MIN(`@timestamp`), last_seen = MAX(`@timestamp`),\n"
                "        actions = VALUES(event.action), hosts = VALUES(host.name),\n"
                "        users = VALUES(user.name)\n"
                "  BY data_stream.dataset\n"
                "| SORT events DESC\n"
                "| LIMIT 50"
            ),
            "params": {"ip": {"type": "string", "description": "IP address to correlate across all data sources, e.g. '203.0.113.66'."}},
        },
    },
    {
        "id": "vgi.host.investigation",
        "type": "esql",
        "description": (
            "Investigate one host across every data source in the last 14 days — process, network, "
            "authentication, Kubernetes, CrowdStrike FDR, and Elastic Defend endpoint events — "
            "rolled up per dataset and event category with counts, time span, the users seen, the "
            "processes run, and the destination IPs contacted. Use to answer 'what happened on this "
            "machine?'. Params: host (exact host.name, e.g. 'gridvault-usw2-01')."
        ),
        "tags": ["vgi", "endpoint", "host", "elasticon"],
        "configuration": {
            "query": (
                "FROM logs-*\n"
                f"| WHERE host.name == ?host AND `@timestamp` > {WINDOW}\n"
                "| STATS events = COUNT(*), first_seen = MIN(`@timestamp`), last_seen = MAX(`@timestamp`),\n"
                "        users = VALUES(user.name), processes = VALUES(process.name),\n"
                "        dst_ips = VALUES(destination.ip), actions = VALUES(event.action)\n"
                "  BY data_stream.dataset, event.category\n"
                "| SORT events DESC\n"
                "| LIMIT 60"
            ),
            "params": {"host": {"type": "string", "description": "Exact host.name, e.g. 'gridvault-usw2-01'."}},
        },
    },
    {
        "id": "vgi.identity.timeline",
        "type": "esql",
        "description": (
            "Trace one identity across the whole estate in the last 14 days — cloud (CloudTrail), "
            "host (SSH/auth), and container (Kubernetes audit) activity for a single user name, "
            "rolled up per dataset and action with counts, time span, source IPs, and hosts touched. "
            "Use for insider or compromised-credential triage where the same name shows up in more "
            "than one place. Params: user (exact user.name, e.g. 'v.fries')."
        ),
        "tags": ["vgi", "identity", "cross-domain", "elasticon"],
        "configuration": {
            "query": (
                "FROM logs-*\n"
                f"| WHERE user.name == ?user AND `@timestamp` > {WINDOW}\n"
                "| STATS events = COUNT(*), first_seen = MIN(`@timestamp`), last_seen = MAX(`@timestamp`),\n"
                "        source_ips = VALUES(source.ip), hosts = VALUES(host.name)\n"
                "  BY data_stream.dataset, event.action\n"
                "| SORT events DESC\n"
                "| LIMIT 100"
            ),
            "params": {"user": {"type": "string", "description": "Exact user.name, e.g. 'v.fries'."}},
        },
    },
]


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(KIBANA_URL + path, data=data, method=method)
    r.add_header("Authorization", f"ApiKey {API_KEY}")
    r.add_header("kbn-xsrf", "true")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    if not KIBANA_URL or not API_KEY:
        sys.exit("ERROR: set KIBANA_URL and ELASTICSEARCH_API_KEY")
    for t in TOOLS:
        s, b = req("POST", "/api/agent_builder/tools", t)
        action = "created"
        if s == 400 and "already exists" in str(b):
            upd = {k: t[k] for k in ("description", "tags", "configuration")}
            s, b = req("PUT", f"/api/agent_builder/tools/{t['id']}", upd)
            action = "updated"
        ok = s in (200, 201)
        print(f"{'OK ' if ok else 'ERR'} {s}  {action} {t['id']}")
        if not ok:
            print("   ", str(b)[:600], file=sys.stderr)


if __name__ == "__main__":
    main()

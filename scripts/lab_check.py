#!/usr/bin/env python3
"""Per-lab checks for the Instruqt track.

    python3 scripts/lab_check.py env labN [--wait MINUTES]   is the data this lab relies on loaded?
    python3 scripts/lab_check.py learner labN                did the learner do what the lab asks?

`env` is what a challenge's setup script runs so a learner never starts a lab whose data is missing.
`learner` is what the Check button runs. Both exit 0 on success and print one line per assertion.
Needs `source env.sh` (ELASTICSEARCH_URL, KIBANA_URL, ELASTICSEARCH_API_KEY, SSL_CERT_FILE).

The environment checks are the guide's own smoke-test assertions (guide_check.py), reduced to what each
lab needs. They assert facts about the seeded data, never about the UI.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ES = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
KB = os.environ.get("KIBANA_URL", "").rstrip("/")
KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")
ALERTS = ".alerts-security.alerts-default"
HERO = "gridvault-usw2-01"
ATTACKER = "203.0.113.66"
CASE_SEARCH = "Crown jewel"
TARS, MOTHER = "TARS", "MOTHER"


def _req(base, method, path, body=None, version=None, timeout=120):
    h = {"Authorization": f"ApiKey {KEY}", "Content-Type": "application/json", "kbn-xsrf": "true",
         "x-elastic-internal-origin": "Kibana"}
    if version:
        h["elastic-api-version"] = version
    r = urllib.request.Request(base + path, method=method, headers=h,
                               data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:400]
    except Exception as e:                                         # noqa: BLE001
        return 0, str(e)


def es(m, p, b=None, **k):
    return _req(ES, m, p, b, **k)


def kb(m, p, b=None, **k):
    return _req(KB, m, p, b, **k)


def esql(query, window="now-24h"):
    body = {"query": query}
    if window:
        body["filter"] = {"range": {"@timestamp": {"gte": window}}}
    s, r = es("POST", "/_query", body)
    if s != 200 or not isinstance(r, dict):
        raise AssertionError(f"ES|QL failed (HTTP {s}): {str(r)[:200]}")
    cols = [c["name"] for c in r["columns"]]
    return [dict(zip(cols, v)) for v in r["values"]]


def alerts(where):
    return esql(f"FROM {ALERTS} METADATA _id | WHERE {where} | KEEP _id, kibana.alert.rule.name, kibana.alert.severity | LIMIT 200")


# ---------------------------------------------------------------- environment checks
ENV = {}


def env_check(name):
    def deco(fn):
        ENV[name] = fn
        return fn
    return deco


@env_check("alerts on the Wall")
def _():
    rows = alerts("kibana.alert.building_block_type IS NULL")
    assert len(rows) >= 15, f"only {len(rows)} visible alerts in the last 24 h (the rules may still be firing)"
    return f"{len(rows)} visible alerts"


@env_check("starting alert on the crown jewel")
def _():
    rows = alerts(f'host.name == "{HERO}" AND kibana.alert.rule.name == "Potential Successful SSH Brute Force Attack" '
                  "AND kibana.alert.building_block_type IS NULL")
    assert len(rows) == 1, f"expected 1 'Potential Successful SSH Brute Force Attack' alert, found {len(rows)}"
    return "Potential Successful SSH Brute Force Attack present"


@env_check("crown-jewel criticality")
def _():
    s, b = kb("GET", f"/api/asset_criticality?id_field=host.name&id_value={HERO}")
    assert s == 200 and b.get("criticality_level") == "extreme_impact", f"asset criticality: HTTP {s} {str(b)[:100]}"
    return "extreme_impact"


@env_check("case template")
def _():
    s, b = kb("GET", "/internal/cases/templates?owner=securitySolution")
    names = [t.get("name") for t in (b.get("templates", []) if isinstance(b, dict) else [])]
    assert any("Crown jewel investigation" in (n or "") for n in names), f"template missing (have {names})"
    return "VGI — Crown jewel investigation"


@env_check("LLM connectors")
def _():
    s, c = kb("GET", "/api/actions/connectors")
    ids = {x.get("id") for x in c} if s == 200 and isinstance(c, list) else set()
    assert {"vgi-opus", "vgi-sonnet"} <= ids, f"connectors present: {sorted(i for i in ids if str(i).startswith('vgi'))}"
    return "vgi-opus, vgi-sonnet"


@env_check("ES|QL COMPLETION endpoint")
def _():
    s, r = es("GET", "/_inference/completion/vgi-completion")
    assert s == 200, f"inference endpoint vgi-completion: HTTP {s}"
    return "vgi-completion"


@env_check("auth logs for the hero host (30 days)")
def _():
    rows = esql(f'FROM logs-system.auth-* | WHERE host.name == "{HERO}" | STATS n = COUNT(*)', window="now-30d")
    assert rows and rows[0]["n"] > 50, f"{rows}"
    return f"{rows[0]['n']} auth events"


@env_check("machine-learning alert")
def _():
    rows = alerts(f'host.name == "{HERO}" AND kibana.alert.rule.type == "machine_learning"')
    assert rows, "no ML alert on the hero host yet (the jobs relearn after seeding)"
    return f"{len(rows)} ML alert(s)"


@env_check("asset exposure lookup")
def _():
    rows = esql(f'FROM vgi-asset-exposure | WHERE host.name == "{HERO}" | STATS n = COUNT(*)', window=None)
    assert rows and rows[0]["n"] >= 1, "vgi-asset-exposure has no row for the hero host"
    return "vgi-asset-exposure"


@env_check("Kubernetes secret read")
def _():
    rows = esql('FROM logs-kubernetes.audit_logs-* | WHERE kubernetes.audit.objectRef.name == "gridvault-deploy-ssh" '
                "| STATS n = COUNT(*)")
    assert rows and rows[0]["n"] >= 1, "no kubernetes audit event for the stolen secret"
    return "gridvault-deploy-ssh read"


@env_check("GuardDuty archive (federation)")
def _():
    rows = esql("FROM guardduty_findings | STATS n = COUNT(*)", window=None)
    assert rows and rows[0]["n"] > 0, "guardduty_findings is empty"
    return f"{rows[0]['n']} findings"


@env_check("GLaDOS agent")
def _():
    s, a = kb("GET", "/api/agent_builder/agents/vgi-glados")
    n = sum(len(t.get("tool_ids", [])) for t in a.get("configuration", {}).get("tools", [])) if s == 200 else 0
    assert s == 200 and n >= 10, f"agent vgi-glados: HTTP {s}, {n} tools"
    return f"{n} tools"


@env_check("competing lead 1 (endpoint)")
def _():
    rows = esql('FROM .alerts-security.alerts-default | WHERE host.name == "elasticon" | STATS n = COUNT(*)', window="now-7d")
    assert rows and rows[0]["n"] >= 1, "no alert on the competing-lead host in 7 days"
    return "alert on host elasticon"


@env_check("closed RDS false-positive history")
def _():
    rows = esql('FROM .alerts-security.alerts-default | WHERE kibana.alert.rule.name == "AWS RDS Snapshot Export" '
                'AND kibana.alert.workflow_status == "closed" | STATS n = COUNT(*)', window="now-30d")
    assert rows and rows[0]["n"] >= 20, f"{rows}: the Alert analysis corpus is incomplete"
    return f"{rows[0]['n']} closed alerts"


@env_check("TARS enabled (MOTHER when the version supports her)")
def _():
    s, wl = kb("GET", "/api/workflows?size=100")
    res = wl.get("results", []) if s == 200 and isinstance(wl, dict) else []
    by = {w["name"].split(" ")[0]: w for w in res}
    assert by.get(TARS, {}).get("enabled"), f"TARS is not enabled: {sorted(by)}"
    m = by.get(MOTHER, {})
    if m.get("enabled"):
        return "TARS and MOTHER enabled"
    # MOTHER uses the `ai.agent` step (newer than 9.5.x): not a blocker, the labs that need her say so.
    return f"TARS enabled; MOTHER is NOT (valid={m.get('valid')}): needs a newer Elastic version"


LAB_ENV = {
    "lab1": ["alerts on the Wall", "starting alert on the crown jewel", "crown-jewel criticality", "case template", "LLM connectors"],
    "lab2": ["auth logs for the hero host (30 days)", "machine-learning alert", "asset exposure lookup", "ES|QL COMPLETION endpoint"],
    "lab3": ["Kubernetes secret read", "GuardDuty archive (federation)", "LLM connectors"],
    "lab4": ["GLaDOS agent", "competing lead 1 (endpoint)", "closed RDS false-positive history"],
    "lab5": ["TARS enabled (MOTHER when the version supports her)", "closed RDS false-positive history"],
}


# ---------------------------------------------------------------- learner checks (the Check button)
def find_case(search=CASE_SEARCH):
    q = urllib.parse.urlencode({"search": search, "searchFields": "title", "perPage": 20, "sortField": "createdAt", "sortOrder": "desc"})
    s, b = kb("GET", f"/api/cases/_find?{q}")
    cases = b.get("cases", []) if s == 200 and isinstance(b, dict) else []
    return next((c for c in cases if "DRILL" not in c.get("title", "")), None)


def learner_lab1():
    c = find_case()
    assert c, "I can't find your case. In Alerts, click Take action → Add to case → Create case, and put 'Crown jewel' in the name."
    assert c.get("totalAlerts", 0) >= 1, f"Your case '{c['title']}' has no alert attached yet. Use Take action → Add to case on the brute-force alert."
    return f"case '{c['title']}' with {c['totalAlerts']} alert(s)"


def learner_lab2():
    c = find_case()
    assert c, "your Crown jewel case is missing; finish Triage first."
    assert c.get("totalComment", 0) >= 1, "Add your timeline to the case as a comment, as the checkpoint says."
    return f"{c['totalComment']} comment(s) on the case"


def learner_lab3():
    s, r = kb("GET", "/api/attack_discovery/_find?start=now-24h&end=now&per_page=50&sort_field=@timestamp&sort_order=desc")
    ds = r.get("data", []) if s == 200 and isinstance(r, dict) else []
    hero = [d for d in ds if HERO in json.dumps(d)]
    assert hero, "No attack discovery mentions the crown jewel yet. Open Attacks → Settings, pick the VGI Opus connector, then Save and run."
    c = find_case()
    assert c and c.get("totalAlerts", 0) >= 3, "Add the discovery to your case (its alerts should be attached)."
    return f"{len(hero)} discovery(ies) about {HERO}; case has {c['totalAlerts']} alerts"


def learner_lab4():
    c = find_case()
    assert c and c.get("totalComment", 0) >= 2, "Attach GLaDOS's findings to your case (Add to chat, then 'Attach this summary…'), then re-check."
    return f"{c['totalComment']} comments on the case"


def learner_lab5():
    """TARS ran: its [DRILL] case exists and carries both the host and the IP it was given."""
    drill = find_case("DRILL")
    assert drill, "Run the TARS workflow (Workflows → TARS → Run → Manual); it opens a [DRILL] case when it finishes."
    title = drill.get("title", "")
    assert HERO in title and ATTACKER in title, f"The [DRILL] case title is missing your inputs: '{title[:90]}'. Run TARS again with the host and IP filled in."
    return f"TARS ran; case '{title[:70]}'"


LEARNER = {"lab1": learner_lab1, "lab2": learner_lab2, "lab3": learner_lab3, "lab4": learner_lab4, "lab5": learner_lab5}


def run_env(lab, wait_min):
    deadline = time.time() + wait_min * 60
    while True:
        fails = []
        for name in LAB_ENV[lab]:
            try:
                print(f"  OK    {name}: {ENV[name]()}")
            except AssertionError as e:
                fails.append(name)
                print(f"  WAIT  {name}: {e}")
            except Exception as e:                                  # noqa: BLE001
                fails.append(name)
                print(f"  ERROR {name}: {e!r}")
        if not fails:
            return 0
        if time.time() > deadline:
            print(f"not ready after {wait_min} min: {', '.join(fails)}")
            return 1
        print(f"  … {len(fails)} not ready, retrying in 20 s")
        time.sleep(20)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["env", "learner"])
    ap.add_argument("lab", choices=sorted(LAB_ENV))
    ap.add_argument("--wait", type=float, default=0, help="env mode: keep retrying for this many minutes")
    a = ap.parse_args()
    if not (ES and KB and KEY):
        sys.exit("source env.sh first")
    if a.mode == "env":
        return run_env(a.lab, a.wait)
    try:
        print(LEARNER[a.lab]())
        return 0
    except AssertionError as e:
        print(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())

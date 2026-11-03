#!/usr/bin/env python3
"""Provision the VGI AWS Cloud Investigator — a custom Agent Builder agent specialized for
AWS/CloudTrail incident response, wired to the six custom vgi.aws.* ES|QL tools created by
create_aws_tools.py.

Run create_aws_tools.py FIRST (the agent references those tool ids).

Environment:
    KIBANA_URL             https://<project>.kb.<region>.aws.elastic.cloud
    ELASTICSEARCH_API_KEY  API key with Agent Builder privileges

Usage:
    python agents/create_aws_agent.py

Idempotent: PUT-updates the agent if it already exists, else POST-creates it.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
API_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")

AGENT_ID = "vgi-glados"

INSTRUCTIONS = """\
You are the **VGI AWS Cloud Investigator**, a senior cloud-incident-response analyst for Vandelay
Global Industries' AWS estate (the GridVault industrial-IoT platform). You specialize in AWS CloudTrail,
IAM, S3, and GuardDuty telemetry. You are invoked to triage a single AWS security alert and
return a decision-grade investigation, fast.

## Environment you work in
- AWS accounts: 847629103455 (prod), 291743806521 (dev). Region: us-west-2 (primary),
  eu-central-1. Data lands in Elastic data streams `logs-aws.cloudtrail-<namespace>` where
  namespace is one of prod_uswest, dev_uswest, prod_eucentral, prod_mfg (the manufacturing org
  that holds turbine IP).
- Known-legitimate automation user agents: aws-sdk-java, terraform, Boto3 from corporate
  egress (Schenectady, "Vandelay Global Industries Corp" ASN). Treat aws-cli/CloudShell from a hosting/VPN ASN
  (e.g. "Example Hosting B.V.", Amsterdam) as suspicious.
- Service accounts you will see: svc-t800-ci, svc-conan-deploy, svc-mfg-sync,
  svc-backup-usw2. Humans: v.fries, h.langston, j.kimble, d.quaid, j.slater.

## Your tools (call them — do not guess at data)
- `vgi.aws.actor_activity_profile` — ALWAYS run this first when an alert names an AWS actor.
  Pass actor (exact name) and actor_arn ('*'+actor+'*'). It gives the full blast radius.
- `vgi.aws.s3_data_access` — object-level S3 reads; the exfiltration signal. Watch
  distinct_objects vs. time span for bulk pulls.
- `vgi.aws.iam_changes` — persistence / priv-esc (CreateAccessKey, DeactivateMFA, ...). The
  actor_ne_target flag = keys minted for another principal.
- `vgi.aws.public_exposure_changes` — bucket/snapshot made public.
- `vgi.aws.defense_evasion` — StopLogging / DeleteTrail / DeleteDetector. If this returns rows,
  state loudly that downstream telemetry may be incomplete.
- `vgi.aws.console_login_risk` — Root logins, MFA-less logins, risky-ASN sign-ins.
- You may also use the built-in ES|QL tools to pivot to any field the custom tools don't cover.

## Method
1. Anchor on the alert's actor and/or source IP. Run actor_activity_profile first.
2. Follow the evidence across the kill-chain phases: initial access (console_login_risk) →
   discovery (S3 ListObjects) → collection/exfil (s3_data_access) → persistence/priv-esc
   (iam_changes) → defense evasion (defense_evasion) → public exposure.
3. Correlate by identity AND source IP — the same attacker IP often appears across namespaces
   and across both human and service-account identities.
4. Distinguish insider misuse (valid creds, off-hours, no MFA, bulk data pull) from external
   compromise (Root brute force, priv-esc, log tampering).

## Output contract — respond in EXACTLY this markdown structure, <= 350 words, no preamble:

**Verdict:** <TRUE POSITIVE | FALSE POSITIVE | NEEDS REVIEW> — one clause why.

**What happened (timeline):**
- chronological bullets, each: `HH:MM UTC — <actor> <action> -> <outcome/impact>`

**MITRE ATT&CK:** comma-separated technique IDs + names that the evidence supports.

**Scope & blast radius:**
- accounts / namespaces / buckets / identities touched, with the numbers you observed.

**IOCs:**
| Indicator | Type | Role |
|---|---|---|
(source IPs, IAM users, buckets, access keys)

**Recommended actions:** 3-5 imperative bullets, most urgent first.

Always ground every claim in a tool result. If a tool returns nothing, say so rather than
inventing activity. Never include a real person's data — this is a simulated POC environment.
"""

TOOL_IDS = [
    "vgi.aws.actor_activity_profile",
    "vgi.aws.s3_data_access",
    "vgi.aws.iam_changes",
    "vgi.aws.public_exposure_changes",
    "vgi.aws.defense_evasion",
    "vgi.aws.console_login_risk",
    "platform.core.generate_esql",
    "platform.core.execute_esql",
    "platform.core.search",
]

AGENT = {
    "id": AGENT_ID,
    "name": "VGI AWS Cloud Investigator",
    "description": (
        "AWS/CloudTrail incident-response specialist for Vandelay Global Industries's GridVault estate. Triages a "
        "single AWS alert into a decision-grade report using the custom vgi.aws.* ES|QL tools "
        "(actor profiling, S3 exfil, IAM persistence, public exposure, defense evasion, console "
        "login risk)."
    ),
    "labels": ["vgi", "aws", "security", "cloud-ir"],
    "configuration": {
        "instructions": INSTRUCTIONS,
        "tools": [{"tool_ids": TOOL_IDS}],
        "enable_elastic_capabilities": False,
    },
}


def req(method: str, path: str, body: dict | None = None):
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


def main() -> None:
    if not KIBANA_URL or not API_KEY:
        print("ERROR: set KIBANA_URL and ELASTICSEARCH_API_KEY env vars.", file=sys.stderr)
        sys.exit(1)

    status, _ = req("GET", f"/api/agent_builder/agents/{AGENT_ID}")
    if status == 200:
        upd = {k: AGENT[k] for k in ("name", "description", "labels", "configuration")}
        s, b = req("PUT", f"/api/agent_builder/agents/{AGENT_ID}", upd)
        action = "updated"
    else:
        s, b = req("POST", "/api/agent_builder/agents", AGENT)
        action = "created"

    ok = s in (200, 201)
    print(f"{'OK ' if ok else 'ERR'} {s}  {action} {AGENT_ID}")
    if not ok:
        print("   ", str(b)[:800], file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

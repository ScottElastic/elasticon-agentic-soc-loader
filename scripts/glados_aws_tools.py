#!/usr/bin/env python3
"""Provision the AWS-investigation custom ES|QL tools (Agent Builder "skills") on the
VGI Elastic Serverless cluster.

Each tool is a parameterized ES|QL query the VGI AWS Cloud Investigator agent can call by
name (see create_aws_agent.py). Running this is idempotent: it deletes any tool with the
same id first, then recreates it.

Environment:
    KIBANA_URL             https://<project>.kb.<region>.aws.elastic.cloud
    ELASTICSEARCH_API_KEY  API key with Agent Builder + ES privileges

Usage:
    python agents/create_aws_tools.py [--list]

Design note on the time window
------------------------------
ES|QL does not allow a bound parameter to be followed by a time unit
(`NOW() - ?p hours` is a parse error) nor to be multiplied by a duration, so the triage
window is baked in as `NOW() - 14 days`. That comfortably covers the live demo scenarios
(which anchor their storyline clock to "now") without asking the agent to compute
timestamps. Widen it here if you seed longer histories.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
API_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")

WINDOW = "NOW() - 14 days"


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


TOOLS = [
    {
        "id": "vgi.aws.actor_activity_profile",
        "type": "esql",
        "description": (
            "Profile ALL AWS CloudTrail activity for one IAM principal (user or role) over the last "
            "14 days. Returns a per-(service, action, outcome) rollup with event counts, failures, "
            "first/last seen, and the distinct source IPs, user agents, accounts, and namespaces the "
            "principal used. Use this FIRST when an alert names an AWS actor — it reveals the full "
            "blast radius of what that identity did. Params: actor (exact IAM user/role name, e.g. "
            "'v.fries'), actor_arn (an ARN LIKE pattern for the same principal, pass '*'+actor+'*')."
        ),
        "tags": ["vgi", "aws", "cloudtrail", "identity"],
        "configuration": {
            "query": (
                "FROM logs-aws.cloudtrail-*\n"
                "| WHERE (user.name == ?actor OR aws.cloudtrail.user_identity.arn LIKE ?actor_arn)\n"
                f"    AND `@timestamp` > {WINDOW}\n"
                "| EVAL failed = CASE(event.outcome == \"failure\", 1, 0)\n"
                "| STATS events = COUNT(*), failures = SUM(failed),\n"
                "        first_seen = MIN(`@timestamp`), last_seen = MAX(`@timestamp`),\n"
                "        source_ips = VALUES(source.ip), user_agents = VALUES(user_agent.name),\n"
                "        accounts = VALUES(cloud.account.id), namespaces = VALUES(data_stream.namespace)\n"
                "  BY event.provider, event.action, event.outcome\n"
                "| SORT events DESC\n"
                "| LIMIT 100"
            ),
            "params": {
                "actor": {"type": "string", "description": "Exact IAM user or role name, e.g. 'v.fries'."},
                "actor_arn": {"type": "string", "description": "IAM ARN LIKE pattern for the same principal, e.g. '*v.fries*'."},
            },
        },
    },
    {
        "id": "vgi.aws.s3_data_access",
        "type": "esql",
        "description": (
            "Surface S3 object-level access (GetObject/ListObjects/PutObject/CopyObject) attributed "
            "to an IAM principal over the last 14 days — the core signal for data-exfiltration "
            "triage. Parses the bucket and object key from the CloudTrail request parameters and "
            "rolls up per bucket/action/source-IP with event counts, distinct-object counts, time "
            "span, and sample object keys. A high distinct-object count in a short window = bulk "
            "pull. Params: actor (exact IAM user/role name)."
        ),
        "tags": ["vgi", "aws", "s3", "exfiltration"],
        "configuration": {
            "query": (
                "FROM logs-aws.cloudtrail-*\n"
                "| WHERE event.provider == \"s3.amazonaws.com\" AND user.name == ?actor\n"
                f"    AND `@timestamp` > {WINDOW}\n"
                "| GROK aws.cloudtrail.request_parameters \"\\\\{bucketName=%{DATA:bucket}[,}]\"\n"
                "| GROK aws.cloudtrail.request_parameters \"key=%{GREEDYDATA:object_key}\\\\}\"\n"
                "| STATS events = COUNT(*), first_seen = MIN(`@timestamp`), last_seen = MAX(`@timestamp`),\n"
                "        distinct_objects = COUNT_DISTINCT(object_key), sample_objects = VALUES(object_key)\n"
                "  BY bucket, event.action, source.ip, data_stream.namespace\n"
                "| SORT events DESC\n"
                "| LIMIT 50"
            ),
            "params": {
                "actor": {"type": "string", "description": "Exact IAM user or role name, e.g. 'v.fries'."},
            },
        },
    },
    {
        "id": "vgi.aws.iam_changes",
        "type": "esql",
        "description": (
            "List sensitive IAM mutations across all accounts in the last 14 days, in time order: "
            "CreateAccessKey, CreateUser, DeleteUser, AttachUserPolicy, PutUserPolicy, "
            "DeactivateMFADevice, UpdateAccessKey, CreateLoginProfile, AddUserToGroup. This is the "
            "persistence + privilege-escalation view. The computed field actor_ne_target flags "
            "CreateAccessKey/etc. where the actor acted on a DIFFERENT principal (keys minted for "
            "someone else) — a strong persistence indicator. No params."
        ),
        "tags": ["vgi", "aws", "iam", "persistence"],
        "configuration": {
            "query": (
                "FROM logs-aws.cloudtrail-*\n"
                "| WHERE event.provider == \"iam.amazonaws.com\"\n"
                "    AND event.action IN (\"CreateAccessKey\",\"CreateUser\",\"DeleteUser\",\"AttachUserPolicy\",\n"
                "                         \"PutUserPolicy\",\"DeactivateMFADevice\",\"UpdateAccessKey\",\n"
                "                         \"CreateLoginProfile\",\"AddUserToGroup\")\n"
                f"    AND `@timestamp` > {WINDOW}\n"
                "| EVAL actor_ne_target = CASE(user.target.name IS NOT NULL AND user.name != user.target.name, true, false)\n"
                "| KEEP `@timestamp`, event.action, event.outcome, user.name, user.target.name, actor_ne_target,\n"
                "       source.ip, source.geo.city_name, user_agent.original, cloud.account.id, data_stream.namespace\n"
                "| SORT `@timestamp` DESC\n"
                "| LIMIT 100"
            ),
            "params": {},
        },
    },
    {
        "id": "vgi.aws.public_exposure_changes",
        "type": "esql",
        "description": (
            "Detect resource-exposure changes over the last 14 days that make data or compute "
            "public: PutBucketPolicy, PutBucketAcl, DeleteBucketPolicy, PutBucketPublicAccessBlock, "
            "ModifySnapshotAttribute, ModifyImageAttribute. Parses the affected bucket name and "
            "keeps the raw request parameters so you can read the policy. Use to confirm whether an "
            "actor opened a bucket to the internet as part of an exfil chain. No params."
        ),
        "tags": ["vgi", "aws", "s3", "exposure"],
        "configuration": {
            "query": (
                "FROM logs-aws.cloudtrail-*\n"
                "| WHERE event.action IN (\"PutBucketPolicy\",\"PutBucketAcl\",\"DeleteBucketPolicy\",\n"
                "                         \"PutBucketPublicAccessBlock\",\"ModifySnapshotAttribute\",\"ModifyImageAttribute\")\n"
                f"    AND `@timestamp` > {WINDOW}\n"
                "| GROK aws.cloudtrail.request_parameters \"\\\\{bucketName=%{DATA:bucket}[,}]\"\n"
                "| KEEP `@timestamp`, event.action, event.outcome, user.name, source.ip, bucket,\n"
                "       aws.cloudtrail.request_parameters, cloud.account.id, data_stream.namespace\n"
                "| SORT `@timestamp` DESC\n"
                "| LIMIT 50"
            ),
            "params": {},
        },
    },
    {
        "id": "vgi.aws.defense_evasion",
        "type": "esql",
        "description": (
            "Find AWS logging/monitoring tamper events in the last 14 days — the attacker-covering-"
            "tracks signal: StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors (CloudTrail), "
            "DeleteDetector (GuardDuty), DeleteFlowLogs (VPC), DisableEbsEncryptionByDefault. "
            "Returns them in time order with actor ARN and source IP. Any hit means telemetry may be "
            "incomplete for the rest of the investigation — call it out explicitly. No params."
        ),
        "tags": ["vgi", "aws", "defense-evasion", "cloudtrail"],
        "configuration": {
            "query": (
                "FROM logs-aws.cloudtrail-*\n"
                "| WHERE event.action IN (\"StopLogging\",\"DeleteTrail\",\"UpdateTrail\",\"PutEventSelectors\",\n"
                "                         \"DeleteDetector\",\"DeleteFlowLogs\",\"DisableEbsEncryptionByDefault\")\n"
                f"    AND `@timestamp` > {WINDOW}\n"
                "| KEEP `@timestamp`, event.action, event.outcome, user.name,\n"
                "       aws.cloudtrail.user_identity.arn, source.ip, source.geo.city_name,\n"
                "       aws.cloudtrail.error_code, cloud.account.id, data_stream.namespace\n"
                "| SORT `@timestamp` DESC\n"
                "| LIMIT 50"
            ),
            "params": {},
        },
    },
    {
        "id": "vgi.aws.console_login_risk",
        "type": "esql",
        "description": (
            "Review AWS console sign-ins from the last 14 days with the risk signals a SOC cares "
            "about: outcome, identity type (Root is high-risk), whether MFA was used, and the source "
            "IP's city and ASN/org. Root logins, MFA-less logins, and sign-ins from hosting/VPN ASNs "
            "(e.g. 'Example Hosting B.V.') are the ones to escalate. Filters to one actor, OR always "
            "includes any Root login regardless. Params: actor (exact IAM user name, or '*' to "
            "return every principal's console logins)."
        ),
        "tags": ["vgi", "aws", "authentication", "cloudtrail"],
        "configuration": {
            "query": (
                "FROM logs-aws.cloudtrail-*\n"
                f"| WHERE event.action == \"ConsoleLogin\" AND `@timestamp` > {WINDOW}\n"
                "    AND (?actor == \"*\" OR user.name == ?actor OR aws.cloudtrail.user_identity.type == \"Root\")\n"
                "| EVAL mfa_used = aws.cloudtrail.console_login.additional_eventdata.mfa_used\n"
                "| KEEP `@timestamp`, event.outcome, aws.cloudtrail.user_identity.type, user.name, mfa_used,\n"
                "       source.ip, source.geo.city_name, source.as.organization.name, data_stream.namespace\n"
                "| SORT `@timestamp` DESC\n"
                "| LIMIT 50"
            ),
            "params": {
                "actor": {"type": "string", "description": "IAM user name to filter to, or '*' for all principals."},
            },
        },
    },
]

TOOL_IDS = [t["id"] for t in TOOLS]


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision VGI AWS investigation ES|QL tools")
    parser.add_argument("--list", action="store_true", help="List the tool ids this script manages and exit")
    args = parser.parse_args()

    if args.list:
        for tid in TOOL_IDS:
            print(tid)
        return

    if not KIBANA_URL or not API_KEY:
        print("ERROR: set KIBANA_URL and ELASTICSEARCH_API_KEY env vars.", file=sys.stderr)
        sys.exit(1)

    for t in TOOLS:
        status, body = req("POST", "/api/agent_builder/tools", t)
        action = "created"
        if status == 400 and "already exists" in str(body):
            # Update in place — PUT accepts the mutable fields (not the id).
            upd = {k: t[k] for k in ("description", "tags", "configuration") if k in t}
            status, body = req("PUT", f"/api/agent_builder/tools/{t['id']}", upd)
            action = "updated"
        ok = status in (200, 201)
        print(f"{'OK ' if ok else 'ERR'} {status}  {action} {t['id']}")
        if not ok:
            print("   ", str(body)[:600], file=sys.stderr)
            sys.exit(1)
    print(f"\nProvisioned {len(TOOLS)} tools.")


if __name__ == "__main__":
    main()

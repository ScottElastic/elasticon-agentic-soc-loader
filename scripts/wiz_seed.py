#!/usr/bin/env python3
"""ElastiCon Workstream 1 — Wiz asset exposure seeder ("Know Your Ground" / Cerebro).

What it does (all idempotent / re-runnable):
  1. installs the Fleet package `wiz` 4.8.0 (skips if already installed)
  2. purges any previously seeded sim docs, then bulk-writes RAW Wiz findings into
     logs-wiz.vulnerability-default and logs-wiz.cloud_configuration_finding_full_posture-default
     (raw shape = Wiz JSON as a string in `message`; the package pipeline parses it)
  3. starts + `_schedule_now`s the two package transforms and waits for the
     security_solution-wiz.*_latest rows to appear
  4. (re)builds the lookup-mode index `vgi-asset-exposure`, one row per host.name,
     aggregated from the *_latest indices + Entity Analytics asset criticality

Every seeded doc carries tag `vgi-sim` (VGI convention) and `labels.vgi_sim: true`,
so `--cleanup` removes exactly what this script created and nothing else. Ids are also
written to a local manifest (.wiz_seed_manifest.json) as a belt-and-braces record.

Usage:
    source <scratchpad>/env.sh
    python3 wiz_seed.py                 # install + seed + transforms + lookup index
    python3 wiz_seed.py --skip-install  # seed only
    python3 wiz_seed.py --lookup-only   # just rebuild vgi-asset-exposure
    python3 wiz_seed.py --simulate      # run one doc of each type through the pipeline, print ECS out
    python3 wiz_seed.py --cleanup       # delete seeded docs (+ lookup index) — leaves the package alone

GOTCHA: the misconfiguration transform has a 26h retention policy (and a now-26h source
window), so misconfiguration_latest rows EXPIRE ~26h after seeding. Re-run this script
within a day of the workshop. Vulnerabilities keep 90d.

Env: ELASTICSEARCH_URL, ELASTICSEARCH_API_KEY, KIBANA_URL, KIBANA_API_KEY
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ES = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
KB = os.environ.get("KIBANA_URL", "").rstrip("/")
ES_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")
KB_KEY = os.environ.get("KIBANA_API_KEY", "") or ES_KEY

SIM_TAG = "vgi-sim"
VULN_DS = "logs-wiz.vulnerability-default"
MISC_DS = "logs-wiz.cloud_configuration_finding_full_posture-default"
VULN_LATEST = "security_solution-wiz.vulnerability_latest"
MISC_LATEST = "security_solution-wiz.misconfiguration_latest"
TRANSFORMS = [
    "logs-wiz.latest_cdr_vulnerabilities-default-0.4.0",
    "logs-wiz.latest_cdr_misconfigurations-default-0.5.0",
]
LOOKUP_INDEX = "vgi-asset-exposure"
MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".wiz_seed_manifest.json")

ACCOUNT = "847629103455"
REGION = "us-west-2"
SUBSCRIPTION_ID = "6c3a1f92-8d44-4a1b-9a0c-2f7b5c8d1e04"
SUBSCRIPTION_NAME = "vgi-prod-usw2"
PROJECTS = [{"id": "e9f0c2a1-33b7-4f52-9d61-7a0c4b8e5d12", "name": "VGI Grid Platform",
             "slug": "vgi-grid-platform", "businessUnit": "Grid Operations",
             "riskProfile": {"businessImpact": "HBI"}}]

NOW = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


TS_NOW = iso(NOW)
TS_FIRST = iso(NOW - timedelta(days=34))
TS_SCAN = iso(NOW - timedelta(minutes=18))

# --------------------------------------------------------------------------------------
# Assets. asset name MUST equal host.name (pipeline lowercases vulnerableAsset.name ->
# host.name when type == VIRTUAL_MACHINE, and resource.name -> host.name for misconfigs).
# --------------------------------------------------------------------------------------
HOSTS = {
    "gridvault-usw2-01": {
        "host_id": "952da0c6-b625-5d91-a4eb-c6cd37d111fa",
        "wiz_id": "3c1f7a90-5d2e-44b8-9c07-1a6b2e8f4d51",
        "instance": "i-0b7c3e9a41d2f8e56",
        "ip": "10.32.14.21",
        "os": "Ubuntu 22.04.4 LTS",
        "tags": {"Name": "gridvault-usw2-01", "division": "grid",
                 "app": "gridvault-telemetry-db", "owner": "harry.tasker"},
        "exposed": True,
    },
    "gridvault-usw2-02": {
        "wiz_id": "8b42d6c1-91fe-4d33-a5b2-6c0e7f19a238",
        "instance": "i-0d41f8a2c7b95e310",
        "ip": "10.32.14.22",
        "os": "Ubuntu 22.04.4 LTS",
        "tags": {"Name": "gridvault-usw2-02", "division": "grid",
                 "app": "gridvault-telemetry-db", "owner": "harry.tasker"},
        "exposed": False,
    },
    "gridvault-usw2-03": {
        "wiz_id": "d70a5e34-2c88-4b61-8f9d-4e3b1c7a0956",
        "instance": "i-07e2b9d4a6c1f3852",
        "ip": "10.32.14.23",
        "os": "Ubuntu 22.04.4 LTS",
        "tags": {"Name": "gridvault-usw2-03", "division": "grid",
                 "app": "gridvault-telemetry-db", "owner": "harry.tasker"},
        "exposed": False,
    },
    "gridvault-bastion-usw2-01": {
        "wiz_id": "a15c93b7-6f40-4e2a-b8c5-93d7e0f21a46",
        "instance": "i-0a5d8c3b2e9f14760",
        "ip": "10.32.2.10",
        "os": "Amazon Linux 2023",
        "tags": {"Name": "gridvault-bastion-usw2-01", "division": "grid",
                 "app": "jump-host", "owner": "h.langston"},
        "exposed": False,
    },
    "ip-10-32-40-11.us-west-2.compute.internal": {
        "wiz_id": "f4e81207-b5a3-4c96-8d12-0b7e3a5c9f68",
        "instance": "i-0c9e4f7a1b3d6528e",
        "ip": "10.32.40.11",
        "os": "Amazon Linux 2 (EKS 1.29)",
        "tags": {"Name": "gridvault-eks-node", "division": "grid",
                 "app": "gridvault-eks-prod", "owner": "j.kimble",
                 "eks:cluster-name": "gridvault-eks-prod"},
        "exposed": False,
    },
}

# (cve, title, severity, score, package, version, fixed, has_exploit, kev,
#  epss_prob, epss_pct, exploitability, impact, validated_runtime)
VULNS = {
    "gridvault-usw2-01": [
        ("CVE-2024-6387",
         "OpenSSH regreSSHion: signal handler race condition in sshd allows unauthenticated "
         "remote code execution as root on glibc-based Linux systems.",
         "HIGH", 8.1, "openssh-server", "1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10",
         True, False, 0.9412, 0.9991, 2.2, 5.9, True),
        ("CVE-2025-1094",
         "PostgreSQL psql improper neutralization of quoting syntax allows SQL injection and "
         "shell metacharacter injection via crafted invalid byte sequences.",
         "HIGH", 8.1, "postgresql-14", "14.10-0ubuntu0.22.04.1", "14.17-0ubuntu0.22.04.1",
         False, True, 0.3078, 0.9724, 2.3, 5.8, True),
        ("CVE-2025-32463",
         "sudo chroot option local privilege escalation: a local user can load an attacker "
         "controlled /etc/nsswitch.conf and gain root.",
         "CRITICAL", 9.3, "sudo", "1.9.15p5-3ubuntu5", "1.9.17p1-1ubuntu1",
         True, False, 0.0621, 0.7206, 2.0, 6.0, False),
        ("CVE-2023-48795",
         "SSH Terrapin prefix truncation attack: the SSH transport protocol binding allows "
         "an MITM to downgrade connection security.",
         "MEDIUM", 5.9, "openssh-client", "1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10",
         False, False, 0.0084, 0.4130, 2.2, 3.6, False),
    ],
    "gridvault-usw2-02": [
        ("CVE-2023-48795",
         "SSH Terrapin prefix truncation attack allows an MITM to downgrade connection security.",
         "MEDIUM", 5.9, "openssh-client", "1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10",
         False, False, 0.0084, 0.4130, 2.2, 3.6, False),
        ("CVE-2024-45490",
         "libexpat XML_ParseBuffer accepts a negative length, leading to out-of-bounds access.",
         "MEDIUM", 6.5, "libexpat1", "2.4.7-1ubuntu0.2", "2.4.7-1ubuntu0.5",
         False, False, 0.0031, 0.2510, 1.8, 3.6, False),
        ("CVE-2024-33599",
         "glibc nscd fixed size stack buffer overflow in netgroup cache.",
         "LOW", 3.7, "libc-bin", "2.35-0ubuntu3.6", "2.35-0ubuntu3.8",
         False, False, 0.0009, 0.0812, 1.6, 2.5, False),
    ],
    "gridvault-usw2-03": [
        ("CVE-2023-48795",
         "SSH Terrapin prefix truncation attack allows an MITM to downgrade connection security.",
         "MEDIUM", 5.9, "openssh-client", "1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10",
         False, False, 0.0084, 0.4130, 2.2, 3.6, False),
        ("CVE-2024-2961",
         "glibc iconv ISO-2022-CN-EXT out-of-bounds write, reachable from some applications.",
         "HIGH", 7.3, "libc-bin", "2.35-0ubuntu3.6", "2.35-0ubuntu3.8",
         False, False, 0.0142, 0.5920, 1.6, 4.7, False),
    ],
    "gridvault-bastion-usw2-01": [
        ("CVE-2024-7589",
         "OpenSSH sshd privilege escalation in the sandbox: a signal handler calls a logging "
         "function that is not async-signal-safe.",
         "HIGH", 7.4, "openssh-server", "9.6p1-1.amzn2023", "9.8p1-1.amzn2023",
         False, False, 0.0202, 0.6031, 1.6, 5.9, False),
        ("CVE-2023-48795",
         "SSH Terrapin prefix truncation attack allows an MITM to downgrade connection security.",
         "MEDIUM", 5.9, "openssh-clients", "9.6p1-1.amzn2023", "9.8p1-1.amzn2023",
         False, False, 0.0084, 0.4130, 2.2, 3.6, False),
    ],
    "ip-10-32-40-11.us-west-2.compute.internal": [
        ("CVE-2024-21626",
         "runc container breakout via internal file descriptor leak (Leaky Vessels): a "
         "malicious image or process.cwd can escape to the host filesystem.",
         "HIGH", 8.6, "runc", "1.1.7-1.amzn2", "1.1.12-1.amzn2",
         True, False, 0.0491, 0.6884, 2.0, 5.9, False),
        ("CVE-2023-48795",
         "SSH Terrapin prefix truncation attack allows an MITM to downgrade connection security.",
         "MEDIUM", 5.9, "openssh-clients", "8.7p1-3.amzn2", "8.7p1-4.amzn2",
         False, False, 0.0084, 0.4130, 2.2, 3.6, False),
    ],
}

# short_id -> (rule uuid, name, description, remediation, config path, expected value)
RULES = {
    "EC2-013": ("1f2c9a04-7d63-4b58-9a41-0c6e3b7f5d20",
                "EC2 instance should not allow inbound SSH (port 22) from 0.0.0.0/0",
                "Security groups attached to the instance must not permit TCP/22 from any IPv4 address.",
                "Restrict the security group rule for TCP/22 to the bastion CIDR or remove it and use SSM Session Manager.",
                "securityGroups[].ipPermissions[].ipRanges[]", "no 0.0.0.0/0 on tcp/22"),
    "EC2-047": ("7a55d1e8-3b90-42cf-8e17-5d2a9c4b6031",
                "SSH password authentication should be disabled",
                "sshd_config must set PasswordAuthentication no so that only key-based auth is accepted.",
                "Set 'PasswordAuthentication no' and 'ChallengeResponseAuthentication no' in /etc/ssh/sshd_config, then reload sshd.",
                "/etc/ssh/sshd_config:PasswordAuthentication", "PasswordAuthentication no"),
    "EC2-021": ("b3e07c42-9f18-4d6a-b250-8c71e5a3f094",
                "IMDSv1 should be disabled (require IMDSv2 tokens)",
                "The instance metadata service must require session tokens (HttpTokens=required).",
                "Run aws ec2 modify-instance-metadata-options --http-tokens required --http-endpoint enabled.",
                "metadataOptions.httpTokens", "required"),
    "EC2-004": ("5d9b2f61-0c47-4e83-91ad-7b6f2c0e4835",
                "EBS volumes attached to EC2 instances should be encrypted at rest",
                "All attached EBS volumes must use KMS encryption.",
                "Snapshot and restore the volume with encryption enabled using the grid CMK.",
                "blockDeviceMappings[].ebs.encrypted", "true"),
    "EC2-018": ("c81a4306-6e25-4f7b-a093-2d5c8b1f7e62",
                "EC2 instance should not allow inbound RDP (port 3389) from 0.0.0.0/0",
                "Security groups attached to the instance must not permit TCP/3389 from any IPv4 address.",
                "Remove the 0.0.0.0/0 rule for TCP/3389.",
                "securityGroups[].ipPermissions[].ipRanges[]", "no 0.0.0.0/0 on tcp/3389"),
    "EC2-030": ("e26f8b95-4a71-40d2-8c63-1f0a9d7b5c38",
                "EC2 instance should have detailed monitoring enabled",
                "Detailed CloudWatch monitoring must be enabled for production instances.",
                "Run aws ec2 monitor-instances --instance-ids <id>.",
                "monitoring.state", "enabled"),
}

# host -> list of (short_id, result, current_value)
MISCONFIGS = {
    "gridvault-usw2-01": [
        ("EC2-013", "FAIL", "0.0.0.0/0:22"),
        ("EC2-047", "FAIL", "PasswordAuthentication yes"),
        ("EC2-021", "FAIL", "optional"),
        ("EC2-004", "PASS", "true"),
        ("EC2-018", "PASS", "no 0.0.0.0/0 on tcp/3389"),
        ("EC2-030", "PASS", "enabled"),
    ],
    "gridvault-usw2-02": [
        ("EC2-021", "FAIL", "optional"),
        ("EC2-013", "PASS", "10.32.2.10/32:22"),
        ("EC2-004", "PASS", "true"),
    ],
    "gridvault-usw2-03": [
        ("EC2-030", "FAIL", "disabled"),
        ("EC2-013", "PASS", "10.32.2.10/32:22"),
        ("EC2-004", "PASS", "true"),
    ],
    "gridvault-bastion-usw2-01": [
        ("EC2-021", "FAIL", "optional"),
        ("EC2-013", "PASS", "198.51.100.0/24:22"),
        ("EC2-047", "PASS", "PasswordAuthentication no"),
    ],
    "ip-10-32-40-11.us-west-2.compute.internal": [
        ("EC2-021", "FAIL", "optional"),
        ("EC2-013", "PASS", "10.32.0.0/16:22"),
    ],
}


# --------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------
def _req(base, key, method, path, body=None, raw=None, ctype="application/json", extra=None):
    if raw is not None:
        data = raw.encode()
    else:
        data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    r.add_header("Authorization", f"ApiKey {key}")
    r.add_header("Content-Type", ctype)
    for k, v in (extra or {}).items():
        r.add_header(k, v)
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


def es(method, path, body=None, raw=None, ctype="application/json"):
    return _req(ES, ES_KEY, method, path, body, raw, ctype)


def kb(method, path, body=None):
    return _req(KB, KB_KEY, method, path, body, extra={
        "kbn-xsrf": "true",
        "x-elastic-internal-origin": "Kibana",
        "elastic-api-version": "2023-10-31",
    })


def esql(query, params=None):
    body = {"query": query}
    if params:
        body["params"] = params
    s, b = es("POST", "/_query", body)
    if s != 200:
        raise RuntimeError(f"ES|QL {s}: {str(b)[:500]}")
    cols = [c["name"] for c in b["columns"]]
    return [dict(zip(cols, row)) for row in b["values"]]


# --------------------------------------------------------------------------------------
# Raw Wiz doc builders
# --------------------------------------------------------------------------------------
def arn(host):
    return f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{HOSTS[host]['instance']}"


def vulnerable_asset(host):
    h = HOSTS[host]
    return {
        "id": h["wiz_id"],
        "name": host,                       # MUST equal host.name
        "type": "VIRTUAL_MACHINE",
        "region": REGION,
        "status": "Active",
        "operatingSystem": h["os"],
        "cloudPlatform": "AWS",
        "cloudProviderURL": (f"https://{REGION}.console.aws.amazon.com/ec2/home?region={REGION}"
                             f"#InstanceDetails:instanceId={h['instance']}"),
        "providerUniqueId": arn(host),
        "subscriptionId": SUBSCRIPTION_ID,
        "subscriptionExternalId": ACCOUNT,
        "subscriptionName": SUBSCRIPTION_NAME,
        "ipAddresses": [h["ip"]],
        "tags": h["tags"],
        "hasWideInternetExposure": h["exposed"],
    }


def vuln_docs():
    out = []
    for host, rows in VULNS.items():
        for (cve, title, sev, score, pkg, ver, fixed, exploit, kev,
             epss_p, epss_pct, expl_score, imp_score, runtime) in rows:
            fid = f"vgisim-vuln-{HOSTS[host]['instance']}-{cve}"
            epss_sev = ("CRITICAL" if epss_p >= 0.5 else "HIGH" if epss_p >= 0.1
                        else "MEDIUM" if epss_p >= 0.01 else "LOW")
            payload = {
                "id": fid,
                "name": cve,
                "CVEDescription": title,
                "CVSSSeverity": sev,
                "score": score,
                "status": "OPEN",
                "vendorSeverity": sev,
                "firstDetectedAt": TS_FIRST,
                "lastDetectedAt": TS_NOW,
                "detailedName": pkg,
                "version": ver,
                "fixedVersion": fixed,
                "hasExploit": exploit,
                "hasCisaKevExploit": kev,
                "validatedInRuntime": runtime,
                "exploitabilityScore": expl_score,
                "impactScore": imp_score,
                "epssProbability": epss_p,
                "epssPercentile": epss_pct,
                "epssSeverity": epss_sev,
                "detectionMethod": "PACKAGE",
                "dataSourceName": "Wiz Cloud Scanner",
                "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "locationPath": "/var/lib/dpkg/status",
                "portalUrl": f"https://app.wiz.io/explorer/vulnerability-findings#~(entity~(~'{fid}))",
                "remediation": f"Upgrade {pkg} to {fixed} and restart the affected service.",
                "description": f"{cve} detected in {pkg} {ver} on {host}",
                "projects": PROJECTS,
                "vulnerableAsset": vulnerable_asset(host),
            }
            out.append((fid, host, payload))
    return out


def misconfig_docs():
    out = []
    for host, rows in MISCONFIGS.items():
        h = HOSTS[host]
        for short_id, result, current in rows:
            rule_uuid, rname, rdesc, rremed, cfg_path, expected = RULES[short_id]
            fid = f"vgisim-misconfig-{h['instance']}-{short_id}"
            payload = {
                "id": fid,
                "analyzedAt": TS_SCAN,
                "updatedAt": TS_SCAN,
                "result": result,
                "status": "OPEN" if result == "FAIL" else "RESOLVED",
                "severity": "HIGH" if result == "FAIL" else "INFORMATIONAL",
                "remediation": rremed,
                "resource": {
                    "id": h["wiz_id"],
                    "providerId": arn(host),
                    "name": host,           # MUST equal host.name
                    "type": "VIRTUAL_MACHINE",
                    "nativeType": "ec2.instance",
                    "region": REGION,
                    "cloudPlatform": "EC2",
                    "subscription": {
                        "cloudProvider": "AWS",
                        "externalId": ACCOUNT,
                        "id": SUBSCRIPTION_ID,
                        "name": SUBSCRIPTION_NAME,
                    },
                    "tags": [{"key": k, "value": v} for k, v in h["tags"].items()],
                },
                "rule": {
                    "id": rule_uuid,
                    "shortId": short_id,
                    "name": rname,
                    "description": rdesc,
                    "remediationInstructions": rremed,
                },
                "evidence": {
                    "currentValue": current,
                    "expectedValue": expected,
                    "configurationPath": cfg_path,
                    "cloudConfigurationLink": (
                        f"https://app.wiz.io/cloud-config-rules#~(rule~'{short_id})"),
                },
            }
            out.append((fid, host, payload))
    return out


def envelope(payload, dataset):
    """Raw shape the Wiz package pipeline expects: JSON string in `message`."""
    asset = payload.get("vulnerableAsset") or payload.get("resource") or {}
    host_id = HOSTS.get(asset.get("name", "").lower(), {}).get("host_id")
    return {
        **({"host": {"id": host_id}} if host_id else {}),
        "@timestamp": TS_NOW,
        "message": json.dumps(payload, separators=(",", ":")),
        "tags": ["preserve_original_event", "preserve_duplicate_custom_fields",
                 "forwarded", SIM_TAG],
        "labels": {"vgi_sim": True},
        "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
        "event": {"dataset": dataset, "module": "wiz"},
    }


# --------------------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------------------
def install_package():
    s, b = kb("GET", "/api/fleet/epm/packages/wiz")
    status = (b.get("item") or {}).get("status") if isinstance(b, dict) else None
    if status == "installed":
        print("OK  wiz package already installed")
        return
    s, b = kb("POST", "/api/fleet/epm/packages/wiz/4.8.0", {"force": True})
    print(f"{'OK ' if s == 200 else 'ERR'} install wiz 4.8.0 -> {s}, "
          f"{len(b.get('items', [])) if isinstance(b, dict) else 0} assets")


def simulate():
    for ds, docs in ((VULN_DS.replace('-default', ''), vuln_docs()[:1]),
                     (MISC_DS.replace('-default', ''), misconfig_docs()[:1])):
        pipeline = f"{ds}-4.8.0"
        doc = envelope(docs[0][2], ds.replace("logs-", ""))
        s, b = es("POST", f"/_ingest/pipeline/{pipeline}/_simulate",
                  {"docs": [{"_source": doc}]})
        print(f"=== {pipeline} -> {s}")
        if s != 200:
            print(str(b)[:800]); continue
        src = b["docs"][0].get("doc", {}).get("_source", b["docs"][0])
        interesting = {k: src.get(k) for k in
                       ("host", "vulnerability", "package", "result", "rule", "resource",
                        "cloud", "tags", "labels", "event", "error")}
        print(json.dumps(interesting, indent=1, default=str)[:2200])


def purge_raw(quiet=False):
    total = 0
    for ds in (VULN_DS, MISC_DS):
        s, b = es("POST", f"/{ds}/_delete_by_query?refresh=true&conflicts=proceed",
                  {"query": {"term": {"tags": SIM_TAG}}})
        n = b.get("deleted", 0) if isinstance(b, dict) else 0
        total += n
        if not quiet:
            print(f"    purged {n} sim docs from {ds} (http {s})")
    return total


def seed():
    vd, md = vuln_docs(), misconfig_docs()
    manifest = {"created": TS_NOW, "vulnerability_ids": [d[0] for d in vd],
                "misconfiguration_ids": [d[0] for d in md],
                "lookup_index": LOOKUP_INDEX, "tag": SIM_TAG}
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f, indent=1)

    for ds, docs, dataset in ((VULN_DS, vd, "wiz.vulnerability"),
                              (MISC_DS, md, "wiz.cloud_configuration_finding_full_posture")):
        lines = []
        for _fid, _host, payload in docs:
            lines.append(json.dumps({"create": {}}))
            lines.append(json.dumps(envelope(payload, dataset)))
        s, b = es("POST", f"/{ds}/_bulk?refresh=true", raw="\n".join(lines) + "\n",
                  ctype="application/x-ndjson")
        errs = [i for i in b.get("items", []) if i.get("create", {}).get("error")] if isinstance(b, dict) else []
        print(f"{'OK ' if s == 200 and not errs else 'ERR'} bulk {len(docs)} -> {ds} (http {s}, errors {len(errs)})")
        for e in errs[:3]:
            print("    ", json.dumps(e["create"]["error"])[:400])

    # any doc the pipeline choked on lands with error.message set (and is skipped by the transform)
    s, b = es("POST", "/logs-wiz.*/_search?size=3",
              {"query": {"bool": {"filter": [{"term": {"tags": SIM_TAG}},
                                             {"exists": {"field": "error.message"}}]}}})
    n = (b.get("hits", {}).get("total", {}) or {}).get("value", 0) if isinstance(b, dict) else 0
    print(f"    pipeline errors on seeded docs: {n}")
    for h in (b.get("hits", {}).get("hits", []) if n else []):
        print("    ", str(h["_source"].get("error"))[:300])


def run_transforms(wait=True):
    for t in TRANSFORMS:
        s, b = es("GET", f"/_transform/{t}/_stats")
        state = b["transforms"][0]["state"] if s == 200 and b.get("transforms") else "missing"
        if state in ("stopped", "failed"):
            es("POST", f"/_transform/{t}/_start")
            print(f"    started {t} (was {state})")
        s, b = es("POST", f"/_transform/{t}/_schedule_now")
        print(f"    _schedule_now {t} -> {s}")
    if not wait:
        return
    for attempt in range(12):
        time.sleep(10)
        es("POST", f"/{VULN_LATEST}*,{MISC_LATEST}*/_refresh")
        try:
            v = esql(f'FROM {VULN_LATEST}* | WHERE host.name == "gridvault-usw2-01" | STATS c=COUNT(*)')[0]["c"]
            m = esql(f'FROM {MISC_LATEST}* | WHERE host.name == "gridvault-usw2-01" | STATS c=COUNT(*)')[0]["c"]
        except Exception as ex:
            v = m = 0
            if attempt > 6:
                print("    ", str(ex)[:200])
        print(f"    wait {10 * (attempt + 1)}s: hero rows vuln={v} misconfig={m}")
        if v and m:
            return
        for t in TRANSFORMS:
            es("POST", f"/_transform/{t}/_schedule_now")
    print("WARN transforms did not materialise hero rows in 120s")


# --------------------------------------------------------------------------------------
# Lookup index
# --------------------------------------------------------------------------------------
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def asset_criticality():
    out = {}
    s, b = es("POST", f"/.asset-criticality.asset-criticality-{os.environ.get('KIBANA_SPACE', 'default')}/_search?size=200",
              {"query": {"term": {"id_field": "host.name"}}})
    if s == 200:
        for h in b.get("hits", {}).get("hits", []):
            src = h["_source"]
            out[src["id_value"]] = src.get("criticality_level")
        return out
    for host in HOSTS:                       # fallback: Kibana entity analytics API
        s, b = kb("GET", f"/api/asset_criticality?id_value={host}&id_field=host.name")
        if s == 200 and isinstance(b, dict):
            out[host] = b.get("criticality_level")
    return out


def build_lookup():
    vulns = esql(
        f"FROM {VULN_LATEST}* | WHERE host.name IS NOT NULL "
        "| KEEP host.name, vulnerability.id, vulnerability.severity, vulnerability.score.base, "
        "wiz.vulnerability.has_exploit, wiz.vulnerability.has_cisa_kev_exploit, "
        "wiz.vulnerability.epss.probability, vulnerability.description | LIMIT 1000")
    miscs = esql(
        f"FROM {MISC_LATEST}* | WHERE host.name IS NOT NULL "
        "| KEEP host.name, rule.id, rule.name, result.evaluation, "
        "result.evidence.current_value | LIMIT 1000")
    crit = asset_criticality()

    rows = {}
    for v in vulns:
        h = v["host.name"]
        r = rows.setdefault(h, {"critical_vulns": 0, "high_vulns": 0, "exploitable_vulns": 0,
                                "kev_vulns": 0, "total_vulns": 0, "failed_misconfigs": 0,
                                "passed_misconfigs": 0, "ssh_exposed_to_internet": False,
                                "ssh_password_auth": False, "_best": None})
        sev = (v.get("vulnerability.severity") or "").upper()
        exploit = bool(v.get("wiz.vulnerability.has_exploit"))
        kev = bool(v.get("wiz.vulnerability.has_cisa_kev_exploit"))
        r["total_vulns"] += 1
        r["critical_vulns"] += sev == "CRITICAL"
        r["high_vulns"] += sev == "HIGH"
        r["exploitable_vulns"] += exploit or kev        # "weaponised": public exploit OR CISA KEV
        r["kev_vulns"] += kev
        # worst = most likely to actually be used: weaponised first, then EPSS, then CVSS
        key = (1 if (exploit or kev) else 0, v.get("wiz.vulnerability.epss.probability") or 0.0,
               v.get("vulnerability.score.base") or 0.0, SEV_RANK.get(sev, 0))
        if r["_best"] is None or key > r["_best"][0]:
            r["_best"] = (key, v.get("vulnerability.id"), v.get("vulnerability.description"))
    for m in miscs:
        h = m["host.name"]
        r = rows.setdefault(h, {"critical_vulns": 0, "high_vulns": 0, "exploitable_vulns": 0,
                                "kev_vulns": 0, "total_vulns": 0, "failed_misconfigs": 0,
                                "passed_misconfigs": 0, "ssh_exposed_to_internet": False,
                                "ssh_password_auth": False, "_best": None})
        failed = m.get("result.evaluation") == "failed"
        r["failed_misconfigs"] += failed
        r["passed_misconfigs"] += m.get("result.evaluation") == "passed"
        if failed and m.get("rule.id") == "EC2-013":
            r["ssh_exposed_to_internet"] = True
        if failed and m.get("rule.id") == "EC2-047":
            r["ssh_password_auth"] = True

    es("DELETE", f"/{LOOKUP_INDEX}")
    s, b = es("PUT", f"/{LOOKUP_INDEX}", {
        "settings": {"index.mode": "lookup"},
        "mappings": {"properties": {
            "host": {"properties": {"name": {"type": "keyword"}}},
            "critical_vulns": {"type": "long"}, "high_vulns": {"type": "long"},
            "exploitable_vulns": {"type": "long"}, "kev_vulns": {"type": "long"},
            "total_vulns": {"type": "long"}, "failed_misconfigs": {"type": "long"},
            "passed_misconfigs": {"type": "long"},
            "top_cve": {"type": "keyword"}, "top_cve_title": {"type": "keyword"},
            "ssh_exposed_to_internet": {"type": "boolean"},
            "ssh_password_auth": {"type": "boolean"},
            "asset_criticality": {"type": "keyword"},
            "exposure_updated": {"type": "date"},
        }},
    })
    if s not in (200, 201):
        raise RuntimeError(f"create {LOOKUP_INDEX} failed {s}: {str(b)[:400]}")

    lines = []
    for host, r in sorted(rows.items()):
        best = r.pop("_best") or (None, None, None)
        title = (best[2] or "")[:240] or None
        doc = {"host": {"name": host}, "top_cve": best[1], "top_cve_title": title,
               "asset_criticality": crit.get(host, "unassigned"),
               "exposure_updated": TS_NOW, **r}
        doc["ssh_exposed_to_internet"] = bool(doc["ssh_exposed_to_internet"])
        doc["ssh_password_auth"] = bool(doc["ssh_password_auth"])
        lines.append(json.dumps({"index": {"_id": host}}))
        lines.append(json.dumps(doc))
    s, b = es("POST", f"/{LOOKUP_INDEX}/_bulk?refresh=true", raw="\n".join(lines) + "\n",
              ctype="application/x-ndjson")
    errs = [i for i in b.get("items", []) if i.get("index", {}).get("error")]
    print(f"{'OK ' if not errs else 'ERR'} {LOOKUP_INDEX}: {len(rows)} rows (http {s}, errors {len(errs)})")
    for e in errs[:2]:
        print("    ", json.dumps(e["index"]["error"])[:300])
    for host, r in sorted(rows.items()):
        print(f"    {host:<44} crit={r['critical_vulns']} high={r['high_vulns']} "
              f"expl={r['exploitable_vulns']} kev={r['kev_vulns']} failed_mis={r['failed_misconfigs']} "
              f"ssh_open={r['ssh_exposed_to_internet']} pw_auth={r['ssh_password_auth']}")


def verify():
    print("--- rows per host in the *_latest indices")
    for idx, label in ((VULN_LATEST, "vulnerability"), (MISC_LATEST, "misconfiguration")):
        try:
            rows = esql(f"FROM {idx}* | WHERE host.name IS NOT NULL "
                        "| STATS c = COUNT(*) BY host.name | SORT c DESC | LIMIT 20")
            for r in rows:
                print(f"    {label:<16} {r['host.name']:<44} {r['c']}")
        except Exception as ex:
            print(f"    {label}: {str(ex)[:200]}")
    print("--- hero host ECS fields")
    try:
        for r in esql(f'FROM {VULN_LATEST}* | WHERE host.name == "gridvault-usw2-01" '
                      "| KEEP vulnerability.id, vulnerability.severity, vulnerability.score.base, "
                      "package.name, package.version, package.fixed_version | SORT vulnerability.score.base DESC"):
            print("   ", json.dumps(r))
        for r in esql(f'FROM {MISC_LATEST}* | WHERE host.name == "gridvault-usw2-01" '
                      "| KEEP rule.id, rule.name, result.evaluation, result.evidence.current_value "
                      "| SORT rule.id"):
            print("   ", json.dumps(r)[:200])
    except Exception as ex:
        print("    ", str(ex)[:300])


def cleanup():
    n = purge_raw()
    for idx in (f"{VULN_LATEST}*", f"{MISC_LATEST}*"):
        s, b = es("POST", f"/{idx}/_delete_by_query?refresh=true&conflicts=proceed",
                  {"query": {"term": {"tags": SIM_TAG}}})
        print(f"    deleted {b.get('deleted', 0) if isinstance(b, dict) else '?'} from {idx} (http {s})")
    s, _ = es("DELETE", f"/{LOOKUP_INDEX}")
    print(f"    deleted index {LOOKUP_INDEX} (http {s})")
    if os.path.exists(MANIFEST):
        os.remove(MANIFEST)
    print(f"OK  cleanup done (raw docs removed: {n}). Fleet package `wiz` left installed.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--simulate", action="store_true", help="pipeline _simulate only, no writes")
    ap.add_argument("--skip-install", action="store_true")
    ap.add_argument("--lookup-only", action="store_true")
    ap.add_argument("--no-wait", action="store_true")
    a = ap.parse_args()
    if not ES or not ES_KEY:
        sys.exit("ERROR: source the env file first (ELASTICSEARCH_URL / ELASTICSEARCH_API_KEY)")
    if a.simulate:
        return simulate()
    if a.cleanup:
        return cleanup()
    if a.lookup_only:
        build_lookup()
        return verify()
    if not a.skip_install:
        install_package()
    print("--- purge previous sim docs")
    purge_raw()
    print("--- seed raw Wiz findings")
    seed()
    print("--- transforms")
    run_transforms(wait=not a.no_wait)
    print("--- lookup index")
    build_lookup()
    verify()


if __name__ == "__main__":
    main()

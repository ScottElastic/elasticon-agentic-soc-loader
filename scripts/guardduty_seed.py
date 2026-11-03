#!/usr/bin/env python3
"""ElastiCon — fake GuardDuty findings archive in S3 ("the sensor's last words").

The beat: the attacker deletes the GuardDuty detector (that alert is on the wall). But
GuardDuty had been exporting findings to S3 the whole time, and the export outlived the
detector. Lab 3 reads that bucket IN PLACE via ES|QL data federation — nothing ingested.

The archive is built AROUND THE SEEDED CAMPAIGN: crownjewel_seed.py writes the campaign
relative to now, so this script reads the attacker's CloudTrail events off the cluster
(root console login, CreateAccessKey, DeactivateMFADevice, StopLogging, DeleteDetector) and
pins each finding to the event it describes. Run it after every campaign seed (deploy.py does).

TIMELINE RULE (do not break it): every finding is strictly BEFORE DeleteDetector.
GuardDuty cannot have seen the Kubernetes stage or the SSH key login on gridvault-usw2-01 —
both come after the detector was deleted. It supplies what Elastic did not see: weeks of
port probes, an earlier SSH brute-force wave, and the IAM activity leading up to the kill.
The last finding lands a few seconds before DeleteDetector.

What it writes (two parallel layouts, so we are not hostage to how federation
flattens nested JSON — see --probe):
  guardduty/AWSLogs/<acct>/GuardDuty/<region>/YYYY/MM/DD/*.jsonl.gz       native nested GuardDuty
  guardduty-flat/AWSLogs/<acct>/GuardDuty/<region>/YYYY/MM/DD/*.jsonl.gz  flat scalar columns

Usage:
    source <scratchpad>/env.sh
    python3 guardduty_seed.py --dry-run        # build locally, print the timeline, upload nothing
    python3 guardduty_seed.py --probe          # upload a 3-finding file only, for schema discovery
    python3 guardduty_seed.py                  # build + upload the full archive
    python3 guardduty_seed.py --wire           # create the ES data source + dataset (needs the key)
    python3 guardduty_seed.py --status         # what is in S3 and in ES right now
    python3 guardduty_seed.py --cleanup        # remove the S3 prefixes + the ES dataset/data source

Uploads use your own authenticated AWS CLI identity (AWS_PROFILE works). The read-only key
pair is needed ONLY by --wire, for the Elasticsearch data source:
    export GD_S3_ACCESS_KEY=<reader access key id>
    export GD_S3_SECRET=<secret>          # never write this to a file in this folder

Env: ELASTICSEARCH_URL, ELASTICSEARCH_API_KEY  (+ GD_S3_ACCESS_KEY / GD_S3_SECRET for --wire)
     GD_BUCKET        bucket the archive lives in   (default vgi-guardduty-archive)
     GD_BUCKET_REGION the bucket's AWS region        (default us-west-2)
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ES = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
ES_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")

# --- the story's fixed points, all verified against the live cluster 2026-09-23 ---
ACCOUNT = "847629103455"
REGION = "us-west-2"
DETECTOR_ID = "a2b8f1c4d7e93056a1b4c7d0e3f69258"
HERO_HOST = "gridvault-usw2-01"
HERO_INSTANCE = "i-0b7c3e9a41d2f8e56"          # from the Wiz resource.id ARN
BASTION_INSTANCE = "i-0a5d8c3b2e9f14760"
ATTACKER_IP = "203.0.113.66"
SCANNER_IP = "198.51.100.23"
# The campaign's CloudTrail events, read off the cluster by discover_anchors(). Offsets are
# crownjewel_seed.py's own spacing, used only when the events can't be found (--dry-run).
ANCHOR_OFFSETS = {"ConsoleLogin": -115, "CreateAccessKey": -70, "DeactivateMFADevice": -40,
                  "StopLogging": -15, "DeleteDetector": 0}
ANCHORS: dict = {}
DELETE_DETECTOR = datetime.now(timezone.utc).replace(microsecond=0)

BUCKET = os.environ.get("GD_BUCKET", "vgi-guardduty-archive")
BUCKET_REGION = os.environ.get("GD_BUCKET_REGION", "us-west-2")
PREFIX_NESTED = f"guardduty/AWSLogs/{ACCOUNT}/GuardDuty/{REGION}"
PREFIX_FLAT = f"guardduty-flat/AWSLogs/{ACCOUNT}/GuardDuty/{REGION}"

DS_NAME = "vgi_guardduty_archive"
DATASET_NAME = "guardduty_findings"
DATASET_FLAT = "guardduty_findings_flat"

STAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gd_stage")
RNG = random.Random(20260918)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ev(action, plus_s=0):
    """The time of a seeded campaign event, plus an offset in seconds."""
    return ANCHORS[action] + timedelta(seconds=plus_s)


def fid(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def sev_label(sev: float) -> str:
    return "High" if sev >= 7 else "Medium" if sev >= 4 else "Low"


# ---------------------------------------------------------------- geo / actor blocks
GEO = {
    ATTACKER_IP: {"country": "Romania", "iso": "RO", "city": "Bucharest",
                  "org": "AS9009 M247 Europe SRL", "asn": "9009", "lat": 44.4323, "lon": 26.1063},
    SCANNER_IP: {"country": "Netherlands", "iso": "NL", "city": "Amsterdam",
                 "org": "AS202425 IP Volume inc", "asn": "202425", "lat": 52.3740, "lon": 4.8897},
}


def remote_ip_details(ip):
    g = GEO.get(ip, {"country": "United States", "iso": "US", "city": "Ashburn",
                     "org": "AS14618 Amazon.com Inc.", "asn": "14618", "lat": 39.0438, "lon": -77.4874})
    return {
        "ipAddressV4": ip,
        "organization": {"asn": g["asn"], "asnOrg": g["org"], "isp": g["org"], "org": g["org"]},
        "country": {"countryName": g["country"], "countryCode": g["iso"]},
        "city": {"cityName": g["city"]},
        "geoLocation": {"lat": g["lat"], "lon": g["lon"]},
    }


def instance_details(instance_id, host_name):
    return {
        "instanceId": instance_id,
        "instanceType": "r6i.4xlarge" if instance_id == HERO_INSTANCE else "t3.large",
        "launchTime": "2026-06-02T09:14:31.000Z",
        "platform": None,
        "productCodes": [],
        "iamInstanceProfile": {
            "arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/gridvault-db-role",
            "id": "AIPA4XK2MHQ7YVLR3TZ9B",
        },
        "networkInterfaces": [{
            "networkInterfaceId": "eni-0f3a7c94d2b615e80",
            "privateDnsName": f"{host_name}.{REGION}.compute.internal",
            "privateIpAddress": "10.32.40.11",
            "publicIp": "54.71.203.118",
            "publicDnsName": f"ec2-54-71-203-118.{REGION}.compute.amazonaws.com",
            "vpcId": "vpc-0c17a9e3b8d45f621",
            "subnetId": "subnet-0a94f2c7e1b360d85",
            "securityGroups": [{"groupId": "sg-0d82a4f61c39eb750", "groupName": "gridvault-db-sg"}],
        }],
        "tags": [{"key": "Name", "value": host_name},
                 {"key": "Environment", "value": "production"},
                 {"key": "BusinessUnit", "value": "Grid Operations"},
                 {"key": "DataClassification", "value": "restricted"}],
        "availabilityZone": f"{REGION}a",
        "imageId": "ami-0c2d3e91f7a4b6d58",
        "imageDescription": "Ubuntu 22.04 LTS hardened (VGI base)",
    }


def access_key_details(user_name, key_id="AKIAIOSFODNN7EXAMPLE"):
    return {"accessKeyId": key_id, "principalId": "AIDAABCEC1F78E8455AF",
            "userType": "IAMUser", "userName": user_name}


# ---------------------------------------------------------------- finding factory
def finding(ts, ftype, severity, title, description, *, resource, action,
            resource_role="TARGET", count=1, first_seen=None, last_seen=None):
    created = first_seen or ts
    f_id = fid(ftype, iso(ts), json.dumps(resource, sort_keys=True))
    return {
        "schemaVersion": "2.0",
        "accountId": ACCOUNT,
        "region": REGION,
        "partition": "aws",
        "id": f_id,
        "arn": f"arn:aws:guardduty:{REGION}:{ACCOUNT}:detector/{DETECTOR_ID}/finding/{f_id}",
        "type": ftype,
        "resource": resource,
        "service": {
            "serviceName": "guardduty",
            "detectorId": DETECTOR_ID,
            "action": action,
            "resourceRole": resource_role,
            "additionalInfo": {"threatListName": "ProofPoint" if severity >= 7 else None,
                               "sample": False},
            "eventFirstSeen": iso(created),
            "eventLastSeen": iso(last_seen or ts),
            "archived": False,
            "count": count,
        },
        "severity": severity,
        "title": title,
        "description": description,
        "createdAt": iso(created),
        "updatedAt": iso(ts),
    }


def net_action(ip, port=22, port_name="SSH", direction="INBOUND", blocked=False, protocol="TCP"):
    return {"actionType": "NETWORK_CONNECTION",
            "networkConnectionAction": {
                "connectionDirection": direction,
                "remoteIpDetails": remote_ip_details(ip),
                "remotePortDetails": {"port": RNG.randint(40000, 61000), "portName": "Unknown"},
                "localPortDetails": {"port": port, "portName": port_name},
                "protocol": protocol, "blocked": blocked}}


def api_action(ip, api, service="iam.amazonaws.com", user_agent="aws-cli/2.15.30 Python/3.11.6 Linux/5.15.0"):
    return {"actionType": "AWS_API_CALL",
            "awsApiCallAction": {
                "api": api, "serviceName": service, "callerType": "Remote IP",
                "remoteIpDetails": remote_ip_details(ip),
                "affectedResources": {}, "userAgent": user_agent}}


def ec2_resource(instance_id=HERO_INSTANCE, host=HERO_HOST):
    return {"resourceType": "Instance", "instanceDetails": instance_details(instance_id, host)}


def iam_resource(user_name, key_id="AKIAIOSFODNN7EXAMPLE"):
    return {"resourceType": "AccessKey", "accessKeyDetails": access_key_details(user_name, key_id)}


# ---------------------------------------------------------------- anchor discovery
def discover_anchors(fixed=None):
    """Read the attacker's CloudTrail events off the cluster; fall back to offsets from `fixed`."""
    global DELETE_DETECTOR
    found = {}
    if fixed is None:
        r = es_req("POST", "/_query", {"query":
            f'FROM logs-aws.cloudtrail-* | WHERE @timestamp >= NOW() - 7 days '
            f'| WHERE source.ip == "{ATTACKER_IP}" OR event.action == "DeleteDetector" '
            '| WHERE event.outcome == "success" OR event.action != "ConsoleLogin" '
            '| STATS t = MAX(@timestamp) BY event.action'})
        for t, action in (r.get("values") or []):
            if action in ANCHOR_OFFSETS:
                found[action] = datetime.strptime(t.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z")
    if "DeleteDetector" not in found:
        dd = fixed or datetime.now(timezone.utc).replace(microsecond=0)
        print(f"  ! no DeleteDetector found — anchoring on {iso(dd)} (seed the campaign first)")
        found = {"DeleteDetector": dd}
    dd = found["DeleteDetector"]
    for action, off in ANCHOR_OFFSETS.items():
        found.setdefault(action, dd + timedelta(seconds=off))
    ANCHORS.update(found)
    DELETE_DETECTOR = dd
    for action in ANCHOR_OFFSETS:
        print(f"  anchor {action:<20} {iso(ANCHORS[action])}")
    return True


# ---------------------------------------------------------------- the campaign
def campaign_findings():
    """Every finding strictly before DELETE_DETECTOR, each pinned to the event it describes."""
    out = []
    dd = DELETE_DETECTOR

    # --- slow recon tail: the scanner has been probing the hero's SSH port for a month
    day = dd - timedelta(days=30)
    while day < dd - timedelta(hours=6):
        out.append(finding(
            day, "Recon:EC2/PortProbeUnprotectedPort", 2.0,
            "Unprotected port on EC2 instance is being probed.",
            f"EC2 instance {HERO_INSTANCE} has an unprotected port 22 which is being probed "
            f"by a known malicious host {SCANNER_IP}.",
            resource=ec2_resource(), action=net_action(SCANNER_IP, blocked=False),
            count=RNG.randint(3, 14), first_seen=day - timedelta(hours=2)))
        day += timedelta(days=RNG.randint(2, 4), hours=RNG.randint(0, 20))

    # --- the detector's final hours
    out.append(finding(
        dd - timedelta(minutes=101), "Recon:EC2/PortProbeUnprotectedPort", 5.0,
        "Unprotected port on EC2 instance is being probed.",
        f"EC2 instance {HERO_INSTANCE} has an unprotected port 22 which is being probed by "
        f"{SCANNER_IP}. Probe volume increased sharply over the preceding hour.",
        resource=ec2_resource(), action=net_action(SCANNER_IP),
        count=118, first_seen=dd - timedelta(minutes=148), last_seen=dd - timedelta(minutes=101)))

    # ★ an earlier, quieter SSH wave against the crown jewel that Elastic's thresholds never caught
    out.append(finding(
        dd - timedelta(minutes=76), "UnauthorizedAccess:EC2/SSHBruteForce", 8.0,
        f"{ATTACKER_IP} is performing SSH brute force attacks against {HERO_INSTANCE}.",
        f"{ATTACKER_IP} is performing SSH brute force attacks against EC2 instance "
        f"{HERO_INSTANCE}. Brute force attacks are used to gain unauthorized access to your "
        f"instance by guessing the SSH password.",
        resource=ec2_resource(), action=net_action(ATTACKER_IP),
        count=47, first_seen=dd - timedelta(minutes=81), last_seen=dd - timedelta(minutes=76)))

    out.append(finding(
        dd - timedelta(minutes=52), "UnauthorizedAccess:EC2/SSHBruteForce", 8.0,
        f"{ATTACKER_IP} is performing SSH brute force attacks against {BASTION_INSTANCE}.",
        f"{ATTACKER_IP} is performing SSH brute force attacks against EC2 instance "
        f"{BASTION_INSTANCE} (gridvault-bastion-usw2-01).",
        resource=ec2_resource(BASTION_INSTANCE, "gridvault-bastion-usw2-01"),
        action=net_action(ATTACKER_IP), count=22,
        first_seen=dd - timedelta(minutes=56), last_seen=dd - timedelta(minutes=52)))

    # --- the AWS stage: each finding lines up with a seeded CloudTrail event
    out.append(finding(
        ev("ConsoleLogin", 4), "Policy:IAMUser/RootCredentialUsage", 7.0,
        "An API was invoked using root credentials.",
        f"A console login using root credentials was observed from {ATTACKER_IP}, which is on a "
        f"threat intelligence list. MFA was not used.",
        resource=iam_resource("root", "ASIAEXAMPLETEMPKEY"),
        action=api_action(ATTACKER_IP, "ConsoleLogin", "signin.amazonaws.com",
                          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")))

    out.append(finding(
        ev("ConsoleLogin", 22), "Recon:IAMUser/MaliciousIPCaller", 5.0,
        "API commonly used to discover resources invoked from a known malicious IP address.",
        f"An API commonly used to discover the users and keys in an AWS account was invoked from "
        f"IP address {ATTACKER_IP}, which is on a threat intelligence list.",
        resource=iam_resource("root", "ASIAEXAMPLETEMPKEY"),
        action=api_action(ATTACKER_IP, "ListUsers"), count=9))

    out.append(finding(
        ev("CreateAccessKey", 3), "PrivilegeEscalation:IAMUser/AnomalousBehavior", 8.0,
        "An API used to gain elevated access was invoked in an anomalous way.",
        f"CreateAccessKey for another principal (svc-t800-ci) was invoked with root credentials "
        f"from {ATTACKER_IP}. This behavior is not typical for this account.",
        resource=iam_resource("svc-t800-ci"),
        action=api_action(ATTACKER_IP, "CreateAccessKey")))

    out.append(finding(
        ev("DeactivateMFADevice", 3), "Persistence:IAMUser/AnomalousBehavior", 6.0,
        "An API used to maintain unauthorized access was invoked in an anomalous way.",
        f"DeactivateMFADevice was invoked on user h.langston from {ATTACKER_IP}.",
        resource=iam_resource("h.langston", "AKIAI44QH8DHBEXAMPLE"),
        action=api_action(ATTACKER_IP, "DeactivateMFADevice")))

    out.append(finding(
        ev("StopLogging", 2), "Stealth:IAMUser/CloudTrailLoggingDisabled", 8.0,
        "AWS CloudTrail trail was disabled.",
        f"CloudTrail logging was disabled from {ATTACKER_IP}. Attackers disable logging to cover "
        f"their tracks.",
        resource=iam_resource("svc-t800-ci"),
        action=api_action(ATTACKER_IP, "StopLogging", "cloudtrail.amazonaws.com")))

    # ★ THE LAST WORDS — the attacker looking the detector up, seconds before deleting it
    out.append(finding(
        ev("DeleteDetector", -4), "Discovery:IAMUser/AnomalousBehavior", 5.0,
        "An API commonly used to discover security controls was invoked in an anomalous way.",
        f"ListDetectors and GetDetector were invoked from {ATTACKER_IP}, which is on the custom "
        f"threat list VGI-CTI-Skynet, immediately after CloudTrail logging was stopped.",
        resource=iam_resource("svc-t800-ci"),
        action=api_action(ATTACKER_IP, "ListDetectors", "guardduty.amazonaws.com")))

    late = [f for f in out if f["updatedAt"] >= iso(DELETE_DETECTOR)]
    if late:
        raise SystemExit(f"TIMELINE VIOLATION: {len(late)} finding(s) at/after DeleteDetector "
                         f"({iso(DELETE_DETECTOR)}): {[f['type'] for f in late]}")
    return out


BENIGN = [
    ("Recon:EC2/PortProbeUnprotectedPort", 2.0, "Unprotected port on EC2 instance is being probed.",
     "has an unprotected port which is being probed"),
    ("Policy:S3.BucketAnonymousAccessGranted", 3.0, "S3 bucket policy allows public read access.",
     "grants read access to the public"),
    ("Policy:IAMUser/ShortTermRootCredentialUsage", 1.0, "Short-term root credentials were used.",
     "short-term root credentials were used"),
    ("Recon:EC2/Portscan", 2.0, "EC2 instance is performing outbound port scans.",
     "is performing outbound port scans"),
    ("UnauthorizedAccess:EC2/RDPBruteForce", 2.0, "RDP brute force attempts observed.",
     "is performing RDP brute force attacks"),
]


def benign_findings(n=200):
    """Low-severity noise over 30 days so the archive reads like a real one, not a prop."""
    out = []
    hosts = [("i-0d41f8a2c7b95e310", "gridvault-usw2-02"),
             ("i-07e2b9d4a6c1f3852", "gridvault-usw2-03"),
             ("i-0c9e4f7a1b3d6528e", "ip-10-32-40-11"),
             (BASTION_INSTANCE, "gridvault-bastion-usw2-01")]
    start = DELETE_DETECTOR - timedelta(days=30)
    span = int((DELETE_DETECTOR - start).total_seconds())
    for _ in range(n):
        ts = start + timedelta(seconds=RNG.randint(0, span - 60))
        ftype, sev, title, blurb = RNG.choice(BENIGN)
        inst, host = RNG.choice(hosts)
        ip = f"{RNG.randint(11, 210)}.{RNG.randint(0, 255)}.{RNG.randint(0, 255)}.{RNG.randint(1, 254)}"
        out.append(finding(
            ts, ftype, sev, title, f"EC2 instance {inst} ({host}) {blurb} by {ip}.",
            resource=ec2_resource(inst, host), action=net_action(ip, port=RNG.choice([22, 3389, 443])),
            count=RNG.randint(1, 30)))
    return sorted(out, key=lambda f: f["updatedAt"])


# ---------------------------------------------------------------- flattening
def flatten(f):
    svc, act = f["service"], f["service"]["action"]
    net = act.get("networkConnectionAction") or {}
    api = act.get("awsApiCallAction") or {}
    rid = net.get("remoteIpDetails") or api.get("remoteIpDetails") or {}
    inst = (f["resource"].get("instanceDetails") or {})
    akd = (f["resource"].get("accessKeyDetails") or {})
    name_tag = next((t["value"] for t in inst.get("tags", []) if t["key"] == "Name"), None)
    return {
        "finding_id": f["id"], "finding_arn": f["arn"], "finding_type": f["type"],
        "severity": f["severity"], "severity_label": sev_label(f["severity"]),
        "title": f["title"], "description": f["description"],
        "created_at": f["createdAt"], "updated_at": f["updatedAt"],
        "event_first_seen": svc["eventFirstSeen"], "event_last_seen": svc["eventLastSeen"],
        "finding_count": svc["count"], "archived": svc["archived"],
        "account_id": f["accountId"], "region": f["region"], "detector_id": svc["detectorId"],
        "resource_type": f["resource"]["resourceType"], "resource_role": svc["resourceRole"],
        "instance_id": inst.get("instanceId"), "instance_name": name_tag,
        "availability_zone": inst.get("availabilityZone"),
        "user_name": akd.get("userName"), "access_key_id": akd.get("accessKeyId"),
        "action_type": act["actionType"], "api_name": api.get("api"),
        "api_service": api.get("serviceName"), "user_agent": api.get("userAgent"),
        "remote_ip": rid.get("ipAddressV4"),
        "remote_country": (rid.get("country") or {}).get("countryName"),
        "remote_city": (rid.get("city") or {}).get("cityName"),
        "remote_org": (rid.get("organization") or {}).get("asnOrg"),
        "local_port": (net.get("localPortDetails") or {}).get("port"),
        "port_name": (net.get("localPortDetails") or {}).get("portName"),
        "protocol": net.get("protocol"), "connection_direction": net.get("connectionDirection"),
        "blocked": net.get("blocked"),
    }


# ---------------------------------------------------------------- IO
def write_gz(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    return os.path.getsize(path)


def build(findings, probe=False):
    """Group by finding date; native + flat under parallel prefixes. Clears the stage first."""
    import shutil
    shutil.rmtree(STAGE, ignore_errors=True)
    made = []
    buckets = {}
    for f in findings:
        buckets.setdefault(f["updatedAt"][:10], []).append(f)
    tag = "probe" if probe else "findings"
    for date, rows in sorted(buckets.items()):
        y, m, d = date.split("-")
        name = f"{tag}-{date}.jsonl.gz"
        n_path = os.path.join(STAGE, PREFIX_NESTED, y, m, d, name)
        f_path = os.path.join(STAGE, PREFIX_FLAT, y, m, d, name)
        made.append((n_path, write_gz(n_path, rows), len(rows)))
        made.append((f_path, write_gz(f_path, [flatten(r) for r in rows]), len(rows)))
    return made


def aws(*args, capture=True):
    r = subprocess.run(["aws", *args], capture_output=capture, text=True)
    if r.returncode != 0:
        sys.exit(f"aws {' '.join(args[:3])} failed:\n{(r.stderr or r.stdout).strip()[:600]}")
    return r.stdout


def upload():
    for pref in (PREFIX_NESTED, PREFIX_FLAT):
        local = os.path.join(STAGE, pref)
        if not os.path.isdir(local):
            continue
        aws("s3", "sync", local, f"s3://{BUCKET}/{pref}/", "--region", BUCKET_REGION, "--delete")
        print(f"  uploaded s3://{BUCKET}/{pref}/")


# ---------------------------------------------------------------- Elasticsearch
def es_req(method, path, body=None):
    if not ES or not ES_KEY:
        sys.exit("ELASTICSEARCH_URL / ELASTICSEARCH_API_KEY not set — source env.sh first.")
    req = urllib.request.Request(
        f"{ES}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"ApiKey {ES_KEY}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"__error": e.code, "body": e.read().decode()[:700]}


def wire():
    ak, sk = os.environ.get("GD_S3_ACCESS_KEY", ""), os.environ.get("GD_S3_SECRET", "")
    if not ak or not sk:
        sys.exit("Set GD_S3_ACCESS_KEY and GD_S3_SECRET (read-only key for <reader-user>).")
    ds_body = {"type": "s3", "description": "VGI GuardDuty findings export — survived the detector deletion",
               "settings": {"auth": "static_credentials", "access_key": ak, "secret_key": sk}}
    print(es_req("PUT", f"/_query/data_source/{DS_NAME}", ds_body))
    for name, pref in ((DATASET_NAME, PREFIX_NESTED), (DATASET_FLAT, PREFIX_FLAT)):
        body = {"data_source": DS_NAME, "resource": f"s3://{BUCKET}/{pref}/*/*/*/*.jsonl.gz",
                # union_by_name is REQUIRED: the default first_file_wins resolves the schema from the
                # earliest file only, which holds EC2/networkConnectionAction findings — the IAM
                # findings' awsApiCallAction + accessKeyDetails columns would vanish from the schema.
                "settings": {"region": BUCKET_REGION, "schema_resolution": "union_by_name"}}
        r = es_req("PUT", f"/_query/dataset/{name}", body)
        if "__error" in r and "unknown setting [region]" in r.get("body", ""):
            # 9.5.x (ECH, experimental) wants the region on the DATA SOURCE; 9.6 on the dataset.
            ds_body["settings"]["region"] = BUCKET_REGION
            print(f"  9.5 layout: region on the data source", es_req("PUT", f"/_query/data_source/{DS_NAME}", ds_body))
            body["settings"].pop("region")
            r = es_req("PUT", f"/_query/dataset/{name}", body)
        print(name, r)
    bad = 0
    for name in (DATASET_NAME, DATASET_FLAT):
        r = es_req("POST", "/_query", {"query": f"FROM {name} | LIMIT 1"})
        if "__error" in r:
            print(f"  ✗ {name}: {r['body'][:300]}")
            bad += 1
        else:
            print(f"  ✓ {name}: {len(r.get('columns', []))} columns")
            print("    " + ", ".join(c["name"] for c in r.get("columns", []))[:1200])
    if bad:
        sys.exit(f"{bad} dataset(s) not queryable")


def status():
    print("S3:")
    for pref in (PREFIX_NESTED, PREFIX_FLAT):
        out = aws("s3", "ls", f"s3://{BUCKET}/{pref}/", "--recursive", "--region", BUCKET_REGION) or ""
        lines = [l for l in out.splitlines() if l.strip()]
        print(f"  {pref}: {len(lines)} object(s)")
        for l in lines[:4]:
            print(f"    {l}")
    print("Elasticsearch:")
    print("  data_sources:", json.dumps(es_req("GET", "/_query/data_source"))[:300])
    print("  datasets:", json.dumps(es_req("GET", "/_query/dataset"))[:400])


def cleanup():
    for name in (DATASET_NAME, DATASET_FLAT):
        print(name, es_req("DELETE", f"/_query/dataset/{name}"))
    print(DS_NAME, es_req("DELETE", f"/_query/data_source/{DS_NAME}"))
    for pref in (PREFIX_NESTED, PREFIX_FLAT):
        aws("s3", "rm", f"s3://{BUCKET}/{pref}/", "--recursive", "--region", BUCKET_REGION)
        print(f"  removed s3://{BUCKET}/{pref}/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="build locally, print timeline, no upload")
    ap.add_argument("--probe", action="store_true", help="upload 3 findings only, for schema discovery")
    ap.add_argument("--wire", action="store_true", help="create the ES data source + datasets")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--benign", type=int, default=200)
    ap.add_argument("--anchor", default="auto",
                    help="'auto' (default) reads the seeded campaign's CloudTrail events off the cluster; "
                         "or a fixed DeleteDetector time like 2026-09-18T13:23:56Z (offline builds)")
    a = ap.parse_args()

    if a.status:
        return status()
    if a.cleanup:
        return cleanup()
    if a.wire:
        return wire()

    if a.anchor == "auto" and not a.dry_run:
        discover_anchors()
    else:
        fixed = (datetime.strptime(a.anchor, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                 if a.anchor not in ("auto", "") else None)
        discover_anchors(fixed or datetime.now(timezone.utc).replace(microsecond=0))

    camp = campaign_findings()
    if a.probe:
        rows = [f for f in camp if f["type"].startswith(("UnauthorizedAccess:EC2/SSHBrute",
                                                         "Stealth:", "Policy:IAMUser/Root"))][:3]
        made = build(rows, probe=True)
    else:
        rows = sorted(camp + benign_findings(a.benign), key=lambda f: f["updatedAt"])
        made = build(rows)

    print(f"Built {len(rows)} findings → {len(made)} file(s) under {STAGE}")
    for p, size, n in made:
        print(f"  {size:>8,} B  {n:>4} rows  {os.path.relpath(p, STAGE)}")

    print(f"\nCampaign timeline (ceiling = DeleteDetector {iso(DELETE_DETECTOR)}):")
    for f in camp:
        if f["updatedAt"] >= iso(DELETE_DETECTOR - timedelta(hours=3)):
            gap = (DELETE_DETECTOR - datetime.strptime(f["updatedAt"], "%Y-%m-%dT%H:%M:%S.%fZ")
                   .replace(tzinfo=timezone.utc)).total_seconds()
            print(f"  {f['updatedAt']}  (-{int(gap):>5}s)  sev {f['severity']:<4} {f['type']}")

    if a.dry_run:
        print("\n--dry-run: nothing uploaded.")
        return
    print()
    upload()
    print("\nNext: python3 guardduty_seed.py --wire   (needs GD_S3_ACCESS_KEY / GD_S3_SECRET)")


if __name__ == "__main__":
    main()

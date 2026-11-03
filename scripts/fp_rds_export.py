#!/usr/bin/env python3
"""Known-false-positive seeder for the ElastiCon workshop (Lab 5).

Emits a BENIGN AWS CloudTrail `StartExportTask` (rds.amazonaws.com, success) performed by
the nightly data-lake export service account `svc-rds-lakeexport`, so the prebuilt rule
**AWS RDS Snapshot Export** (rule_id 119c8877-8613-416d-a98a-96b6664ee73a) fires on data
that is *not* an attack.  The managed Alert analysis workflow
(`system-security-alert-analysis`) then classifies it FALSE_POSITIVE and auto-closes it.

Documents are built with Vandelay Global Industries generator's own CloudTrail emitter
(`vgi_sim.emitters.cloudtrail._ct`) + `envelope.wrap`, so the doc shape, the data stream
(`logs-aws.cloudtrail-prod_uswest`) and the `vgi-sim` teardown tag match every other
AWS document on the cluster.

The benign actor deliberately shares NOTHING with the Skynet attack personas:
new IAM user, AWS-internal source IP, Lambda SDK user agent.

Usage (source the env file with KIBANA_URL / ELASTICSEARCH_URL / *_API_KEY first):

    python3 fp_rds_export.py --live                 # one event, now
    python3 fp_rds_export.py --wait-alert           # poll for the alert the rule creates
    python3 fp_rds_export.py --history 7            # 7 prior-night CLOSED-FP alert copies
    python3 fp_rds_export.py --close-latest         # close newest open alert (false_positive)
    python3 fp_rds_export.py --history-events 7     # FALLBACK path: real events + real alerts
    python3 fp_rds_export.py --status               # what exists right now
    python3 fp_rds_export.py --cleanup              # remove everything this script created
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

def _generator_path():
    """The vgi_sim generator package: $VGI_GENERATOR, else seed-kit/generator next to this script."""
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.environ.get("VGI_GENERATOR", ""), os.path.join(here, "..", "generator")):
        if p and os.path.isdir(os.path.join(p, "vgi_sim")):
            return os.path.abspath(p)
    sys.exit("vgi_sim not found: run from seed-kit/ or set VGI_GENERATOR")


VGI = _generator_path()
sys.path.insert(0, VGI)

from vgi_sim import config                                   # noqa: E402
from vgi_sim.clock import iso_ct, iso_ms                     # noqa: E402
from vgi_sim.emitters import cloudtrail as ct                # noqa: E402
from vgi_sim.entities import AWS_ACCOUNT_PROD, AWS_REGION, NS_PROD_USWEST  # noqa: E402
from vgi_sim.esclient import Client, ElasticError            # noqa: E402
from vgi_sim.scenarios import ds                             # noqa: E402

# --------------------------------------------------------------------------- constants
RULE_ID = "119c8877-8613-416d-a98a-96b6664ee73a"          # prebuilt "AWS RDS Snapshot Export"
ALERTS_INDEX = f".alerts-security.alerts-{os.environ.get('KIBANA_SPACE', 'default')}"
ALERTS_ALIAS = ALERTS_INDEX
NAMESPACE = NS_PROD_USWEST                                 # same namespace as all other AWS data
DATASTREAM = ds("aws.cloudtrail", NAMESPACE)               # logs-aws.cloudtrail-prod_uswest

BENIGN_USER = "svc-rds-lakeexport"
BENIGN_ARN = f"arn:aws:iam::{AWS_ACCOUNT_PROD}:user/{BENIGN_USER}"
BENIGN_UA = ("aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22 "
             "exec-env/AWS_Lambda_provided.al2023 api/rds#1.82.0")
BENIGN_IP = "10.32.60.14"                                  # stable AWS-internal (Lambda ENI)
DB_INSTANCE = "gridvault-telemetry-db"
S3_BUCKET = "vgi-grid-datalake"
S3_PREFIX = "rds-exports/"
EXPORT_ROLE = f"arn:aws:iam::{AWS_ACCOUNT_PROD}:role/vgi-rds-export-lambda"
KMS_KEY = f"arn:aws:kms:{AWS_REGION}:{AWS_ACCOUNT_PROD}:key/9b1f3c5d-7a42-4c8e-9f10-2d6b8e4a7c31"

CLOSER = "dutch.schaefer"
NOTE_TEXT = ("Nightly grid DB export to the data lake — standing change CHG0042 — Dutch")


@dataclass(frozen=True)
class InternalSrc:
    """RFC1918 source — duck-types entities.ExtIP but carries no geo/as (correct for an
    AWS-internal caller; the geoip processor would not enrich a private address)."""
    ip: str

    def source(self) -> dict:
        return {"source": {"ip": self.ip, "address": self.ip}}


LAMBDA_ENI = InternalSrc(BENIGN_IP)


# --------------------------------------------------------------------------- Kibana http
def _kbn(method: str, path: str, body=None, internal: bool = False):
    url = os.environ["KIBANA_URL"].rstrip("/") + path
    headers = {
        "Authorization": "ApiKey " + os.environ["KIBANA_API_KEY"],
        "kbn-xsrf": "true",
        "Accept": "application/json",
    }
    if internal:
        headers["x-elastic-internal-origin"] = "Kibana"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> HTTP {e.code}: {e.read().decode()[:600]}") from None
    return json.loads(raw) if raw.strip() else {}


# --------------------------------------------------------------------------- the event
def snapshot_id(when: datetime) -> str:
    """Automated RDS snapshot identifier, e.g. rds:gridvault-telemetry-db-2026-09-21-02-00."""
    return f"rds:{DB_INSTANCE}-{when.astimezone(timezone.utc):%Y-%m-%d}-02-00"


def start_export_task(when: datetime, namespace: str = NAMESPACE) -> dict:
    """Benign `StartExportTask` built through the VGI CloudTrail emitter (same envelope,
    same `vgi-sim` tag, same data stream as every other AWS doc)."""
    snap = snapshot_id(when)
    task_id = f"{DB_INSTANCE}-lakeexport-{when.astimezone(timezone.utc):%Y%m%d}"
    source_arn = f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_PROD}:snapshot:{snap}"
    req = {
        "exportTaskIdentifier": task_id,
        "sourceArn": source_arn,
        "s3BucketName": S3_BUCKET,
        "s3Prefix": S3_PREFIX,
        "iamRoleArn": EXPORT_ROLE,
        "kmsKeyId": KMS_KEY,
        "exportOnly": ["gridvault_telemetry.asset_readings", "gridvault_telemetry.turbine_events"],
    }
    resp = {
        "exportTaskIdentifier": task_id,
        "sourceArn": source_arn,
        "s3Bucket": S3_BUCKET,
        "s3Prefix": S3_PREFIX,
        "iamRoleArn": EXPORT_ROLE,
        "kmsKeyId": KMS_KEY,
        "status": "STARTING",
        "percentProgress": 0,
        "totalExtractedDataInGB": 0,
        "taskStartTime": iso_ms(when),
        "sourceType": "SNAPSHOT",
    }
    return ct._ct(
        when,
        event_name="StartExportTask",
        event_source="rds.amazonaws.com",
        outcome="success",
        category=["database"],
        etype=["change"],
        namespace=namespace,
        identity_type="IAMUser",
        user_name=BENIGN_USER,
        user_arn=BENIGN_ARN,
        src=LAMBDA_ENI,
        user_agent=BENIGN_UA,
        request_parameters=req,
        response_elements=resp,
    )


# --------------------------------------------------------------------------- actions
def cmd_live(c: Client, when: datetime | None = None, quiet: bool = False) -> dict:
    when = when or datetime.now(timezone.utc)
    doc = start_export_task(when)
    c.bulk(DATASTREAM, [doc], refresh="wait_for")
    if not quiet:
        print(f"  indexed 1 StartExportTask -> {DATASTREAM}  "
              f"(@timestamp {doc['@timestamp']}, snapshot {snapshot_id(when)})")
    return doc


def _es_search(c: Client, index: str, body: dict) -> dict:
    return c.es_req("POST", f"/{index}/_search?ignore_unavailable=true", body)


def latest_alerts(c: Client, size: int = 5, status: str | None = None) -> list[dict]:
    must = [{"term": {"kibana.alert.rule.rule_id": RULE_ID}}]
    if status:
        must.append({"term": {"kibana.alert.workflow_status": status}})
    res = _es_search(c, ALERTS_INDEX, {
        "size": size, "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": must}},
    })
    return res.get("hits", {}).get("hits", [])


def cmd_wait_alert(c: Client, after: datetime, timeout_s: int = 480, poll_s: int = 20) -> dict | None:
    """Poll the alerts index until the rule produces an alert created after `after`."""
    deadline = time.time() + timeout_s
    seen = None
    while time.time() < deadline:
        for h in latest_alerts(c, size=10):
            src = h["_source"]
            ts = src.get("kibana.alert.start") or src.get("@timestamp")
            try:
                when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if when >= after:
                print(f"  ALERT {h['_id']}  start={ts}  status={src.get('kibana.alert.workflow_status')}")
                return h
        seen = int(deadline - time.time())
        print(f"  ...no alert yet ({seen}s budget left)", flush=True)
        time.sleep(poll_s)
    return None


def cmd_history(c: Client, nights: int, note: bool = True, start: int = 1) -> list[str]:
    """Clone the most recent real alert for this rule into N prior nights, already CLOSED
    as a false positive by a human. This is the corpus the managed workflow reads when it
    asks 'how were similar alerts handled?'."""
    hits = latest_alerts(c, size=1)
    if not hits:
        raise SystemExit("no existing alert for the rule to clone — run --live and --wait-alert first")
    base = hits[0]["_source"]
    now = datetime.now(timezone.utc)
    ids: list[str] = []
    bulk_lines: list[str] = []
    for n in range(start, start + nights):
        night = (now - timedelta(days=n)).replace(hour=2, minute=3 + (n % 5), second=17,
                                                  microsecond=0)
        # real alert _ids are 64 hex chars and kibana.alert.uuid mirrors _id — match that
        aid = uuid.uuid4().hex + uuid.uuid4().hex
        auuid = aid
        doc = _retime(base, night)          # rewrite snapshot id + every embedded timestamp
        doc["@timestamp"] = iso_ms(night)
        doc["kibana.alert.uuid"] = auuid
        doc["kibana.alert.start"] = iso_ms(night)
        doc["kibana.alert.last_detected"] = iso_ms(night)
        doc["kibana.alert.original_time"] = iso_ct(night)
        doc["kibana.alert.rule.execution.timestamp"] = iso_ms(night)
        doc["event.ingested"] = iso_ms(night)
        doc["kibana.alert.workflow_status"] = "closed"
        doc["kibana.alert.workflow_reason"] = "false_positive"
        doc["kibana.alert.workflow_status_updated_at"] = iso_ms(night + timedelta(minutes=41))
        doc["kibana.alert.workflow_user"] = CLOSER
        doc["kibana.alert.workflow_assignee_ids"] = []
        doc["kibana.alert.workflow_tags"] = []
        doc["kibana.alert.rule.execution.uuid"] = str(uuid.uuid4())
        doc["kibana.alert.status"] = "active"
        if isinstance(doc.get("kibana.alert.url"), str):
            doc["kibana.alert.url"] = doc["kibana.alert.url"].replace(
                base.get("kibana.alert.uuid", ""), aid)
        bulk_lines.append(json.dumps({"create": {"_index": ALERTS_INDEX, "_id": aid}}))
        bulk_lines.append(json.dumps(doc))
        ids.append(aid)
    res = c.es_req("POST", "/_bulk?refresh=wait_for", "\n".join(bulk_lines) + "\n", ndjson=True)
    errs = [i["create"].get("error") for i in res.get("items", []) if i.get("create", {}).get("error")]
    if errs:
        raise ElasticError(f"alert-history write refused ({len(errs)}): {json.dumps(errs[0])[:400]}")
    print(f"  wrote {len(ids)} closed-FP history alerts into {ALERTS_INDEX}")
    if note:
        for aid in ids:
            try:
                add_note(aid, NOTE_TEXT)
            except Exception as e:                                        # noqa: BLE001
                print(f"  (note for {aid} failed: {e})")
        print(f"  attached analyst notes to {len(ids)} history alerts")
    return ids


def _retime(base: dict, night: datetime) -> dict:
    """Deep-copy the alert and move the whole story back to `night`: the automated snapshot
    identifier, the export task id and every embedded event timestamp (including the ones
    inside the escaped `event.original` JSON blob) are rewritten, so a history alert reads
    exactly like that night's export rather than a copy of tonight's."""
    raw = json.dumps(base)
    base_evt = base.get("kibana.alert.original_time") or base.get("@timestamp")
    base_dt = datetime.fromisoformat(base_evt.replace("Z", "+00:00"))
    # 1) snapshot + task identifiers
    raw = raw.replace(snapshot_id(base_dt), snapshot_id(night))
    raw = raw.replace(f"{DB_INSTANCE}-lakeexport-{base_dt:%Y%m%d}",
                      f"{DB_INSTANCE}-lakeexport-{night:%Y%m%d}")
    # 2) the source event's clock (eventTime / taskStartTime / event.created / ingested)
    raw = raw.replace(f"{base_dt.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%S}",
                      f"{night.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%S}")
    return json.loads(raw)


def add_note(alert_id: str, text: str) -> dict:
    """Security Solution note API. Notes attached to an alert document id."""
    body = {"note": {"eventId": alert_id, "note": text, "timelineId": ""}}
    return _kbn("PATCH", "/api/note", body)


def close_alert(alert_ids: list[str], reason: str = "false_positive") -> dict:
    return _kbn("POST", "/api/detection_engine/signals/status",
                {"signal_ids": alert_ids, "status": "closed", "reason": reason})


def cmd_history_events(c: Client, n: int, spacing_s: int = 400) -> None:
    """FALLBACK path (used only if direct alert-index writes are refused): emit N real
    CloudTrail events spaced past the 5m rule interval, let the rule alert on each, then
    close each alert as a false positive with a note. Background-friendly, logs progress."""
    for i in range(n):
        t0 = datetime.now(timezone.utc)
        cmd_live(c, t0, quiet=True)
        print(f"[{i+1}/{n}] emitted at {iso_ms(t0)}", flush=True)
        hit = cmd_wait_alert(c, t0, timeout_s=480, poll_s=20)
        if hit:
            close_alert([hit["_id"]])
            try:
                add_note(hit["_id"], NOTE_TEXT)
            except Exception as e:                                        # noqa: BLE001
                print(f"  (note failed: {e})", flush=True)
            print(f"[{i+1}/{n}] closed {hit['_id']} as false_positive", flush=True)
        else:
            print(f"[{i+1}/{n}] TIMEOUT waiting for alert", flush=True)
        if i < n - 1:
            time.sleep(spacing_s)


def cmd_status(c: Client) -> None:
    cnt = c.es_req("POST", f"/{DATASTREAM}/_count",
                   {"query": {"bool": {"filter": [{"term": {"user.name": BENIGN_USER}},
                                                  {"term": {"event.action": "StartExportTask"}}]}}})
    print(f"  cloudtrail StartExportTask by {BENIGN_USER}: {cnt.get('count')}")
    res = _es_search(c, ALERTS_INDEX, {
        "size": 0, "query": {"bool": {"filter": [{"term": {"kibana.alert.rule.rule_id": RULE_ID}}]}},
        "aggs": {"st": {"terms": {"field": "kibana.alert.workflow_status"}},
                 "tags": {"terms": {"field": "kibana.alert.workflow_tags", "size": 10}}}})
    print(f"  alerts for rule: {res['hits']['total']['value']}  "
          f"status={[(b['key'], b['doc_count']) for b in res['aggregations']['st']['buckets']]}  "
          f"tags={[(b['key'], b['doc_count']) for b in res['aggregations']['tags']['buckets']]}")


def cmd_cleanup(c: Client) -> None:
    q = {"query": {"bool": {"filter": [
        {"term": {"tags": config.POC_TAG}},
        {"term": {"user.name": BENIGN_USER}},
        {"term": {"event.action": "StartExportTask"}}]}}}
    r = c.es_req("POST", "/logs-aws.cloudtrail-*/_delete_by_query?refresh=true&conflicts=proceed", q)
    print(f"  deleted {r.get('deleted')} CloudTrail StartExportTask docs")
    qa = {"query": {"bool": {"filter": [
        {"term": {"kibana.alert.rule.rule_id": RULE_ID}}]}}}
    # notes first — they are saved objects keyed on the alert _id and would be orphaned
    hits = _es_search(c, ALERTS_INDEX, {"size": 200, "_source": False, **qa})
    purged = 0
    for h in hits.get("hits", {}).get("hits", []):
        try:
            ns = _kbn("GET", f"/api/note?documentIds={h['_id']}").get("notes", [])
            if ns:
                _kbn("DELETE", "/api/note", {"noteIds": [n["noteId"] for n in ns]})
                purged += len(ns)
        except Exception:                                                 # noqa: BLE001
            pass
    print(f"  deleted {purged} analyst/verdict notes")
    try:
        ra = c.es_req("POST", f"/{ALERTS_INDEX}/_delete_by_query?refresh=true&conflicts=proceed", qa)
        print(f"  deleted {ra.get('deleted')} alerts for rule {RULE_ID}")
    except ElasticError as e:
        print(f"  alert delete refused ({e}); close them in the UI instead")
    print("  NOTE: detach the rule from the managed workflow with\n"
          "        POST /internal/security_solution/alert_analysis_workflow/rules/_update\n"
          '        {"detachRuleIds":["f78f48cb-d98c-41e4-8fe0-ce04797b5068"]}')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--live", action="store_true", help="emit one benign StartExportTask now")
    p.add_argument("--wait-alert", action="store_true", help="poll until the rule alerts")
    p.add_argument("--history", type=int, metavar="N",
                   help="clone the latest alert into N prior nights, closed as false_positive")
    p.add_argument("--history-start", type=int, default=1, metavar="D",
                   help="first night offset in days (default 1); use to extend an existing run")
    p.add_argument("--history-events", type=int, metavar="N",
                   help="FALLBACK: emit N spaced real events and close each resulting alert")
    p.add_argument("--close-latest", action="store_true",
                   help="close the newest open alert for the rule (false_positive) + note")
    p.add_argument("--no-notes", action="store_true", help="skip the /api/note calls")
    p.add_argument("--status", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    a = p.parse_args()
    if config.offline():
        print("ERROR: source the env file first (ELASTICSEARCH_URL / *_API_KEY).", file=sys.stderr)
        return 2
    c = Client()
    t0 = datetime.now(timezone.utc)
    if a.cleanup:
        cmd_cleanup(c)
        return 0
    if a.live:
        cmd_live(c, t0)
    if a.wait_alert:
        hit = cmd_wait_alert(c, t0 if a.live else t0 - timedelta(minutes=30))
        if not hit:
            return 1
    if a.history:
        cmd_history(c, a.history, note=not a.no_notes, start=a.history_start)
    if a.history_events:
        cmd_history_events(c, a.history_events)
    if a.close_latest:
        hits = latest_alerts(c, size=1, status="open")
        if not hits:
            print("  no open alert to close")
        else:
            aid = hits[0]["_id"]
            print("  close:", json.dumps(close_alert([aid]))[:200])
            if not a.no_notes:
                try:
                    add_note(aid, NOTE_TEXT)
                    print(f"  note attached to {aid}")
                except Exception as e:                                    # noqa: BLE001
                    print(f"  (note failed: {e})")
    if a.status or not any([a.live, a.wait_alert, a.history, a.history_events, a.close_latest]):
        cmd_status(c)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""crowdstrike emitter — two paths (docs/integrations/crowdstrike.md, rules-crowdstrike-endpoint.md):

  * crowdstrike.fdr   -> logs-crowdstrike.fdr-*   : raw sensor telemetry; ProcessRollup2 events
                          fire ~320 Elastic behavioral EQL rules (the "we detect on your existing
                          CrowdStrike data" story). NOTE ecs.version is 8.17.0 for FDR, observer.*.
  * crowdstrike.alert -> logs-crowdstrike.alert-* : CrowdStrike's own detections; the promotion
                          rule aeebe561 turns each into an Elastic alert (event.kind:alert).

Both are forwarded (aws-s3 / cel API) but carry host.* describing the monitored ENDPOINT.

Rules fired:
  cs_alert (Credential Theft)     -> aeebe561 (CrowdStrike External Alerts, promotion)
  fdr vssadmin delete shadows     -> b5ea4bfe (Volume Shadow Copy Deleted via VssAdmin, high)
  fdr wevtutil cl Security        -> d331bbe2 (Clearing Windows Event Logs)
"""
from __future__ import annotations

import json
import random
import uuid

from ..clock import iso_ms
from ..entities import AGENT_CROWDSTRIKE, CS_CUSTOMER_ID, Endpoint
from ..envelope import wrap

FDR_DATASET = "crowdstrike.fdr"
ALERT_DATASET = "crowdstrike.alert"


def _endpoint_host(ep: Endpoint) -> dict:
    return {"name": ep.name, "hostname": ep.name, "id": ep.aid, "ip": [ep.ip],
            "os": {"type": "windows", "name": "Windows", "platform": "windows",
                   "family": "windows", "version": ep.os_version, "kernel": ep.os_version}}


def fdr_process(ts, ep: Endpoint, *, name: str, args: list[str], command_line: str,
                namespace: str, executable: str | None = None,
                parent_name: str = "cmd.exe", sha256: str | None = None) -> dict:
    pid = random.randint(1000, 999999)
    ppid = random.randint(600, 5000)
    fdr_id = str(uuid.uuid4())
    exe = executable or f"C:\\Windows\\System32\\{name}"
    raw = {
        "event_simpleName": "ProcessRollup2",
        "name": "ProcessRollup2V19",
        "aid": ep.aid, "cid": CS_CUSTOMER_ID, "id": fdr_id,
        "timestamp": str(int(ts.timestamp() * 1000)),
        "event_platform": "Win",
        "ImageFileName": exe.replace("C:\\", "\\Device\\HarddiskVolume2\\"),
        "CommandLine": command_line,
        "RawProcessId": str(pid), "TargetProcessId": str(random.randint(10**17, 10**18)),
        "ParentBaseFileName": parent_name, "UserName": ep.user,
        "SHA256HashData": sha256 or "".join(random.choice("0123456789abcdef") for _ in range(64)),
    }
    body = {
        "@timestamp": iso_ms(ts),
        "ecs": {"version": "8.17.0"},  # FDR pins 8.17.0 (not 8.11.0)
        "event": {"kind": "event", "category": ["process"], "type": ["start"],
                  "action": "ProcessRollup2", "module": "crowdstrike",
                  "original": json.dumps(raw, separators=(",", ":"))},
        "observer": {"vendor": "crowdstrike", "type": "agent", "product": "Falcon"},
        "crowdstrike": {"event_simpleName": "ProcessRollup2", "name": "ProcessRollup2V19",
                        "aid": ep.aid, "cid": CS_CUSTOMER_ID},
        "process": {"name": name, "args": args, "command_line": command_line, "pid": pid,
                    "executable": exe,
                    "parent": {"name": parent_name, "pid": ppid},
                    "hash": {"sha256": raw["SHA256HashData"]}},
        "host": _endpoint_host(ep),
        "user": {"name": ep.user},
        "input": {"type": "aws-s3"},
        "aws": {"s3": {"bucket": {"name": "vandelay-crowdstrike-fdr"},
                       "object": {"key": f"data/{fdr_id}.gz"}}},
        "related": {"hosts": [ep.name], "user": [ep.user], "hash": [raw["SHA256HashData"]]},
    }
    return wrap(body, dataset=FDR_DATASET, namespace=namespace, agent=AGENT_CROWDSTRIKE,
               forwarded=True, tags=["crowdstrike-fdr"])


def _fdr_common(ts, ep: Endpoint, raw: dict, ecs: dict) -> dict:
    """Shared envelope for non-process FDR telemetry (dns / network) — mappings verified in
    docs/integrations/crowdstrike.md §2.4/2.5: aid -> device.id/host.id/observer.serial_number,
    aip (sensor public IP) -> observer.address/ip, event.id = id|aid|cid."""
    body = {
        "@timestamp": iso_ms(ts),
        "ecs": {"version": "8.17.0"},
        "event": {"kind": "event", "module": "crowdstrike",
                  "id": f"{raw['id']}|{ep.aid}|{CS_CUSTOMER_ID}",
                  "created": iso_ms(ts),
                  "original": json.dumps(raw, separators=(",", ":")), **ecs.pop("event")},
        "observer": {"vendor": "crowdstrike", "type": "agent", "product": "Falcon",
                     "address": [raw["aip"]], "ip": [raw["aip"]],
                     "serial_number": ep.aid, "version": raw["ConfigBuild"]},
        "device": {"id": ep.aid},
        "crowdstrike": {"event_simpleName": raw["event_simpleName"], "name": raw["name"],
                        "cid": CS_CUSTOMER_ID, "id": raw["id"],
                        "ContextProcessId": raw["ContextProcessId"]},
        "process": {"entity_id": raw["ContextProcessId"]},
        "host": _endpoint_host(ep),
        "input": {"type": "aws-s3"},
        "aws": {"s3": {"bucket": {"name": "vandelay-crowdstrike-fdr"},
                       "object": {"key": f"data/{raw['id']}.gz"}}},
        **ecs,
    }
    return body


def fdr_dns_request(ts, ep: Endpoint, *, domain: str, namespace: str,
                    sensor_public_ip: str = "198.51.100.10",
                    context_process_id: str | None = None) -> dict:
    """DnsRequest FDR telemetry — the endpoint resolving a (C2) domain."""
    parts = domain.split(".")
    cpid = context_process_id or str(random.randint(10**17, 10**18))
    fdr_id = str(uuid.uuid4())
    raw = {
        "event_simpleName": "DnsRequest", "name": "DnsRequestWinV4",
        "aid": ep.aid, "cid": CS_CUSTOMER_ID, "id": fdr_id,
        "timestamp": str(int(ts.timestamp() * 1000)),
        "ContextTimeStamp": f"{ts.timestamp() - 0.3:.3f}",
        "ContextProcessId": cpid, "ContextThreadId": "0",
        "aip": sensor_public_ip, "ConfigBuild": "1007.4.0019811.1",
        "event_platform": "Win", "DomainName": domain, "RequestType": "1",
    }
    ecs = {
        "event": {"action": "DnsRequest", "category": ["network"],
                  "type": ["protocol"], "outcome": "success"},
        "dns": {"type": "query",
                "question": {"name": domain, "type": "A",
                             "registered_domain": ".".join(parts[-2:]),
                             "subdomain": ".".join(parts[:-2]) or None,
                             "top_level_domain": parts[-1]}},
        "network": {"protocol": "dns"},
        "related": {"hosts": [ep.name, domain], "ip": [sensor_public_ip]},
    }
    if ecs["dns"]["question"]["subdomain"] is None:
        del ecs["dns"]["question"]["subdomain"]
    body = _fdr_common(ts, ep, raw, ecs)
    return wrap(body, dataset=FDR_DATASET, namespace=namespace, agent=AGENT_CROWDSTRIKE,
                forwarded=True, tags=["crowdstrike-fdr"])


def fdr_network_connect(ts, ep: Endpoint, *, dst_ip: str, dst_port: int, namespace: str,
                        src_port: int | None = None, sensor_public_ip: str = "198.51.100.10",
                        context_process_id: str | None = None) -> dict:
    """NetworkConnectIP4 FDR telemetry — outbound TCP connect (e.g. the C2 beacon)."""
    from .panw import community_id  # same algorithm the panw pipeline uses
    sport = src_port or random.randint(49152, 65000)
    cpid = context_process_id or str(random.randint(10**17, 10**18))
    fdr_id = str(uuid.uuid4())
    raw = {
        "event_simpleName": "NetworkConnectIP4", "name": "NetworkConnectIP4WinV10",
        "aid": ep.aid, "cid": CS_CUSTOMER_ID, "id": fdr_id,
        "timestamp": str(int(ts.timestamp() * 1000)),
        "ContextTimeStamp": f"{ts.timestamp() - 0.2:.3f}",
        "ContextProcessId": cpid, "ConnectionFlags": "0", "ConnectionDirection": "0",
        "InContext": "0", "aip": sensor_public_ip, "ConfigBuild": "1007.4.0019811.1",
        "event_platform": "Win", "Protocol": "6",
        "LocalAddressIP4": ep.ip, "LocalPort": str(sport),
        "RemoteAddressIP4": dst_ip, "RemotePort": str(dst_port),
    }
    ecs = {
        "event": {"action": "NetworkConnectIP4", "category": ["network"],
                  "type": ["start", "connection"], "outcome": "unknown"},
        "source": {"ip": ep.ip, "address": ep.ip, "port": sport},
        "destination": {"ip": dst_ip, "address": dst_ip, "port": dst_port},
        "network": {"direction": "outbound", "iana_number": "6", "transport": "tcp",
                    "community_id": community_id(ep.ip, dst_ip, sport, dst_port)},
        "related": {"hosts": [ep.name], "ip": [ep.ip, dst_ip, sensor_public_ip]},
    }
    body = _fdr_common(ts, ep, raw, ecs)
    return wrap(body, dataset=FDR_DATASET, namespace=namespace, agent=AGENT_CROWDSTRIKE,
                forwarded=True, tags=["crowdstrike-fdr"])


def vssadmin_delete_shadows(ts, ep: Endpoint, *, namespace: str) -> dict:
    return fdr_process(ts, ep, name="vssadmin.exe",
                       args=["vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
                       command_line="vssadmin delete shadows /all /quiet", namespace=namespace)


def clear_event_logs(ts, ep: Endpoint, *, namespace: str) -> dict:
    return fdr_process(ts, ep, name="wevtutil.exe",
                       args=["wevtutil.exe", "cl", "Security"],
                       command_line="wevtutil cl Security", namespace=namespace)


def cs_alert(ts, ep: Endpoint, *, namespace: str,
             name: str = "Credential Theft via LSASS Memory Access",
             tactic: str = "Credential Access", technique: str = "OS Credential Dumping",
             severity: int = 73) -> dict:
    detect_id = "ldt:" + uuid.uuid4().hex + ":" + str(random.randint(10**11, 10**12))
    body = {
        "@timestamp": iso_ms(ts),
        "event": {"kind": "alert", "module": "crowdstrike", "category": ["malware"],
                  "type": ["info"], "action": "Process Terminated", "severity": severity,
                  "dataset": ALERT_DATASET,
                  "reference": f"https://falcon.crowdstrike.com/activity/detections/detail/{detect_id}"},
        "message": name,
        "rule": {"name": name, "id": detect_id,
                 "description": f"{name} detected on {ep.name}"},
        "crowdstrike": {"alert": {
            "name": name, "description": f"{name} detected on {ep.name}",
            "severity": 70, "tactic": tactic, "technique": technique,
            "status": "new", "show_in_ui": True,
            "incident": {"score": severity},
            "device": {"hostname": ep.name, "platform_name": "Windows"}}},
        "threat": {"framework": "CrowdStrike Falcon Detections Framework",
                   "tactic": {"name": tactic}, "technique": {"name": technique}},
        "process": {"name": "mimikatz.exe", "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                    "pid": random.randint(1000, 60000)},
        "host": _endpoint_host(ep),
        "user": {"name": ep.user},
        "related": {"hosts": [ep.name], "user": [ep.user]},
    }
    return wrap(body, dataset=ALERT_DATASET, namespace=namespace, agent=AGENT_CROWDSTRIKE,
               forwarded=True, tags=["crowdstrike-alert"])


def attach_stage(r, tl, *, namespace: str, endpoint: Endpoint) -> None:
    """Stage 8 — endpoint / credential access on a CrowdStrike-managed Windows host."""
    fdr_ds = f"logs-{FDR_DATASET}-{namespace}"
    alert_ds = f"logs-{ALERT_DATASET}-{namespace}"
    # Elastic behavioral rules fire on CrowdStrike FDR telemetry:
    r.add(fdr_ds, vssadmin_delete_shadows(tl.advance(20), endpoint, namespace=namespace))
    r.expect("b5ea4bfe-a1b2-421f-9d47-22a75a6f2921", "Volume Shadow Copy Deleted or Resized via VssAdmin")
    r.add(fdr_ds, clear_event_logs(tl.advance(12), endpoint, namespace=namespace))
    r.expect("d331bbe2-6db4-4941-80a5-8270db72eb61", "Clearing Windows Event Logs")
    # CrowdStrike's own detection, promoted into an Elastic alert:
    r.add(alert_ds, cs_alert(tl.advance(15), endpoint, namespace=namespace))
    r.expect("aeebe561-c338-4118-9924-8cb4e478aa58", "CrowdStrike External Alerts")

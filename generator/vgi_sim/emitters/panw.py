"""panw emitter — Palo Alto PAN-OS firewall logs (docs/integrations/panw-panos.md).

ONE data stream carries every PAN-OS log type: logs-panw.panos-<namespace>, discriminated
by panw.panos.type (TRAFFIC / THREAT / ...) + sub_type. Docs are the post-pipeline shape at
DEFAULT integration config (duplicated panw.panos.* copies of ECS fields pruned, no
event.original) — mirror sample_event.json, NOT the _dev/test expected docs (preserve tags).

Envelope quirks vs. the other emitters:
  * filebeat agent receiving syslog over TCP -> input.type tcp + log.syslog block
  * NO host.* — the firewall is observer.* (vendor/product/serial + ingress/egress zones)
  * ecs.version pinned 8.17.0 (panw package), overriding the wrap() default
  * event.module=panw / event.dataset=panw.panos are constant_keyword in the mapping —
    they MUST be exactly these values (wrap() derives both from the dataset, so they are)

Rules fired:
  threat(sub_type=spyware, severity=medium) x<=5 within 10 min -> 283683eb (Newly Observed
  Palo Alto Network Alert, ESQL, keys on @timestamp — anchor docs near now, like the SSH
  brute-force rule). Traffic docs are context/hunt fodder (no doc-range-safe prebuilt rule).
"""
from __future__ import annotations

import base64
import hashlib
import random
import socket
import struct
from datetime import timedelta

from ..clock import iso_ct
from ..entities import (
    AGENT_PANW,
    PAN_FW,
    PAN_IF_INSIDE,
    PAN_IF_OUTSIDE,
    PAN_ZONE_TRUST,
    PAN_ZONE_UNTRUST,
    ExtIP,
)
from ..envelope import wrap

DATASET = "panw.panos"

# The syslog collector agent's listener (log.source.address on every doc).
_COLLECTOR_IP = "10.32.6.30"

# PAN-OS severity string -> event.severity (default.yml map) + syslog severity.
_SEVERITY = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}
_SYSLOG_SEV = {"critical": (2, "Critical"), "high": (3, "Error"), "medium": (4, "Warning"),
               "low": (5, "Notice"), "informational": (6, "Informational")}

# THREAT sub_type -> event.action (default.yml lookup table).
_THREAT_ACTION = {
    "data": "data_match", "file": "file_match", "flood": "flood_detected",
    "packet": "packet_attack", "scan": "scan_detected", "spyware": "spyware_detected",
    "url": "url_filtering", "virus": "virus_detected", "vulnerability": "exploit_detected",
    "wildfire": "wildfire_verdict", "wildfire-virus": "wildfire_virus_detected",
}

_ALLOWED_ACTIONS = {"alert", "allow", "continue"}


def community_id(saddr: str, daddr: str, sport: int, dport: int, proto: int = 6) -> str:
    """Real community-id v1 (seed 0) — matches what the panw pipeline computes."""
    src, dst = socket.inet_aton(saddr), socket.inet_aton(daddr)
    if (src, sport) > (dst, dport):
        src, dst, sport, dport = dst, src, dport, sport
    data = struct.pack("!H", 0) + src + dst + struct.pack("!BBHH", proto, 0, sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()


def _syslog(ts, severity: str) -> dict:
    code, name = _SYSLOG_SEV[severity]
    return {
        "input": {"type": "tcp"},
        "log": {
            "level": severity,
            "source": {"address": f"{_COLLECTOR_IP}:{random.randint(40000, 65000)}"},
            "syslog": {
                "facility": {"code": 1, "name": "user-level"},
                "priority": 8 + code,
                "severity": {"code": code, "name": name},
                "hostname": PAN_FW.name,
            },
        },
    }


def _observer() -> dict:
    return {
        "observer": {
            "hostname": PAN_FW.name,
            "serial_number": PAN_FW.serial,
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "type": "firewall",
            "ingress": {"interface": {"name": PAN_IF_INSIDE}, "zone": PAN_ZONE_TRUST},
            "egress": {"interface": {"name": PAN_IF_OUTSIDE}, "zone": PAN_ZONE_UNTRUST},
        }
    }


def _dest(dst: ExtIP, port: int) -> dict:
    return {
        "ip": dst.ip, "port": port,
        "geo": {"name": dst.country, "city_name": dst.city, "country_iso_code": dst.country_iso,
                "country_name": dst.country, "continent_name": dst.continent,
                "location": {"lat": dst.lat, "lon": dst.lon}},
        "as": {"number": dst.asn, "organization": {"name": dst.as_org}},
    }


def _wrap(body: dict, ts, *, severity: str, namespace: str) -> dict:
    body.setdefault("ecs", {"version": "8.17.0"})  # panw pins 8.17.0 (not the wrap default)
    for k, v in _syslog(ts, severity).items():
        body.setdefault(k, v)
    return wrap(body, dataset=DATASET, namespace=namespace, agent=AGENT_PANW,
                forwarded=True, tags=["panw-panos"])


def traffic(ts, *, src_ip: str, dst: ExtIP, dst_port: int = 443, src_port: int | None = None,
            app: str = "ssl", transport: str = "tcp", action: str = "allow",
            sub_type: str = "end", bytes_out: int = 1420, bytes_in: int = 618,
            packets_out: int = 12, packets_in: int = 9, duration_s: int = 10,
            rule_name: str = "allow-outbound-web", src_user: str | None = None,
            namespace: str = "prod_uswest") -> dict:
    """One TRAFFIC log (sub_type start/end/deny/drop) — internal host -> internet."""
    sport = src_port or random.randint(49152, 65000)
    allowed = action in _ALLOWED_ACTIONS
    ev_action = {"start": "flow_started", "end": "flow_terminated",
                 "deny": "flow_denied", "drop": "flow_dropped"}[sub_type]
    ev_type = (["allowed"] if allowed else ["denied"]) + (
        {"start": ["start", "connection"], "end": ["end", "connection"]}.get(sub_type, ["connection"]))
    start_dt = ts - timedelta(seconds=duration_s)

    body = {
        "@timestamp": iso_ct(ts),
        "event": {"kind": "event", "category": ["network"], "type": ev_type,
                  "action": ev_action, "outcome": "success" if action == "allow" else "failure",
                  "start": iso_ct(start_dt), "end": iso_ct(ts) if sub_type == "end" else None,
                  "duration": duration_s * 1_000_000_000, "timezone": "UTC"},
        "network": {"application": app, "transport": transport, "type": "ipv4",
                    "direction": "outbound",
                    "bytes": bytes_out + bytes_in,
                    "packets": packets_out + packets_in,
                    "community_id": community_id(src_ip, dst.ip, sport, dst_port,
                                                 6 if transport == "tcp" else 17)},
        "source": {"ip": src_ip, "port": sport, "bytes": bytes_out, "packets": packets_out,
                   "geo": {"name": "10.0.0.0-10.255.255.255"}},
        "destination": {**_dest(dst, dst_port), "bytes": bytes_in, "packets": packets_in},
        "rule": {"name": rule_name},
        "related": {"ip": [src_ip, dst.ip], "hosts": [PAN_FW.name]},
        "panw": {"panos": {
            "type": "TRAFFIC", "sub_type": sub_type, "action": action,
            "action_flags": "0x0", "action_source": "from-policy",
            "endreason": "tcp-fin" if sub_type == "end" else ("policy-deny" if not allowed else "n/a"),
            "flow_id": str(random.randint(10000, 99999)),
            "generated_time": iso_ct(ts), "received_time": iso_ct(ts),
            "inbound_interface": PAN_IF_INSIDE, "outbound_interface": PAN_IF_OUTSIDE,
            "log_profile": "forward-to-elastic", "parent_session": {"id": "0"},
            "repeat_count": 1, "ruleset": rule_name,
            "sequence_number": str(random.randint(10**7, 10**8)),
            "tunnel_type": "N/A", "url": {"category": "computer-and-internet-info"},
            "virtual_sys": "vsys1",
        }},
    }
    if body["event"]["end"] is None:
        del body["event"]["end"]
    if src_user:
        body["source"]["user"] = {"name": src_user}
        body["user"] = {"name": src_user}
        body["related"]["user"] = [src_user]
    return _wrap(body, ts, severity="informational", namespace=namespace)


def threat(ts, *, src_ip: str, dst: ExtIP, dst_port: int = 443, src_port: int | None = None,
           sub_type: str = "spyware", severity: str = "medium", action: str = "alert",
           threat_id: str = "86672", threat_name: str = "Spyware Command and Control Traffic",
           threat_category: str = "spyware", domain: str | None = None,
           url_path: str = "/", app: str = "ssl", rule_name: str = "allow-outbound-web",
           src_user: str | None = None, namespace: str = "prod_uswest") -> dict:
    """One THREAT log (kind=alert). severity medium+ feeds prebuilt rule 283683eb."""
    sport = src_port or random.randint(49152, 65000)
    allowed = action in _ALLOWED_ACTIONS
    body = {
        "@timestamp": iso_ct(ts),
        "event": {"kind": "alert",
                  "category": ["intrusion_detection", "threat", "network"],
                  "type": ["allowed"] if allowed else ["denied"],
                  "action": _THREAT_ACTION[sub_type],
                  "outcome": "success" if allowed else "failure",
                  "severity": _SEVERITY[severity], "timezone": "UTC"},
        "network": {"application": app, "transport": "tcp", "type": "ipv4",
                    # threat direction 0/client-to-server -> "inbound" (pipeline quirk, faithful)
                    "direction": "inbound",
                    "community_id": community_id(src_ip, dst.ip, sport, dst_port)},
        "source": {"ip": src_ip, "port": sport, "geo": {"name": "10.0.0.0-10.255.255.255"}},
        "destination": _dest(dst, dst_port),
        "rule": {"name": rule_name},
        "related": {"ip": [src_ip, dst.ip], "hosts": [PAN_FW.name]},
        "panw": {"panos": {
            "type": "THREAT", "sub_type": sub_type, "action": action, "action_flags": "0x0",
            "flow_id": str(random.randint(10000, 99999)),
            "generated_time": iso_ct(ts), "received_time": iso_ct(ts), "logged_time": iso_ct(ts),
            "log_profile": "forward-to-elastic", "repeat_count": 1, "ruleset": rule_name,
            "sequence_number": str(random.randint(10**7, 10**8)),
            "threat": {"id": threat_id, "name": threat_name},
            "threat_category": threat_category,
            "url": {"category": "command-and-control" if sub_type == "spyware" else "not-resolved"},
            "virtual_sys": "vsys1",
        }},
    }
    if domain:
        body["destination"]["domain"] = domain
        body["url"] = {"domain": domain, "original": f"{domain}{url_path}", "path": url_path}
        body["message"] = f"{domain}{url_path}"
    if src_user:
        body["source"]["user"] = {"name": src_user}
        body["user"] = {"name": src_user}
        body["related"]["user"] = [src_user]
    return _wrap(body, ts, severity=severity, namespace=namespace)

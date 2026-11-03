"""Scenario D — "Axios C2": supply-chain compromise beaconing through the PAN firewall
(the VGI port of the Vibin "Axios threat hunt" demo — see workflows/vgi-daily-threat-hunt.yaml).

Story: a GridVault UI developer's laptop (VGI-LT-4471 / j.kimble) runs `npm install`; the
trojaned `plain-crypto-js` dependency's postinstall drops a RAT that beacons to
cdn.plain-crypto-js.dev every ~4 minutes. Three data planes tell the story:

  * vgi-threat-intel (plain index)      — the IOC watchlist the daily hunt workflow reads:
                                          domain + IP + RAT sha256 indicators
  * logs-panw.panos-*   (PAN firewall)  — TRAFFIC beacons to the C2 + THREAT spyware alerts
                                          carrying the malicious DOMAIN (url/destination.domain)
  * logs-crowdstrike.fdr-* (endpoint)   — ProcessRollup2 (node postinstall), DnsRequest
                                          (the domain!), NetworkConnectIP4 — the HOST evidence
                                          the hunt pivots to: host.name / host.ip / user / hash

Prebuilt rule: the 3 THREAT spyware docs (severity medium, <=5 count, anchored to the last
~6 min) satisfy 283683eb "Newly Observed Palo Alto Network Alert" (ESQL, keys on @timestamp,
10-minute recency — run the hunt/rules soon after seeding). The domain hunt itself is the
custom daily-threat-hunt workflow's job.
"""
from __future__ import annotations

import random

from ..clock import Timeline, iso_ms
from ..config import POC_TAG
from ..emitters import crowdstrike as cs
from ..emitters import panw
from ..entities import (
    C2_DOMAIN,
    C2_HOST,
    NS_PROD_USWEST,
    RAT_SHA256,
    TROJAN_PACKAGE,
    WIN_ENDPOINTS,
)
from . import ScenarioResult, ds

INTEL_INDEX = "vgi-threat-intel"
DEV = WIN_ENDPOINTS[0]  # VGI-LT-4471, 10.32.88.71, j.kimble — the GridVault UI developer

INTEL_MAPPING = {
    "properties": {
        "@timestamp": {"type": "date"},
        "tags": {"type": "keyword"},
        "event": {"properties": {"kind": {"type": "keyword"},
                                 "category": {"type": "keyword"},
                                 "type": {"type": "keyword"}}},
        "threat": {"properties": {
            "feed": {"properties": {"name": {"type": "keyword"}}},
            "software": {"properties": {"name": {"type": "keyword"}}},
            "indicator": {"properties": {
                "type": {"type": "keyword"},
                "name": {"type": "keyword"},
                "description": {"type": "text"},
                "confidence": {"type": "keyword"},
                "provider": {"type": "keyword"},
                "reference": {"type": "keyword"},
                "first_seen": {"type": "date"},
            }},
        }},
    }
}


def _indicator(ts, *, ind_type: str, name: str, description: str) -> dict:
    return {
        "@timestamp": iso_ms(ts),
        "event": {"kind": "enrichment", "category": ["threat"], "type": ["indicator"]},
        "threat": {
            "feed": {"name": "vgi-threat-intel"},
            "software": {"name": "PlainCrypto RAT"},
            "indicator": {
                "type": ind_type, "name": name, "description": description,
                "confidence": "High", "provider": "Elastic Security Labs",
                "reference": "https://www.elastic.co/security-labs (Axios supply-chain briefing)",
                "first_seen": iso_ms(ts),
            },
        },
        "tags": [POC_TAG, "axios-supply-chain"],
    }


def build(namespace: str = NS_PROD_USWEST) -> ScenarioResult:
    r = ScenarioResult("axios_c2")
    r.index_mappings[INTEL_INDEX] = INTEL_MAPPING
    tl = Timeline(start_offset_s=-1800)  # 30 min ago
    fdr_ds = ds("crowdstrike.fdr", namespace)
    pan_ds = ds("panw.panos", namespace)

    # ── Threat intel watchlist (what the daily hunt workflow reads) ────────────
    t_intel = tl.at(0)
    r.add(INTEL_INDEX, _indicator(
        t_intel, ind_type="domain-name", name=C2_DOMAIN,
        description=f"C2 domain for the {TROJAN_PACKAGE} npm supply-chain compromise "
                    "(Axios ecosystem); RAT delivered via malicious postinstall hook."))
    r.add(INTEL_INDEX, _indicator(
        t_intel, ind_type="ipv4-addr", name=C2_HOST.ip,
        description=f"C2 server behind {C2_DOMAIN} ({C2_HOST.as_org}, AS{C2_HOST.asn})."))
    r.add(INTEL_INDEX, _indicator(
        t_intel, ind_type="file-sha256", name=RAT_SHA256,
        description=f"PlainCrypto RAT dropper (node postinstall payload in {TROJAN_PACKAGE})."))

    # ── Initial compromise: npm postinstall spawns the RAT ─────────────────────
    rat_pid = str(random.randint(10**17, 10**18))  # ContextProcessId shared by beacons
    r.add(fdr_ds, cs.fdr_process(
        tl.advance(5), DEV,
        name="node.exe",
        executable="C:\\Program Files\\nodejs\\node.exe",
        parent_name="cmd.exe",  # npm runs lifecycle scripts through cmd.exe on Windows
        args=["node", f"node_modules\\{TROJAN_PACKAGE}\\scripts\\postinstall.js"],
        command_line=f"node C:\\Users\\{DEV.user}\\gridvault-ui\\node_modules\\{TROJAN_PACKAGE}"
                     "\\scripts\\postinstall.js",
        sha256=RAT_SHA256, namespace=namespace))

    # ── Beacon loop: DNS -> connect -> PAN session, every ~4 min ──────────────
    for i in range(6):
        t = tl.advance(200 + random.randint(0, 40))
        r.add(fdr_ds, cs.fdr_dns_request(t, DEV, domain=C2_DOMAIN, namespace=namespace,
                                         context_process_id=rat_pid))
        r.add(fdr_ds, cs.fdr_network_connect(tl.advance(1), DEV, dst_ip=C2_HOST.ip,
                                             dst_port=443, namespace=namespace,
                                             context_process_id=rat_pid))
        r.add(pan_ds, panw.traffic(tl.advance(8), src_ip=DEV.ip, dst=C2_HOST, dst_port=443,
                                   app="ssl", sub_type="end", duration_s=8,
                                   bytes_out=1380 + random.randint(0, 200),
                                   bytes_in=590 + random.randint(0, 120),
                                   src_user=DEV.user, namespace=namespace))

    # ── The last beacons trip the PAN anti-spyware signature (THREAT, medium) ──
    # 3 docs / medium severity / anchored to the final minutes -> rule 283683eb's
    # ESQL constraints (severity<=3, <=5 alerts, <=2 src/dst, first_seen <=10 min ago).
    for i in range(3):
        r.add(pan_ds, panw.threat(
            tl.advance(70), src_ip=DEV.ip, dst=C2_HOST, dst_port=443,
            sub_type="spyware", severity="medium", action="alert",
            threat_id="86672", threat_name="PlainCrypto RAT Command and Control Traffic",
            threat_category="spyware", domain=C2_DOMAIN, url_path="/api/v2/telemetry",
            app="ssl", src_user=DEV.user, namespace=namespace))
    r.expect("283683eb-f2ce-40a5-be16-fa931cb5f504", "Newly Observed Palo Alto Network Alert")

    r.note(f"Hunt thread: {INTEL_INDEX} watchlist -> domain {C2_DOMAIN} in panw.panos "
           f"(url.domain / destination.domain) -> src ip {DEV.ip} -> crowdstrike.fdr "
           f"DnsRequest/NetworkConnect/ProcessRollup2 on {DEV.name} (user {DEV.user}, "
           f"sha256 {RAT_SHA256[:12]}…). Driven by the 'MOTHER — Daily Threat Hunt' workflow "
           "(24h schedule). Rule 283683eb keys on @timestamp: expect it only if it runs "
           "within ~10 min of seeding.")
    return r

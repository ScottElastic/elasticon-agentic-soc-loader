"""Steady-state background traffic — makes the environment look lived-in, at the DIMA volume
mix (container logs dominate ~56%, then FDR, AWS, syslog, metrics). All benign and near-now,
so it populates dashboards / Discover / Entity Analytics without tripping detection rules.

Not a scenario (no attack) — indexed via `run.py background`.
"""
from __future__ import annotations

import random
from datetime import timedelta

from .clock import now_utc
from .emitters import cloudtrail as ct
from .emitters import container_logs as cl
from .emitters import crowdstrike as cs
from .emitters import system_auth as auth
from .emitters import system_process as sp
from .emitters import waf
from .entities import (ADMINS, LINUX_HOSTS, NS_PROD_USWEST, SCANNER, WIN_ENDPOINTS)
from .scenarios import ScenarioResult, ds

# a stable set of internal jump-box IPs so new_terms rules don't burst on benign logins
_OFFICE_IPS = ["10.32.2.15", "10.32.2.16", "10.32.2.17", "10.32.2.18"]
# (name, args, executable, parent) — real Windows paths + realistic parents so benign MS
# binaries don't trip signature rules. explorer.exe MUST live at C:\Windows\explorer.exe (NOT
# System32): the "DLL Side-Loading via Trusted Microsoft Programs" EQL rule allowlists the real
# path, so the old System32\explorer.exe + cmd.exe parent was a self-inflicted false positive.
_BENIGN_FDR = [
    ("svchost.exe", ["svchost.exe", "-k", "netsvcs"],
     "C:\\Windows\\System32\\svchost.exe", "services.exe"),
    ("chrome.exe", ["chrome.exe", "--type=renderer"],
     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe"),
    ("explorer.exe", ["explorer.exe"],
     "C:\\Windows\\explorer.exe", "userinit.exe"),
    ("MsMpEng.exe", ["MsMpEng.exe"],
     "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080.9-0\\MsMpEng.exe",
     "services.exe"),
]


def build(namespace: str = NS_PROD_USWEST, minutes: int = 15, scale: float = 1.0) -> ScenarioResult:
    r = ScenarioResult("background")
    now = now_utc()

    def rt() -> "any":
        return now - timedelta(seconds=random.randint(0, minutes * 60))

    # Container logs — the volume king (~56% of their ingest)
    for _ in range(int(220 * scale)):
        r.add(ds("kubernetes.container_logs", namespace),
              cl.info_line(rt(), namespace=namespace,
                          service=random.choice(["asset-svc", "timeseries-svc", "ingestion-router",
                                                 "edge-gateway", "apm-operations-svc"])))

    # CrowdStrike FDR benign process telemetry (~9%)
    for _ in range(int(40 * scale)):
        name, args, exe, parent = random.choice(_BENIGN_FDR)
        ep = random.choice(WIN_ENDPOINTS)
        r.add(ds("crowdstrike.fdr", namespace),
              cs.fdr_process(rt(), ep, name=name, args=args, command_line=" ".join(args),
                             executable=exe, parent_name=parent, namespace=namespace))

    # WAF — normal allowed traffic + a low hum of blocked scanners
    for _ in range(int(30 * scale)):
        r.add(ds("aws.waf", namespace), waf.waf_event(rt(), namespace=namespace, src=SCANNER,
                                                     action="ALLOW", uri="/v2/assets", condition_type=None))
    for _ in range(int(6 * scale)):
        r.add(ds("aws.waf", namespace), waf.probe(rt(), namespace=namespace, src=SCANNER))

    # system.auth — benign internal SSH success
    for _ in range(int(15 * scale)):
        host = random.choice(LINUX_HOSTS)
        r.add(ds("system.auth", namespace),
              auth.ssh_login(rt(), host=host, user=random.choice(ADMINS),
                            src=random.choice(_OFFICE_IPS), outcome="success",
                            namespace=namespace, method="publickey"))

    # CloudTrail — routine read-only API activity
    for _ in range(int(25 * scale)):
        r.add(ds("aws.cloudtrail", namespace),
              ct.readonly(rt(), namespace=namespace,
                         action=random.choice(["DescribeInstances", "ListBuckets", "AssumeRole",
                                               "DescribeLogStreams", "GetParameters"])))

    # metrics-system.process — recent samples per Linux host (TSDS window)
    for host in LINUX_HOSTS:
        for k in range(6):
            t = now - timedelta(minutes=(12 - k * 2))
            for doc in sp.host_process_sample(t, host, namespace=namespace):
                r.add(ds("system.process", namespace, metrics=True), doc)

    r.note(f"Steady-state background: {len(r.events)} docs over the last {minutes} min at the "
           f"DIMA volume mix. Benign — should not trigger detection rules (a few low-sev new_terms "
           f"'unusual IP/user' alerts may fire once on first ingest in a fresh cluster).")
    return r


def seed_history(namespace: str = NS_PROD_USWEST, days: int = 30, per_day: int = 120) -> ScenarioResult:
    """Backfill thinned LOG history so dashboards / Entity Analytics / trends aren't day-one
    empty. LOG datasets only — metrics-system.process is a TSDS and cannot be backfilled beyond
    ~2h (docs/ecs §5(d)); generate metrics live instead. @timestamp is spread across the past
    `days`; event.ingested is stamped at write time, so rules with the override could still see
    these — prefer running with rules disabled, or use rule backfill for historical alerts."""
    r = ScenarioResult("seed_history")
    now = now_utc()
    for d in range(days):
        for _ in range(per_day):
            t = now - timedelta(days=d, seconds=random.randint(0, 86400))
            roll = random.random()
            if roll < 0.6:
                r.add(ds("kubernetes.container_logs", namespace),
                      cl.info_line(t, namespace=namespace,
                                  service=random.choice(["asset-svc", "timeseries-svc", "edge-gateway"])))
            elif roll < 0.75:
                name, args, exe, parent = random.choice(_BENIGN_FDR)
                r.add(ds("crowdstrike.fdr", namespace),
                      cs.fdr_process(t, random.choice(WIN_ENDPOINTS), name=name, args=args,
                                    command_line=" ".join(args), executable=exe,
                                    parent_name=parent, namespace=namespace))
            elif roll < 0.85:
                r.add(ds("aws.cloudtrail", namespace), ct.readonly(t, namespace=namespace))
            elif roll < 0.93:
                r.add(ds("aws.waf", namespace),
                      waf.waf_event(t, namespace=namespace, src=SCANNER, action="ALLOW", condition_type=None))
            else:
                r.add(ds("system.auth", namespace),
                      auth.ssh_login(t, host=random.choice(LINUX_HOSTS), user=random.choice(ADMINS),
                                    src=random.choice(_OFFICE_IPS), outcome="success",
                                    namespace=namespace, method="publickey"))
    r.note(f"Backfilled {len(r.events)} log docs across {days} days. Disable detection rules while "
           f"seeding (event.ingested=now would otherwise let override rules match), or seed first "
           f"then enable rules. Metrics are NOT backfilled (TSDS window).")
    return r

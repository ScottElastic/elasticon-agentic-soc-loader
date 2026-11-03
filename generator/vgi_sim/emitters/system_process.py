"""metrics-system.process emitter — replaces Vandelay Global Industries's Splunk `ps_metric` (UF scripted
input). Modeled on docs/integrations/system-linux.md §6. Metricbeat-shaped, TSDS.

TSDS caveats (docs/ecs §5(d), system-linux §7.3): index_mode time_series; dimensions are
process.pid + host.name + agent.id (+ cloud.*); documents are deduped by dimensions+@timestamp
(409 on collision) and REJECTED outside the ~2h look-back / 30m look-ahead write window — so
these must be generated at (near) real time; you cannot backfill 30 days of metrics.
"""
from __future__ import annotations

import random

from ..clock import iso_ms
from ..entities import Host
from ..envelope import wrap

DATASET = "system.process"

# stable pid per (host, process name) so the TSDS dimension set is consistent across samples
_PIDS: dict[tuple[str, str], int] = {}


def _pid(host: str, name: str) -> int:
    key = (host, name)
    if key not in _PIDS:
        _PIDS[key] = random.randint(300, 60000)
    return _PIDS[key]


def proc_metric(ts, host: Host, *, name: str, cmdline: str, namespace: str,
                cpu_pct: float, rss_bytes: int, state: str = "running",
                cpu_total_value: int | None = None) -> dict:
    pid = _pid(host.name, name)
    body = {
        "@timestamp": iso_ms(ts),
        "event": {"duration": random.randint(200000, 3000000)},
        "metricset": {"name": "process", "period": 10000},
        "service": {"type": "system"},
        "process": {
            "pid": pid, "name": name, "command_line": cmdline,
            "args": cmdline.split(), "executable": cmdline.split()[0],
            "state": state, "parent": {"pid": 1}, "pgid": pid,
            "working_directory": "/", "cpu": {"pct": round(cpu_pct, 4)},
            "memory": {"pct": round(rss_bytes / (32 * 1024**3), 6)},
        },
        "user": {"name": random.choice(["root", "gridvault", "svc-gridvault"])},
        "system": {"process": {
            "state": state, "cmdline": cmdline, "num_threads": random.randint(1, 120),
            "cpu": {"total": {"value": cpu_total_value if cpu_total_value is not None else random.randint(100, 10**7),
                              "pct": round(cpu_pct, 4), "norm": {"pct": round(cpu_pct / 8, 4)}}},
            "memory": {"rss": {"bytes": rss_bytes, "pct": round(rss_bytes / (32 * 1024**3), 6)},
                       "size": rss_bytes * 3, "share": rss_bytes // 4},
            "fd": {"open": random.randint(3, 400), "limit": {"soft": 1048576, "hard": 1048576}},
        }},
    }
    return wrap(body, dataset=DATASET, namespace=namespace, agent=host.agent, host=host, metrics=True)


# a small realistic process table per Linux host
_PROC_TABLE = [
    ("java", "/usr/lib/jvm/temurin-17/bin/java -Xmx4g -jar /opt/gridvault/asset-svc.jar", 0.12, 2_800_000_000),
    ("postgres", "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main", 0.05, 900_000_000),
    ("node_exporter", "/usr/local/bin/node_exporter", 0.01, 45_000_000),
    ("sshd", "/usr/sbin/sshd -D", 0.001, 8_000_000),
    ("systemd", "/sbin/init", 0.002, 12_000_000),
]


def host_process_sample(ts, host: Host, *, namespace: str, spike: bool = False):
    """One metric doc per process for a host at time ts. spike=True inflates java CPU
    (feeds the 'Zero Signal' high-CPU / error-correlation ops story)."""
    out = []
    for name, cmd, base_cpu, rss in _PROC_TABLE:
        cpu = base_cpu * (7.0 if spike and name == "java" else 1.0) * random.uniform(0.7, 1.3)
        out.append(proc_metric(ts, host, name=name, cmdline=cmd, namespace=namespace,
                               cpu_pct=min(cpu, 0.99), rss_bytes=int(rss * random.uniform(0.9, 1.15))))
    return out

"""kubernetes.container_logs emitter — GridVault microservice logs (the #1 Vandelay Global Industries data
source, ~56% of Splunk volume). Modeled on docs/integrations/kubernetes.md §3.

Context/observability only — NO prebuilt Security rule reads kubernetes.container_logs
(rules-kubernetes.md). These power dashboards, Logs Explorer, and the "Zero Signal" ops
scenario (the APM error burst that recreates their #1 Splunk alert). Custom threshold /
ES|QL rules alert on these (POC-PLAN.md §4, §8).
"""
from __future__ import annotations

import random
import uuid

from ..clock import iso_ms
from ..entities import EKS_CLUSTER_PROD, EKS_NODES, Host

DATASET = "kubernetes.container_logs"


def _pod_name(service: str) -> str:
    return f"{service}-{uuid.uuid4().hex[:10]}-{uuid.uuid4().hex[:5]}"


def container_log(ts, *, namespace: str, service: str, message: str, level: str = "INFO",
                  k8s_namespace: str = "gridvault-platform", node: Host | None = None,
                  pod: str | None = None, stream: str = "stdout") -> dict:
    node = node or random.choice(EKS_NODES)
    pod = pod or _pod_name(service)
    cid = uuid.uuid4().hex + uuid.uuid4().hex[:32]
    agent = node.agent  # DaemonSet agent on the node (filebeat)
    doc = {
        "@timestamp": iso_ms(ts),
        "data_stream": {"type": "logs", "dataset": DATASET, "namespace": namespace},
        "ecs": {"version": "8.11.0"},
        "message": message,
        "stream": stream,
        "event": {"dataset": DATASET, "module": "kubernetes", "kind": "event"},
        "log": {"file": {"path": f"/var/log/containers/{pod}_{k8s_namespace}_{service}-{cid}.log"},
                "offset": random.randint(0, 4_000_000)},
        "container": {"id": cid, "runtime": "containerd",
                      "image": {"name": f"847629103455.dkr.ecr.us-west-2.amazonaws.com/gridvault/{service}:2.14.3"}},
        "orchestrator": {"type": "kubernetes", "cluster": {"name": EKS_CLUSTER_PROD}},
        "kubernetes": {
            "container": {"name": service},
            "pod": {"name": pod, "uid": str(uuid.uuid4()),
                    "ip": f"10.244.{random.randint(0,7)}.{random.randint(2,250)}"},
            "namespace": k8s_namespace,
            "node": {"name": node.name, "hostname": node.name, "uid": str(uuid.uuid4())},
            "deployment": {"name": service},
            "replicaset": {"name": f"{service}-{uuid.uuid4().hex[:10]}"},
            "labels": {"app": service, "pod-template-hash": uuid.uuid4().hex[:10]},
        },
        "agent": {"id": agent.id, "ephemeral_id": str(uuid.uuid4()), "name": node.name,
                  "type": "filebeat", "version": "9.4.0"},
        "elastic_agent": {"id": agent.id, "snapshot": False, "version": "9.4.0"},
        "tags": ["vgi-sim"],
    }
    if level in ("ERROR", "WARN"):
        doc["log"]["level"] = level.lower()
    return doc


# --- GridVault-flavored log lines ---------------------------------------------
_INFO_LINES = [
    'INFO  1 --- [http-nio-8080-exec-{n}] c.g.p.{svc}.ApiController : {method} /v2/assets/{aid} 200 {ms}ms',
    'INFO  1 --- [scheduler-{n}] c.g.p.{svc}.IngestionJob : processed {rows} timeseries points for tag GT-{aid}',
    'INFO  1 --- [kafka-consumer-{n}] c.g.p.{svc}.EventListener : committed offset {off} partition {n}',
]
_ERROR_LINE = ('ERROR 1 --- [http-nio-8080-exec-{n}] c.g.p.apm.GenerationService : APM report '
               'generation failed for asset AST-{aid}: '
               'java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not '
               'available, request timed out after 30000ms')


def info_line(ts, *, namespace, service="asset-svc", **kw):
    n = random.randint(1, 16)
    msg = random.choice(_INFO_LINES).format(
        n=n, svc=service.split("-")[0], method=random.choice(["GET", "POST", "PUT"]),
        aid=random.randint(1000, 9999), ms=random.randint(3, 220),
        rows=random.randint(50, 5000), off=random.randint(10**6, 10**7))
    return container_log(ts, namespace=namespace, service=service, message=msg, level="INFO", **kw)


def apm_error_line(ts, *, namespace, **kw):
    msg = _ERROR_LINE.format(n=random.randint(1, 16), aid=random.randint(1000, 9999))
    return container_log(ts, namespace=namespace, service="flux-capacitor-svc",
                         message=msg, level="ERROR", stream="stderr", **kw)

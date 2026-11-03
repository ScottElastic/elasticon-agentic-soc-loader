"""Stamp the Elastic-Agent / Fleet envelope onto every document.

This is the heart of "indistinguishable": emitters build the source-specific body, then
`wrap()` adds everything Fleet/Agent add to a real document. See the checklist in
IMPLEMENTATION-GUIDE.md §4 and the field-level spec in docs/ecs/data-stream-and-agent-conventions.md.

NOT set here on purpose:
  * event.ingested        — the Fleet final pipeline stamps it at write time (=now).
  * event.agent_id_status — the final pipeline computes it (will be `auth_metadata_missing`
                            for injected docs; defensible as Logstash/Kafka-routed agent
                            data — docs/ecs §3(c)). Any value we send is deleted anyway.
"""
from __future__ import annotations

from . import config
from .entities import Agent, Host


def _deep_merge(base: dict, extra: dict) -> dict:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def wrap(
    body: dict,
    *,
    dataset: str,
    namespace: str,
    agent: Agent,
    host: Host | None = None,
    forwarded: bool = False,
    metrics: bool = False,
    tags: list[str] | None = None,
) -> dict:
    """Return `body` enriched with the full data_stream / agent / event envelope.

    dataset   e.g. "aws.cloudtrail", "system.auth", "kubernetes.audit_logs"
    namespace data_stream.namespace (e.g. "prod_uswest")
    agent     the Agent that "produced" the event
    host      host.* enrichment (host-local datasets); omitted for forwarded datasets
    forwarded adds the "forwarded" tag and suppresses host.* (cloud/SaaS datasets)
    metrics   metrics data stream (agent.type=metricbeat, data_stream.type=metrics)
    """
    module = dataset.split(".")[0]
    ds_type = "metrics" if metrics else "logs"

    doc: dict = {
        "data_stream": {"type": ds_type, "dataset": dataset, "namespace": namespace},
        "ecs": {"version": config.ECS_VERSION},
    }
    _deep_merge(doc, agent.envelope(metrics=metrics))

    # event.dataset always mirrors data_stream.dataset; event.module is the package name.
    ev = {"dataset": dataset, "module": module}
    _deep_merge(doc, {"event": ev})

    # Merge the source-specific body (may override event.kind/category/type/outcome, etc.)
    _deep_merge(doc, body)

    if host is not None and not forwarded:
        _deep_merge(doc, host.fields())

    all_tags = list(tags or [])
    if forwarded and "forwarded" not in all_tags:
        all_tags.append("forwarded")
    if config.POC_TAG not in all_tags:
        all_tags.append(config.POC_TAG)
    # Preserve any tags the body already set.
    existing = doc.get("tags") or []
    doc["tags"] = list(dict.fromkeys([*existing, *all_tags]))
    return doc

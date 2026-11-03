"""
vgi_sim — Vandelay Global Industries Elastic POC data generator.

Emits ECS-perfect, Elastic-Agent-shaped documents into Elastic data streams so that
the real prebuilt detection-rule set fires on them. See generators/README.md and the
repo-root POC-PLAN.md / IMPLEMENTATION-GUIDE.md for the why; docs/ for the field-level
evidence behind every value here.

Design invariants (from docs/ecs/data-stream-and-agent-conventions.md):
  * Documents are written INTO data streams (logs-<dataset>-<namespace>) with
    ?pipeline=_none, so the package pipeline is skipped but the Fleet final pipeline
    still stamps event.ingested (=now) and event.agent_id_status.
  * Because the package pipeline is skipped, we populate geo / user_agent / categorization
    / related.* ourselves — the emitters produce the *post-pipeline* shape directly.
  * agent.type is "filebeat" (logs) / "metricbeat" (metrics), never "elastic-agent".
  * ecs.version is the integration's pinned "8.11.0", NOT the stack version.
"""

__version__ = "0.1.0"

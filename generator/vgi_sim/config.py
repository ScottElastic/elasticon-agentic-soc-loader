"""Environment + global constants for the generator.

Credentials are read from the same env vars the Elastic skills use, so the generator
drops into an existing shell session without extra setup:

    export ELASTICSEARCH_URL="https://<deployment>.es.<region>.cloud.es.io"
    export ELASTICSEARCH_API_KEY="<base64 api key>"          # preferred
    # or ELASTICSEARCH_USERNAME / ELASTICSEARCH_PASSWORD
    export KIBANA_URL="https://<deployment>.kb.<region>.cloud.es.io"

If no Elasticsearch URL is set the generator runs OFFLINE (dry-run): it builds the exact
documents and writes NDJSON to stdout / a file, so you can inspect fidelity without a cluster.
"""
from __future__ import annotations

import os

# --- Values that must match the installed stack / integrations (see docs/ecs) ---
ECS_VERSION = "8.11.0"          # integrations pin this; do NOT use the stack's ECS version
AGENT_VERSION = "9.4.0"         # Elastic Agent / Beats version stamped on documents
STACK_VERSION = "9.5.2"

# Default data_stream.namespace when a scenario/emitter does not specify one.
DEFAULT_NAMESPACE = os.environ.get("VGI_NAMESPACE", "prod_uswest")

# Marker tag added to every generated document for safe teardown (delete_by_query).
POC_TAG = "vgi-sim"


def es_url() -> str | None:
    return os.environ.get("ELASTICSEARCH_URL") or os.environ.get("ES_URL")


def kibana_url() -> str | None:
    return os.environ.get("KIBANA_URL") or os.environ.get("KBN_URL")


def es_api_key() -> str | None:
    return os.environ.get("ELASTICSEARCH_API_KEY") or os.environ.get("ES_API_KEY")


def es_basic_auth() -> tuple[str, str] | None:
    u = os.environ.get("ELASTICSEARCH_USERNAME") or os.environ.get("ES_USERNAME")
    p = os.environ.get("ELASTICSEARCH_PASSWORD") or os.environ.get("ES_PASSWORD")
    return (u, p) if u and p else None


def offline() -> bool:
    """True when no cluster is configured — the generator dry-runs to NDJSON."""
    return es_url() is None

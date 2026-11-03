"""Minimal Elasticsearch + Kibana client (Python stdlib only — no pip installs).

Covers exactly what the POC needs: bulk-write into data streams (pipeline=_none so the
Fleet final pipeline still stamps event.ingested), install integration packages + prebuilt
rules, enable rules by tag, preview a rule, and teardown by marker tag.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from . import config


class ElasticError(RuntimeError):
    pass


class Client:
    def __init__(self) -> None:
        self.es = (config.es_url() or "").rstrip("/")
        self.kbn = (config.kibana_url() or "").rstrip("/")
        self._auth = self._auth_header()

    def _auth_header(self) -> str | None:
        if config.es_api_key():
            return "ApiKey " + config.es_api_key()
        basic = config.es_basic_auth()
        if basic:
            raw = f"{basic[0]}:{basic[1]}".encode()
            return "Basic " + base64.b64encode(raw).decode()
        return None

    # -- low level -----------------------------------------------------------
    def _request(self, base: str, method: str, path: str, body=None,
                 ndjson: bool = False, kibana: bool = False) -> dict:
        if not base:
            raise ElasticError(
                f"No {'Kibana' if kibana else 'Elasticsearch'} URL configured "
                f"(set {'KIBANA_URL' if kibana else 'ELASTICSEARCH_URL'})."
            )
        url = base + path
        headers = {"Accept": "application/json"}
        if self._auth:
            headers["Authorization"] = self._auth
        if kibana:
            headers["kbn-xsrf"] = "true"
        data = None
        if body is not None:
            if ndjson:
                headers["Content-Type"] = "application/x-ndjson"
                data = body.encode() if isinstance(body, str) else body
            else:
                headers["Content-Type"] = "application/json"
                data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            raise ElasticError(f"{method} {path} -> HTTP {e.code}: {detail[:800]}") from None
        except urllib.error.URLError as e:
            raise ElasticError(f"{method} {path} -> {e}") from None
        return json.loads(raw) if raw.strip() else {}

    def es_req(self, method: str, path: str, body=None, ndjson=False) -> dict:
        return self._request(self.es, method, path, body, ndjson=ndjson)

    def kbn_req(self, method: str, path: str, body=None) -> dict:
        return self._request(self.kbn, method, path, body, kibana=True)

    # -- data ----------------------------------------------------------------
    def bulk(self, datastream: str, docs: list[dict], refresh: str = "false") -> dict:
        """Create docs into a data stream. pipeline=_none skips the package pipeline;
        the index.final_pipeline still runs and stamps event.ingested / agent_id_status."""
        if not docs:
            return {"took": 0, "items": []}
        lines = []
        for d in docs:
            lines.append(json.dumps({"create": {}}))
            lines.append(json.dumps(d))
        payload = "\n".join(lines) + "\n"
        path = f"/{datastream}/_bulk?pipeline=_none&refresh={refresh}"
        res = self.es_req("POST", path, payload, ndjson=True)
        if res.get("errors"):
            problems = [
                it["create"].get("error")
                for it in res.get("items", [])
                if it.get("create", {}).get("error")
            ]
            raise ElasticError(
                f"bulk into {datastream}: {len(problems)} item error(s); first: "
                f"{json.dumps(problems[0])[:600] if problems else '?'}"
            )
        return res

    # -- Fleet / detections --------------------------------------------------
    def install_package(self, name: str, version: str | None = None) -> dict:
        path = f"/api/fleet/epm/packages/{name}" + (f"/{version}" if version else "")
        return self.kbn_req("POST", path, {"force": True})

    def install_prebuilt_rules(self) -> dict:
        # Documented, supported path (docs/detection-rules/prebuilt-rules-management.md §1).
        return self.kbn_req("PUT", "/api/detection_engine/rules/prepackaged")

    def enable_rules_by_query(self, kql: str, dry_run: bool = False) -> dict:
        # Try the combined query first; if the cluster's 1000-rule cap is hit,
        # fall back to one query per OR-clause (each tag individually).
        path = "/api/detection_engine/rules/_bulk_action" + ("?dry_run=true" if dry_run else "")
        try:
            return self.kbn_req("POST", path, {"action": "enable", "query": kql})
        except ElasticError as exc:
            if "array size is" not in str(exc) and "cannot be greater than" not in str(exc):
                raise
        # Split the OR-query into individual clauses and enable each separately.
        clauses = [c.strip() for c in kql.split(" or ") if c.strip()]
        total_enabled = 0
        last = {}
        for clause in clauses:
            try:
                res = self.kbn_req("POST", path, {"action": "enable", "query": clause})
                summary = res.get("attributes", {}).get("summary", {})
                total_enabled += summary.get("enabled", 0) + summary.get("succeeded", 0)
                last = res
            except ElasticError as exc2:
                if "array size is" not in str(exc2) and "cannot be greater than" not in str(exc2):
                    raise
                # Even a single tag has >1000 — skip rather than loop-fail.
                print(f"  WARNING: skipping clause (>1000 rules): {clause[:80]}", flush=True)
        return {"attributes": {"summary": {"total": "batched", "enabled": total_enabled}}, "_batched": True, **last}

    def get_rule(self, rule_id: str) -> dict:
        return self.kbn_req("GET", f"/api/detection_engine/rules?rule_id={rule_id}")

    def enable_rule_by_id(self, rule_id: str) -> dict:
        """Enable one prebuilt rule by rule_id. Needed for rules that carry no
        'Data Source: *' tag (e.g. the Linux SSH-brute-force / user-creation rules),
        which the tag-based enable_rules_by_query misses."""
        return self.kbn_req("PATCH", "/api/detection_engine/rules",
                            {"rule_id": rule_id, "enabled": True})

    def run_rule_now(self, rule_id: str, start_iso: str, end_iso: str) -> dict:
        """Manual run (backfill) of an installed rule over [start,end] — fires it on cue.
        9.6 renamed the bulk action to "run" with a "run" payload (the old
        "manual_rule_run"/"manual_rule_run_payload" shape now 400s)."""
        rule = self.get_rule(rule_id)
        so_id = rule.get("id")
        if not so_id:
            raise ElasticError(f"rule_id {rule_id} not installed/enabled")
        body = {"action": "run",
                "ids": [so_id],
                "run": {"start_date": start_iso, "end_date": end_iso}}
        return self.kbn_req("POST", "/api/detection_engine/rules/_bulk_action", body)

    def ensure_index(self, name: str, mappings: dict) -> None:
        """Create a plain index with explicit mappings; no-op if it already exists."""
        try:
            self.es_req("PUT", f"/{name}", {"mappings": mappings})
        except ElasticError as exc:
            if "resource_already_exists_exception" not in str(exc):
                raise

    def delete_by_tag(self, datastream_pattern: str, tag: str = config.POC_TAG) -> dict:
        body = {"query": {"term": {"tags": tag}}}
        return self.es_req("POST", f"/{datastream_pattern}/_delete_by_query?refresh=true&conflicts=proceed", body)

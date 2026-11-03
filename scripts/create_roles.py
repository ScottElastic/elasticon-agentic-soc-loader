#!/usr/bin/env python3
"""ElastiCon workshop RBAC — two custom roles on the Serverless Security project.

* elasticon-attendee   : can do EVERYTHING in the workshop EXCEPT mutate the live host.
                         No endpoint response actions (isolate/release/kill/get-file/scan/
                         execute), no Fleet agent management. Attendees can execute the
                         simulated-containment workflow; real isolation is disarmed. Everything else — alerts,
                         Attack Discovery, AI Assistant, Agent Builder chat with GLaDOS,
                         cases, timelines, Discover/ES|QL, dashboards — is on.
* elasticon-facilitator: the presenter role — same, PLUS every endpoint response action and
                         workflow execution, so the facilitator drives the one live isolate.

Assign the attendee role to invited Cloud-org users (or use it as the shared workshop login's
role). Serverless native-user creation is Cloud-org-managed, so this script creates the ROLES;
you assign them when inviting users in the Cloud console.

Env: KIBANA_URL, ELASTICSEARCH_API_KEY (admin). Idempotent (PUT).
"""
from __future__ import annotations
import json, os, sys, urllib.error, urllib.request

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
API_KEY = os.environ.get("ELASTICSEARCH_API_KEY", "") or os.environ.get("KIBANA_API_KEY", "")

# Read access to the data attendees pivot through in Discover / ES|QL / Agent Builder tools.
DATA_INDICES = [
    "logs-*", "metrics-*", ".alerts-security.alerts-*",
    "vgi-threat-intel*", "vgi-endpoint-filescan*",
    "security_solution-*", "vgi-asset-exposure", ".ml-anomalies-shared*",
    ".entities*", ".entity_analytics*", "risk-score.*",
]

# Non-destructive Security sub-features attendees SHOULD have (view/interact), deliberately
# OMITTING every response-action sub-priv: host_isolation_all, process_operations_all,
# file_operations_all, execute_operations_all, scan_operations_all, actions_log_management_all,
# policy_management_all, plus artifact-management writes.
ATTENDEE_SIEM = [
    "all",                       # Security app base (response actions are opt-in, NOT in base)
    "endpoint_list_read",
    "trusted_applications_read", "trusted_devices_read", "host_isolation_exceptions_read",
    "blocklist_read", "event_filters_read", "endpoint_exceptions_read",
    "policy_management_read", "scripts_management_read", "actions_log_management_read",
]

ATTENDEE_FEATURES = {
    "siemV5": ATTENDEE_SIEM,
    "securitySolutionCasesV3": ["all", "create_comment", "case_reopen", "cases_assign"],
    "securitySolutionTimeline": ["all"],
    "securitySolutionNotes": ["all"],
    "securitySolutionAlertsV1": ["all"],
    "securitySolutionRulesV4": ["read"],
    "securitySolutionAssistant": ["all"],          # JARVIS — AI Assistant
    "securitySolutionAttackDiscovery": ["all"],    # Deep Thought — Attack Discovery
    "agentBuilder": ["all"],                        # GLaDOS — chat + explore tools
    "discover_v2": ["all"],
    "dashboard_v2": ["all"],
    "ml": ["read"],
    # Attendees CAN run workflows (so they get the hands-on "click Respond" moment), but every
    # real isolate is gated behind an approval input the facilitator supplies, and the
    # attendee-safe workflow only STUBS containment — so execution never mutates the live host.
    # UI host isolation stays blocked (no host_isolation_all above).
    "workflowsManagement": ["read", "workflow_execute", "workflow_execution_read"],
    "fleet": ["read"],                              # Integrations (see the data sources)
}

# Facilitator = attendee + the destructive/driving privileges.
FACILITATOR_FEATURES = dict(ATTENDEE_FEATURES)
FACILITATOR_FEATURES.update({
    "siemV5": [
        "all", "endpoint_list_all", "global_artifact_management_all",
        "trusted_applications_all", "trusted_devices_all", "host_isolation_exceptions_all",
        "blocklist_all", "event_filters_all", "endpoint_exceptions_all",
        "policy_management_all", "scripts_management_all", "actions_log_management_all",
        "host_isolation_all", "process_operations_all", "file_operations_all",
        "execute_operations_all", "scan_operations_all",
    ],
    "securitySolutionRulesV4": ["all"],
    "workflowsManagement": ["all"],                 # execute the response workflows
    "fleet": ["all"],
    "fleetv2": ["all"],
    "securitySolutionSiemMigrations": ["all"],
})

# ES|QL COMPLETION (Lab 2) calls the inference API, which needs monitor_inference.
INFERENCE = ["monitor_inference"]

ROLES = {
    "elasticon-attendee": {
        "elasticsearch": {"cluster": INFERENCE, "indices": [
            {"names": DATA_INDICES, "privileges": ["read", "view_index_metadata"]}
        ], "run_as": []},
        "kibana": [{"base": [], "feature": ATTENDEE_FEATURES, "spaces": [os.environ.get("KIBANA_SPACE", "default")]}],
    },
    "elasticon-facilitator": {
        "elasticsearch": {"cluster": INFERENCE, "indices": [
            {"names": DATA_INDICES + ["*"], "privileges": ["read", "view_index_metadata"]}
        ], "run_as": []},
        "kibana": [{"base": [], "feature": FACILITATOR_FEATURES, "spaces": [os.environ.get("KIBANA_SPACE", "default")]}],
    },
}


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(KIBANA_URL + path, data=data, method=method)
    r.add_header("Authorization", f"ApiKey {API_KEY}")
    r.add_header("kbn-xsrf", "true")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, (resp.read().decode() or "")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    if not KIBANA_URL or not API_KEY:
        sys.exit("ERROR: set KIBANA_URL and ELASTICSEARCH_API_KEY")
    for name, body in ROLES.items():
        s, b = req("PUT", f"/api/security/role/{name}", body)
        print(f"{'OK ' if s in (200,204) else 'ERR '+str(s)}  role {name}")
        if s not in (200, 204):
            print("   ", b[:600], file=sys.stderr)


if __name__ == "__main__":
    main()

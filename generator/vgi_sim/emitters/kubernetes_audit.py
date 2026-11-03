"""kubernetes.audit_logs emitter — API-server audit events under kubernetes.audit.*
(docs/detection-rules/rules-kubernetes.md field reminder). Cluster-level API data:
no host.* (orchestrator.cluster.* instead).

Note the annotation key literally contains a slash: kubernetes.audit.annotations has key
"authorization_k8s_io/decision" (the integration renames authorization.k8s.io/decision).

Rules fired (all read logs-kubernetes.audit_logs-*, all use event.ingested override):
  exec into pod        -> 14de811c   privileged pod -> c7908cac   hostNetwork pod -> 12cbf709
  cluster-admin bind   -> a2951930   anonymous secrets read (fresh UA) -> 63c057cc
"""
from __future__ import annotations

import uuid

from ..clock import iso_ms
from ..entities import (AWS_ACCOUNT_PROD, ATTACKER, COMPROMISED_IAM_USER, EKS_CLUSTER_PROD)
from ..entities import Agent
from ..envelope import wrap

DATASET = "kubernetes.audit_logs"
AGENT_EKS = Agent("elastic-agent-usw2-eksaudit")
K8S_NAMESPACE = "gridvault-platform"
ATTACKER_K8S_USER = f"arn:aws:iam::{AWS_ACCOUNT_PROD}:user/{COMPROMISED_IAM_USER}"


def _audit(ts, *, namespace: str, verb: str, resource: str, level: str, stage: str,
           request_uri: str, event_category: list[str], event_type: list[str],
           user_username: str = ATTACKER_K8S_USER, user_groups=None,
           subresource: str | None = None, object_name: str | None = None,
           object_namespace: str | None = K8S_NAMESPACE, request_object: dict | None = None,
           user_agent: str = "kubectl/v1.30.2 (linux/amd64) kubernetes/3968854",
           response_code: int = 201, src_ip: str = ATTACKER.ip, decision: str = "allow") -> dict:
    audit_id = str(uuid.uuid4())
    object_ref = {"resource": resource, "apiVersion": "v1"}
    if object_namespace:
        object_ref["namespace"] = object_namespace
    if object_name:
        object_ref["name"] = object_name
    if subresource:
        object_ref["subresource"] = subresource

    audit = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": level,
        "auditID": audit_id,
        "stage": stage,
        "verb": verb,
        "user": {"username": user_username, "groups": user_groups or ["system:authenticated"]},
        "sourceIPs": [src_ip],
        "userAgent": user_agent,
        "objectRef": object_ref,
        "requestURI": request_uri,
        "annotations": {"authorization_k8s_io/decision": decision, "authorization_k8s_io/reason": ""},
        "requestReceivedTimestamp": iso_ms(ts),
        "stageTimestamp": iso_ms(ts),
        "responseStatus": {"metadata": {}, "code": response_code},
    }
    if request_object is not None:
        audit["requestObject"] = request_object

    body = {
        "@timestamp": iso_ms(ts),
        "event": {"kind": "event", "id": audit_id, "category": event_category,
                  "type": event_type, "outcome": "success" if response_code < 400 else "failure"},
        "user_agent": {"original": user_agent},
        "source": {"ip": src_ip},
        "orchestrator": {"type": "kubernetes", "cluster": {"name": EKS_CLUSTER_PROD}},
        "kubernetes": {"audit": audit},
        "related": {"user": [user_username], "ip": [src_ip]},
    }
    return wrap(body, dataset=DATASET, namespace=namespace, agent=AGENT_EKS, tags=["kubernetes-audit"])


def exec_into_pod(ts, *, namespace: str, pod: str = "flux-capacitor-svc-6d4f9b7c8-h2xk9",
                  container: str = "flux-capacitor-svc") -> dict:
    uri = (f"/api/v1/namespaces/{K8S_NAMESPACE}/pods/{pod}/exec?command=%2Fbin%2Fbash"
           f"&container={container}&stdin=true&stdout=true&tty=true")
    return _audit(ts, namespace=namespace, verb="create", resource="pods", subresource="exec",
                  level="Request", stage="ResponseStarted", request_uri=uri, object_name=pod,
                  event_category=["process"], event_type=["start"], response_code=101)


def privileged_pod(ts, *, namespace: str, pod: str = "debug-tools") -> dict:
    ro = {"apiVersion": "v1", "kind": "Pod",
          "metadata": {"name": pod, "namespace": K8S_NAMESPACE},
          "spec": {"containers": [{"name": "tools", "image": "docker.io/library/busybox:latest",
                                   "securityContext": {"privileged": True}}]}}
    return _audit(ts, namespace=namespace, verb="create", resource="pods", level="RequestResponse",
                  stage="ResponseComplete", request_uri=f"/api/v1/namespaces/{K8S_NAMESPACE}/pods",
                  object_name=pod, event_category=["configuration"], event_type=["creation"],
                  request_object=ro)


def hostnetwork_pod(ts, *, namespace: str, pod: str = "net-recon") -> dict:
    ro = {"apiVersion": "v1", "kind": "Pod",
          "metadata": {"name": pod, "namespace": K8S_NAMESPACE},
          "spec": {"hostNetwork": True,
                   "containers": [{"name": "web", "image": "docker.io/library/nginx:latest"}]}}
    return _audit(ts, namespace=namespace, verb="create", resource="pods", level="RequestResponse",
                  stage="ResponseComplete", request_uri=f"/api/v1/namespaces/{K8S_NAMESPACE}/pods",
                  object_name=pod, event_category=["configuration"], event_type=["creation"],
                  request_object=ro)


def cluster_admin_binding(ts, *, namespace: str, name: str = "pwn-cluster-admin") -> dict:
    ro = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
          "metadata": {"name": name},
          "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
          "subjects": [{"kind": "User", "name": ATTACKER_K8S_USER}]}
    return _audit(ts, namespace=namespace, verb="create", resource="clusterrolebindings",
                  level="RequestResponse", stage="ResponseComplete",
                  request_uri="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                  object_name=name, object_namespace=None, event_category=["configuration"],
                  event_type=["creation"], request_object=ro)


def anonymous_secrets(ts, *, namespace: str) -> dict:
    return _audit(ts, namespace=namespace, verb="get", resource="secrets", level="Request",
                  stage="ResponseComplete",
                  request_uri=f"/api/v1/namespaces/{K8S_NAMESPACE}/secrets",
                  event_category=["configuration"], event_type=["access"],
                  user_username="system:anonymous", user_groups=["system:unauthenticated"],
                  user_agent="curl/8.5.0-redteam", response_code=200)


def attach_stage(r, tl, *, namespace: str) -> None:
    """Stage 5 — lateral into Kubernetes via stolen IRSA creds."""
    ds = f"logs-{DATASET}-{namespace}"
    r.add(ds, exec_into_pod(tl.advance(20), namespace=namespace))
    r.expect("14de811c-d60f-11ec-9fd7-f661ea17fbce", "Kubernetes User Exec into Pod")
    r.add(ds, privileged_pod(tl.advance(15), namespace=namespace))
    r.expect("c7908cac-337a-4f38-b50d-5eeb78bdb531", "Kubernetes Privileged Pod Created")
    r.add(ds, hostnetwork_pod(tl.advance(10), namespace=namespace))
    r.expect("12cbf709-69e8-4055-94f9-24314385c27e", "Kubernetes Pod Created With HostNetwork")
    r.add(ds, cluster_admin_binding(tl.advance(12), namespace=namespace))
    r.expect("a2951930-dd35-438c-b10e-1bbdc5881cb4", "Kubernetes Cluster-Admin Role Binding Created")
    r.add(ds, anonymous_secrets(tl.advance(8), namespace=namespace))
    r.expect("63c057cc-339a-11ed-a261-0242ac120002", "Kubernetes Anonymous Request Authorized by Unusual User Agent")

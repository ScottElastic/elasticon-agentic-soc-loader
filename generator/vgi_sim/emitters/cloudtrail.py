"""aws.cloudtrail emitter — post-pipeline documents modeled byte-for-byte on
docs/integrations/aws-cloudtrail.md §3b (the real CreateAccessKey pipeline-test output).

Dataset: aws.cloudtrail -> logs-aws.cloudtrail-<namespace>. Forwarded (aws-s3 input): tags
include forwarded + aws-cloudtrail + preserve_original_event + actor_target_mapping, no host.*.

Rule targets satisfied (docs/detection-rules/rules-aws-cloudtrail.md):
  console_login(Root, failure) x>=10  -> 4d50a94f (root brute force, threshold)
  console_login(Root, success)        -> e2a67480 (root console login)
  create_access_key(actor!=target)    -> 696015ef (access keys for another user, esql)
  deactivate_mfa                      -> d8fc1cca
  stop_logging / delete_trail         -> 1aa8fa52 / 7024e2a0
  delete_detector                     -> 523116c0 (guardduty)
"""
from __future__ import annotations

import json
import uuid

from .. import config
from ..clock import iso_ct, iso_ms
from ..entities import (AGENT_AWS, ATTACK_USER_AGENT, ATTACKER, AWS_ACCOUNT_PROD,
                        AWS_REGION, COMPROMISED_IAM_ARN, COMPROMISED_IAM_USER, CORP_EGRESS,
                        PERSISTENCE_IAM_USER, ROOT_ARN, ExtIP)
from ..envelope import wrap

DATASET = "aws.cloudtrail"


def java_map(d: dict) -> str:
    """Render a dict the way the CloudTrail pipeline does — Java Map#toString, not JSON.
    {"userName": "Bob"} -> "{userName=Bob}"."""
    def render(v):
        if isinstance(v, dict):
            return "{" + ", ".join(f"{k}={render(val)}" for k, val in v.items()) + "}"
        if isinstance(v, list):
            return "[" + ", ".join(render(x) for x in v) + "]"
        return str(v)
    return render(d)


def _svc_from_source(event_source: str) -> str:
    return event_source.split(".")[0]


def _event_time(ts) -> str:
    """CloudTrail raw eventTime: whole seconds with a Z, no millis."""
    return iso_ct(ts).replace(".000Z", "Z")


def _ct(
    ts,
    *,
    event_name: str,
    event_source: str,
    outcome: str,
    category: list[str],
    etype: list[str],
    namespace: str,
    identity_type: str = "IAMUser",
    user_name: str | None = None,
    user_id: str | None = None,
    user_arn: str | None = None,
    target_user: str | None = None,
    src: ExtIP | None = None,
    user_agent: str = "signin.amazonaws.com",
    account: str = AWS_ACCOUNT_PROD,
    region: str = AWS_REGION,
    request_parameters: dict | None = None,
    response_elements: dict | None = None,
    error_code: str | None = None,
    console_login_success: str | None = None,
    mfa_used: bool | None = None,
) -> dict:
    src = src or ATTACKER
    request_parameters = request_parameters or {}
    event_id = str(uuid.uuid4())
    request_id = uuid.uuid4().hex[:20].upper()

    # ---- raw CloudTrail record (event.original) — camelCase AWS keys ----
    user_identity = {"type": identity_type, "accountId": account}
    if identity_type == "Root":
        user_identity.update({"principalId": account, "arn": ROOT_ARN, "invokedBy": "signin.amazonaws.com"})
    else:
        user_identity.update({
            # principalId is STABLE per actor for the same reason accessKeyId is (below): a real
            # IAM user has ONE principal id for life. A fresh random id per API call shatters the
            # actor across docs — and Entity Store V2 keys AWS identities on exactly this value
            # (entity.id = "user:<principalId>@aws"), so a random id means risk can never
            # accumulate on the identity. uuid5 keeps it deterministic across runs.
            "principalId": (user_id or "AIDA"
                            + uuid.uuid5(uuid.NAMESPACE_DNS, f"vgi-principal|{user_name}").hex[:16].upper()),
            "arn": user_arn or f"arn:aws:iam::{account}:user/{user_name}",
            "userName": user_name,
            # AssumedRole = STS temporary creds -> ASIA*; IAMUser = long-term -> AKIA*.
            # Key is STABLE per actor (real sessions reuse one key). A fresh random key per API
            # call would make every call a new (access_key_id, source.ip) pair and flood the
            # "Long-Term Access Key First Seen from Source IP" new_terms rule — e.g. v.fries's 30
            # GetObject exfil calls each looked like a brand-new key. Now they share one.
            "accessKeyId": ("ASIA" if identity_type == "AssumedRole" else "AKIA")
                           + uuid.uuid5(uuid.NAMESPACE_DNS, f"vgi-key|{user_name}").hex[:16].upper(),
        })
    raw = {
        "eventVersion": "1.08",
        "userIdentity": user_identity,
        "eventTime": _event_time(ts),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": src.ip,
        "userAgent": user_agent,
        "requestParameters": request_parameters or None,
        "responseElements": response_elements,
        "requestID": request_id,
        "eventID": event_id,
        "eventType": "AwsApiCall" if event_source != "signin.amazonaws.com" else "AwsConsoleSignIn",
        "recipientAccountId": account,
    }
    if error_code:
        raw["errorCode"] = error_code
    if console_login_success is not None:
        raw["responseElements"] = {"ConsoleLogin": console_login_success}
        raw["additionalEventData"] = {"MFAUsed": "Yes" if mfa_used else "No",
                                      "LoginTo": "https://console.aws.amazon.com/console/home"}
    raw = {k: v for k, v in raw.items() if v is not None}

    # ---- parsed aws.cloudtrail.* ----
    ct: dict = {
        "event_version": "1.08",
        "event_type": raw["eventType"],
        "recipient_account_id": account,
        "request_id": request_id,
        "user_identity": {"type": identity_type, "arn": user_identity["arn"]},
    }
    if identity_type != "Root":
        ct["user_identity"]["access_key_id"] = user_identity.get("accessKeyId")
    if request_parameters:
        ct["request_parameters"] = java_map(request_parameters)
        ct["flattened"] = {"request_parameters": request_parameters}
    if response_elements:
        ct["response_elements"] = java_map(response_elements)
        ct.setdefault("flattened", {})["response_elements"] = response_elements
    if error_code:
        ct["error_code"] = error_code
    if console_login_success is not None:
        ct["console_login"] = {"additional_eventdata": {
            "mfa_used": bool(mfa_used),
            "login_to": "https://console.aws.amazon.com/console/home"}}

    body: dict = {
        "@timestamp": iso_ct(ts),
        "event": {
            "kind": "event",
            "action": event_name,
            "provider": event_source,
            "id": event_id,
            "outcome": outcome,
            "category": category,
            "type": etype,
            "created": iso_ms(ts),
        },
        "aws": {"cloudtrail": ct,
                "s3": {"bucket": {"name": f"vandelay-cloudtrail-{account}",
                                  "arn": f"arn:aws:s3:::vandelay-cloudtrail-{account}"},
                       "object": {"key": f"AWSLogs/{account}/CloudTrail/{region}/{event_id}.json.gz"}}},
        "cloud": {"provider": "aws", "account": {"id": account}, "region": region,
                  "service": {"name": _svc_from_source(event_source)}},
        "user_agent": _ua(user_agent),
        "input": {"type": "aws-s3"},
        "log": {"file": {"path": f"https://vandelay-cloudtrail-{account}.s3.{region}.amazonaws.com/"
                                 f"AWSLogs/{account}/CloudTrail/{region}/{event_id}.json.gz"},
                "offset": 0},
        "event_original_holder": None,  # placeholder removed below
    }
    body.pop("event_original_holder")
    body["event"]["original"] = json.dumps(raw, separators=(",", ":"))

    # ---- source + related ----
    related_users: list[str] = []
    related_ips: list[str] = []
    if identity_type == "Root":
        related_users.append(ROOT_ARN)
    else:
        body["user"] = {"name": user_name, "id": user_identity["principalId"]}
        related_users += [user_name, user_identity["principalId"]]
        if target_user:
            body["user"]["target"] = {"name": target_user}
            related_users.append(target_user)
    # external source with hand-set geo/as (geoip processor is bypassed)
    body.update(src.source())
    related_ips.append(src.ip)

    body["related"] = {"user": list(dict.fromkeys(related_users)),
                       "ip": list(dict.fromkeys(related_ips))}

    return wrap(body, dataset=DATASET, namespace=namespace, agent=AGENT_AWS, forwarded=True,
                tags=["preserve_original_event", "actor_target_mapping", "aws-cloudtrail"])


def _ua(original: str) -> dict:
    if original.startswith("aws-cli"):
        return {"original": original, "name": "aws-cli", "version": "2.15.30", "device": {"name": "Other"}}
    return {"original": original, "name": "Other", "device": {"name": "Other"}}


# --------------------------- stage builders --------------------------------
def console_login(ts, *, outcome: str, namespace: str, src: ExtIP = ATTACKER,
                  identity_type: str = "Root", mfa_used: bool = False,
                  user_name: str | None = None) -> dict:
    return _ct(ts, event_name="ConsoleLogin", event_source="signin.amazonaws.com",
               outcome=outcome, category=["authentication"], etype=["start"],
               namespace=namespace, identity_type=identity_type, user_name=user_name, src=src,
               user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
               console_login_success="Success" if outcome == "success" else "Failure",
               mfa_used=mfa_used)


def create_access_key(ts, *, namespace: str, actor: str = COMPROMISED_IAM_USER,
                      target: str = PERSISTENCE_IAM_USER, src: ExtIP = ATTACKER,
                      user_arn: str | None = None) -> dict:
    # user_arn defaults to the Grid-Runner/Quiet-Turbine compromised ARN to preserve those
    # scenarios byte-for-byte; pass an explicit ARN (e.g. for a different actor) to override.
    return _ct(ts, event_name="CreateAccessKey", event_source="iam.amazonaws.com",
               outcome="success", category=["iam"], etype=["user", "change"],
               namespace=namespace, identity_type="IAMUser", user_name=actor,
               user_arn=user_arn or COMPROMISED_IAM_ARN, target_user=target, src=src,
               user_agent=ATTACK_USER_AGENT,
               request_parameters={"userName": target},
               response_elements={"accessKey": {"accessKeyId": "AKIA" + uuid.uuid4().hex[:16].upper(),
                                                 "status": "Active", "userName": target}})


def attach_user_policy(ts, *, namespace: str, actor: str, target: str,
                       policy_arn: str = "arn:aws:iam::aws:policy/AdministratorAccess",
                       actor_arn: str | None = None, src: ExtIP = ATTACKER) -> dict:
    """IAM privilege escalation: attach a managed (default Administrator) policy to a user.
    Context/agent signal for the cross-cloud IAM chain (T1098)."""
    return _ct(ts, event_name="AttachUserPolicy", event_source="iam.amazonaws.com",
               outcome="success", category=["iam"], etype=["user", "change"],
               namespace=namespace, identity_type="IAMUser", user_name=actor,
               user_arn=actor_arn, target_user=target, src=src, user_agent=ATTACK_USER_AGENT,
               request_parameters={"userName": target, "policyArn": policy_arn})


def assume_role(ts, *, namespace: str, actor: str, role_arn: str,
                actor_arn: str | None = None, src: ExtIP = ATTACKER) -> dict:
    """Anomalous cross-account/role assumption (T1078.004) — the pivot beat of the chain."""
    return _ct(ts, event_name="AssumeRole", event_source="sts.amazonaws.com",
               outcome="success", category=["authentication"], etype=["start"],
               namespace=namespace, identity_type="IAMUser", user_name=actor,
               user_arn=actor_arn, src=src, user_agent=ATTACK_USER_AGENT,
               request_parameters={"roleArn": role_arn,
                                   "roleSessionName": f"{actor}-session"})


def deactivate_mfa(ts, *, namespace: str, target: str = "h.langston", src: ExtIP = ATTACKER) -> dict:
    return _ct(ts, event_name="DeactivateMFADevice", event_source="iam.amazonaws.com",
               outcome="success", category=["iam"], etype=["user", "change"],
               namespace=namespace, identity_type="IAMUser", user_name=COMPROMISED_IAM_USER,
               user_arn=COMPROMISED_IAM_ARN, target_user=target, src=src, user_agent=ATTACK_USER_AGENT,
               request_parameters={"userName": target,
                                   "serialNumber": f"arn:aws:iam::{AWS_ACCOUNT_PROD}:mfa/{target}"})


def stop_logging(ts, *, namespace: str, trail: str = "vandelay-org-trail", src: ExtIP = ATTACKER) -> dict:
    return _ct(ts, event_name="StopLogging", event_source="cloudtrail.amazonaws.com",
               outcome="success", category=["configuration"], etype=["change"],
               namespace=namespace, identity_type="IAMUser", user_name=COMPROMISED_IAM_USER,
               user_arn=COMPROMISED_IAM_ARN, src=src, user_agent=ATTACK_USER_AGENT,
               request_parameters={"name": f"arn:aws:cloudtrail:{AWS_REGION}:{AWS_ACCOUNT_PROD}:trail/{trail}"})


def delete_trail(ts, *, namespace: str, trail: str = "vandelay-org-trail", src: ExtIP = ATTACKER) -> dict:
    return _ct(ts, event_name="DeleteTrail", event_source="cloudtrail.amazonaws.com",
               outcome="success", category=["configuration"], etype=["deletion"],
               namespace=namespace, identity_type="IAMUser", user_name=COMPROMISED_IAM_USER,
               user_arn=COMPROMISED_IAM_ARN, src=src, user_agent=ATTACK_USER_AGENT,
               request_parameters={"name": f"arn:aws:cloudtrail:{AWS_REGION}:{AWS_ACCOUNT_PROD}:trail/{trail}"})


def delete_detector(ts, *, namespace: str, src: ExtIP = ATTACKER) -> dict:
    return _ct(ts, event_name="DeleteDetector", event_source="guardduty.amazonaws.com",
               outcome="success", category=["configuration"], etype=["deletion"],
               namespace=namespace, identity_type="IAMUser", user_name=COMPROMISED_IAM_USER,
               user_arn=COMPROMISED_IAM_ARN, src=src, user_agent=ATTACK_USER_AGENT,
               request_parameters={"detectorId": uuid.uuid4().hex})


# --------------------------- S3 (Quiet Turbine exfil) ----------------------
def get_object(ts, *, namespace: str, bucket: str, key: str, actor: str,
               src: ExtIP = ATTACKER, region: str = AWS_REGION) -> dict:
    return _ct(ts, event_name="GetObject", event_source="s3.amazonaws.com", outcome="success",
               category=["file"], etype=["access"], namespace=namespace, identity_type="IAMUser",
               user_name=actor, src=src, user_agent=ATTACK_USER_AGENT, region=region,
               request_parameters={"bucketName": bucket, "key": key})


def list_objects(ts, *, namespace: str, bucket: str, actor: str, prefix: str = "",
                 src: ExtIP = ATTACKER, region: str = AWS_REGION) -> dict:
    """Bucket enumeration ahead of a pull — the recon beat of the Quiet Turbine exfil."""
    return _ct(ts, event_name="ListObjects", event_source="s3.amazonaws.com", outcome="success",
               category=["file"], etype=["access"], namespace=namespace, identity_type="IAMUser",
               user_name=actor, src=src, user_agent=ATTACK_USER_AGENT, region=region,
               request_parameters={"bucketName": bucket, "prefix": prefix})


def put_bucket_policy_public(ts, *, namespace: str, bucket: str, actor: str,
                             src: ExtIP = ATTACKER, region: str = AWS_REGION) -> dict:
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
              "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}
    return _ct(ts, event_name="PutBucketPolicy", event_source="s3.amazonaws.com", outcome="success",
               category=["configuration"], etype=["change"], namespace=namespace,
               identity_type="IAMUser", user_name=actor, src=src, user_agent=ATTACK_USER_AGENT,
               region=region, request_parameters={"bucketName": bucket, "bucketPolicy": policy})


# --------------------------- benign background -----------------------------
def readonly(ts, *, namespace: str, action: str = "DescribeInstances",
             event_source: str = "ec2.amazonaws.com", actor: str = "svc-conan-deploy",
             src: ExtIP = CORP_EGRESS) -> dict:
    """A boring, rule-inert read-only API call for steady-state background."""
    return _ct(ts, event_name=action, event_source=event_source, outcome="success",
               category=["network"], etype=["access"], namespace=namespace,
               identity_type="AssumedRole", user_name=actor, src=src,
               user_agent="aws-sdk-java/1.12.470 Linux/5.15 OpenJDK_64-Bit_Server_VM/17",
               request_parameters={"maxResults": 100})

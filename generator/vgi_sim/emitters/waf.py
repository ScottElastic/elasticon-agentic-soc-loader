"""aws.waf emitter — WAF web-ACL records modeled on docs/integrations/aws-waf.md §3.

Context/dashboard only — NO prebuilt Security rule reads aws.waf (rules-aws-cloudtrail.md).
Used for the Grid-Runner edge-recon stage (blocked SQLi/traversal probes) and background
web traffic. A custom ES|QL rule can alert on these; WAF *tampering* surfaces via CloudTrail.
"""
from __future__ import annotations

import json
import random
import uuid

from ..clock import iso_ms
from ..entities import AGENT_AWS, AWS_ACCOUNT_PROD, AWS_REGION, ExtIP
from ..envelope import wrap

DATASET = "aws.waf"
WEBACL_ARN = (f"arn:aws:wafv2:{AWS_REGION}:{AWS_ACCOUNT_PROD}:regional/webacl/"
              f"gridvault-api-waf/1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d")


def waf_event(ts, *, namespace: str, src: ExtIP, action: str = "BLOCK",
              uri: str = "/v2/assets", method: str = "GET", host_header: str = "api.gridvault.vandelayindustries.com",
              condition_type: str | None = "SQL_INJECTION", user_agent: str = "curl/8.5.0",
              terminating_rule: str = "gridvault-SQLi-XSS") -> dict:
    headers = [{"name": "Host", "value": host_header}, {"name": "User-Agent", "value": user_agent},
               {"name": "Accept", "value": "*/*"}]
    raw = {
        "timestamp": int(ts.timestamp() * 1000),
        "formatVersion": 1, "webaclId": WEBACL_ARN,
        "terminatingRuleId": terminating_rule if action == "BLOCK" else "Default_Action",
        "terminatingRuleType": "REGULAR" if action == "BLOCK" else "MANAGED_RULE_GROUP",
        "action": action,
        "terminatingRuleMatchDetails": ([{"conditionType": condition_type, "location": "URI",
                                          "matchedData": ["1", "OR", "1"]}] if action == "BLOCK" and condition_type else []),
        "httpSourceName": "APIGW", "httpSourceId": "-",
        "httpRequest": {"clientIp": src.ip, "country": src.country_iso,
                        "headers": headers, "uri": uri, "args": "", "httpVersion": "HTTP/2",
                        "httpMethod": method, "requestId": uuid.uuid4().hex},
    }
    etype = ["access", "denied"] if action == "BLOCK" else ["access", "allowed"]
    body = {
        "@timestamp": iso_ms(ts),
        "event": {"kind": "event", "action": action, "category": ["web", "network"], "type": etype,
                  "outcome": "success", "original": json.dumps(raw, separators=(",", ":"))},
        "aws": {"waf": {"arn": WEBACL_ARN, "id": WEBACL_ARN.split(":")[-1], "format_version": "1",
                        "source": {"name": "APIGW"},
                        "terminating_rule_match_details": raw["terminatingRuleMatchDetails"]},
                "s3": {"bucket": {"name": "aws-waf-logs-gridvault"},
                       "object": {"key": f"gridvault/{uuid.uuid4().hex}.gz"}}},
        "cloud": {"provider": "aws", "account": {"id": AWS_ACCOUNT_PROD}, "region": AWS_REGION,
                  "service": {"name": "wafv2"}},
        "http": {"request": {"method": method}, "version": "2"},
        "url": {"path": uri, "domain": host_header},
        "user_agent": {"original": user_agent},
        "input": {"type": "aws-s3"},
        "related": {"ip": [src.ip]},
    }
    body.update(src.source())
    return wrap(body, dataset=DATASET, namespace=namespace, agent=AGENT_AWS, forwarded=True,
               tags=["aws-waf"])


# a few attack-probe shapes for the edge-recon stage
_PROBES = [
    ("/v2/assets?id=1'%20OR%20'1'='1", "GET", "SQL_INJECTION", "sqlmap/1.8"),
    ("/v2/../../etc/passwd", "GET", "GENERIC_RFI", "curl/8.5.0"),
    ("/v2/timeseries", "POST", "CROSS_SITE_SCRIPTING", "Mozilla/5.0 (compatible; Nuclei)"),
    ("/actuator/gateway/routes", "GET", None, "python-requests/2.31"),  # Log4Shell-style recon
]


def probe(ts, *, namespace, src, allowed=False):
    uri, method, cond, ua = random.choice(_PROBES)
    return waf_event(ts, namespace=namespace, src=src, action=("ALLOW" if allowed else "BLOCK"),
                     uri=uri, method=method, condition_type=cond, user_agent=ua)

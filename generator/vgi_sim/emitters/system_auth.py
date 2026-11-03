"""system.auth emitter — post-pipeline sshd documents modeled byte-for-byte on
docs/integrations/system-linux.md §5 (verbatim pipeline-test output).

Dataset: system.auth -> logs-system.auth-<namespace>. Host-local (agent on the host):
carries full host.* and related.hosts. Categorization matches the integration's painless:
  Accepted -> event.category ["authentication","session"], outcome success
  Failed   -> event.category ["authentication"],            outcome failure
  both     -> event.action "ssh_login", event.type ["info"], process.name "sshd"

Rules (docs/detection-rules/rules-linux-auth.md):
  25x fail + 1 success, same host.id+source.ip+user.name, span<=15s, @timestamp NOW
                                    -> 8cb84371 (Potential Successful SSH Brute Force, NO override)
  the success (fresh related.ip)    -> 5c495612 (Successful SSH from Unusual IP, new_terms)
  success as a system user          -> 428e9109 (Unusual Login via System User, new_terms)
  useradd                           -> edfd5ca9 (Linux User Account Creation, eql)
"""
from __future__ import annotations

import random
import uuid
from datetime import timedelta

from ..clock import iso_ms, now_utc
from ..entities import ATTACKER, Host, ExtIP
from ..envelope import wrap

DATASET = "system.auth"


def _syslog_line(ts, host: str, proc: str, pid: int, msg: str) -> str:
    # BSD syslog header: "Feb 21 21:54:44 host sshd[pid]: <msg>"
    return f"{ts.strftime('%b %e %H:%M:%S')} {host} {proc}[{pid}]: {msg}"


def ssh_login(ts, *, host: Host, user: str, src, outcome: str, namespace: str,
              method: str = "password") -> dict:
    is_ext = isinstance(src, ExtIP)
    src_ip = src.ip if is_ext else src
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 60000)
    ssh_event = "Accepted" if outcome == "success" else "Failed"
    category = ["authentication", "session"] if outcome == "success" else ["authentication"]
    sig = "RSA SHA256:" + "".join(random.choice("0123456789abcdef") for _ in range(20))

    if outcome == "success" and method == "publickey":
        msg = f"Accepted publickey for {user} from {src_ip} port {port} ssh2: {sig}"
        ssh = {"event": "Accepted", "method": "publickey", "signature": sig}
    else:
        verb = "Accepted" if outcome == "success" else "Failed"
        msg = f"{verb} {method} for {user} from {src_ip} port {port} ssh2"
        ssh = {"event": ssh_event, "method": method}

    body: dict = {
        "@timestamp": iso_ms(ts),
        "message": msg,
        "event": {
            "kind": "event",
            "id": str(uuid.uuid4()),
            "action": "ssh_login",
            "category": category,
            "type": ["info"],
            "outcome": outcome,
            "timezone": "+00:00",
            "original": _syslog_line(ts, host.name, "sshd", pid, msg),
        },
        "host": {"target": {"id": host.id, "name": host.name}},
        "process": {"name": "sshd", "pid": pid},
        "system": {"auth": {"ssh": ssh}},
        "user": {"name": user},
        "source": {"port": port},
        "input": {"type": "log"},
        "log": {"file": {"path": "/var/log/auth.log"}, "offset": random.randint(0, 900000)},
        "related": {"hosts": [host.name], "ip": [src_ip], "user": [user]},
    }
    if is_ext:
        body["source"].update(src.source()["source"])  # ip/address/geo/as
    else:
        body["source"].update({"ip": src_ip, "address": src_ip})

    return wrap(body, dataset=DATASET, namespace=namespace, agent=host.agent, host=host,
                tags=["preserve_original_event", "system-auth"])


def useradd(ts, *, host: Host, new_user: str, uid: int, namespace: str) -> dict:
    msg = f"new user: name={new_user}, UID={uid}, GID={uid}, home=/home/{new_user}, shell=/bin/bash"
    body: dict = {
        "@timestamp": iso_ms(ts),
        "message": msg,
        "event": {"kind": "event", "id": str(uuid.uuid4()), "action": "user_add",
                  "category": ["iam"], "type": ["user", "creation"],
                  "outcome": "success", "timezone": "+00:00",
                  "original": _syslog_line(ts, host.name, "useradd", random.randint(1000, 60000), msg)},
        "process": {"name": "useradd"},
        "system": {"auth": {"useradd": {"home": f"/home/{new_user}", "shell": "/bin/bash"}}},
        # System 3.x maps the new account to user.target.name only; 9.5's "Linux User Account Creation"
        # also needs user.name (older pipelines set it to the new account), so carry both.
        "user": {"name": new_user, "target": {"name": new_user, "id": str(uid)}},
        "input": {"type": "log"},
        "log": {"file": {"path": "/var/log/auth.log"}, "offset": random.randint(0, 900000)},
        "related": {"hosts": [host.name], "user": [new_user]},
    }
    return wrap(body, dataset=DATASET, namespace=namespace, agent=host.agent, host=host,
               tags=["preserve_original_event", "system-auth"])


def attach_stage(r, tl, *, namespace: str, target: Host, jump: Host,
                 user: str = "svc-conan-deploy") -> None:
    """Stage 7 — SSH brute force + success + persistence, anchored to NOW.

    The brute-force rule 8cb84371 has no timestamp_override, so the 26-event sequence must
    have current @timestamp values spanning <15s. Anchor at now-14s.
    """
    ds = f"logs-{DATASET}-{namespace}"
    base = now_utc() - timedelta(seconds=14)
    for i in range(25):  # runs=25 failures
        r.add(ds, ssh_login(base + timedelta(seconds=i * 0.5), host=target, user=user,
                            src=ATTACKER, outcome="failure", namespace=namespace))
    r.add(ds, ssh_login(base + timedelta(seconds=13), host=target, user=user,
                        src=ATTACKER, outcome="success", namespace=namespace, method="publickey"))
    r.expect("8cb84371-d053-4f4f-bce0-c74990e28f28", "Potential Successful SSH Brute Force Attack")
    r.expect("5c495612-9992-49a7-afe3-0f647671fb60", "Successful SSH Authentication from Unusual IP Address")

    # Unusual login as a system user (www-data should never SSH in) -> 428e9109
    r.add(ds, ssh_login(now_utc() - timedelta(seconds=40), host=target, user="www-data",
                        src=ATTACKER, outcome="success", namespace=namespace, method="publickey"))
    r.expect("428e9109-dc13-4ae9-84cb-100464d4c6fa", "Unusual Login via System User")

    # Persistence: create a backdoor local user -> edfd5ca9
    r.add(ds, useradd(now_utc() - timedelta(seconds=20), host=target, new_user="whte_rbt",
                     uid=1500, namespace=namespace))
    r.expect("edfd5ca9-9d6c-44d9-b615-1e56b920219c", "Linux User Account Creation")

#!/usr/bin/env python3
"""Vandelay Global Industries POC data generator — CLI.

Zero external dependencies (Python 3.9+ stdlib only). Runs OFFLINE by default (builds the
exact documents and prints/writes NDJSON) so you can inspect ECS fidelity without a cluster;
set ELASTICSEARCH_URL + credentials to index for real. See generators/README.md.

Examples
    python run.py emit grid_runner --out /tmp/grid.ndjson   # offline: build + dump NDJSON
    python run.py sample grid_runner                        # offline: one pretty doc / dataset
    python run.py install                                   # install integrations + prebuilt rules
    python run.py enable-rules                               # enable relevant prebuilt rules
    python run.py scenario grid_runner                      # index the scenario into Elastic
    python run.py fire grid_runner                          # manual-run the expected rules now
    python run.py cleanup                                    # delete all vgi-sim docs
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Make `import vgi_sim` work whether run as `python run.py` or `python generators/run.py`.
sys.path.insert(0, __file__.rsplit("/", 1)[0])

from vgi_sim import config                    # noqa: E402
from vgi_sim import background                 # noqa: E402
from vgi_sim.scenarios import axios_c2                                 # noqa: E402

# The workshop uses one scenario from the original generator: MOTHER's overnight-hunt data.
# (The crown-jewel campaign itself is scripts/crownjewel_seed.py.)
SCENARIOS = {
    "axios_c2": axios_c2.build,
}

# Integration packages whose assets (templates/pipelines/mappings) must exist first.
PACKAGES = ["aws", "kubernetes", "system", "crowdstrike", "azure", "endpoint", "panw", "vsphere"]

# Datasets this generator writes to (for enable-rules tags + cleanup).
LOG_DATASETS = [
    "aws.cloudtrail", "aws.waf", "aws.elb_logs",
    "kubernetes.audit_logs", "kubernetes.container_logs",
    "system.auth", "system.syslog",
    "crowdstrike.fdr", "crowdstrike.alert",
    "azure.signinlogs", "azure.activitylogs", "azure.auditlogs",
    "panw.panos",
    "vsphere.log",                          # UC4 — ESXi syslog + vCenter audit
]
METRIC_DATASETS = ["system.process"]

# Plain (non-data-stream) indices scenarios write to (cleanup only deletes tagged docs).
PLAIN_INDICES = ["vgi-threat-intel", "vgi-endpoint-filescan"]

RULE_TAGS = [
    "Data Source: AWS", "Data Source: Amazon Web Services", "Data Source: Kubernetes",
    "Data Source: Crowdstrike", "Data Source: System", "Data Source: Azure",
    "Data Source: Elastic Defend", "Data Source: PAN-OS",
]


def _print_expectations(res, where: str) -> None:
    print(f"\n  Scenario '{res.name}' -> {where}", file=sys.stderr)
    counts = {ds: len(docs) for ds, docs in res.by_datastream().items()}
    for ds, n in sorted(counts.items()):
        print(f"    {n:4d}  {ds}", file=sys.stderr)
    print(f"    total docs: {len(res.events)}", file=sys.stderr)
    if res.expected_rules:
        print("\n  Prebuilt rules expected to fire:", file=sys.stderr)
        for rid, name in res.expected_rules:
            print(f"    - {name}  ({rid})", file=sys.stderr)
    for n in getattr(res, "notes", []):
        print(f"\n  NOTE: {n}", file=sys.stderr)


def _emit_or_index(res, out=None) -> int:
    """Offline (no ES URL) or --out: dump NDJSON. Online: bulk-index into data streams."""
    if config.offline() or out is not None:
        f = open(out, "w") if out else sys.stdout
        try:
            for ds, doc in res.events:
                f.write(json.dumps({"_datastream": ds, **doc}) + "\n")
        finally:
            if out:
                f.close()
        _print_expectations(res, out or "stdout (NDJSON, offline)")
    else:
        c = _client()
        for ds, docs in res.by_datastream().items():
            c.bulk(ds, docs, refresh="false")
            print(f"  indexed {len(docs):5d} -> {ds}")
        _print_expectations(res, "indexed into Elasticsearch")
    return 0


def cmd_emit(args) -> int:
    res = SCENARIOS[args.scenario]()
    out = open(args.out, "w") if args.out else sys.stdout
    try:
        for ds, doc in res.events:
            out.write(json.dumps({"_datastream": ds, **doc}) + "\n")
    finally:
        if args.out:
            out.close()
    _print_expectations(res, args.out or "stdout (NDJSON)")
    return 0


def cmd_sample(args) -> int:
    res = SCENARIOS[args.scenario]()
    seen = {}
    for ds, doc in res.events:
        seen.setdefault(ds, doc)
    for ds, doc in sorted(seen.items()):
        print(f"\n===== {ds} =====")
        print(json.dumps(doc, indent=2, sort_keys=True))
    _print_expectations(res, "sample (one doc per dataset)")
    return 0


def _client():
    if config.offline():
        print("ERROR: no ELASTICSEARCH_URL set. Use `emit`/`sample` offline, or export "
              "ELASTICSEARCH_URL + ELASTICSEARCH_API_KEY.", file=sys.stderr)
        raise SystemExit(2)
    from vgi_sim.esclient import Client
    return Client()


def cmd_install(args) -> int:
    c = _client()
    skip = {p.strip() for p in os.environ.get("VGI_SKIP_PACKAGES", "").split(",") if p.strip()}
    for pkg in PACKAGES:
        if pkg in skip:
            print(f"  skipped package: {pkg} (VGI_SKIP_PACKAGES)")
            continue
        try:
            c.install_package(pkg)
            print(f"  installed package: {pkg}")
        except Exception as e:  # noqa: BLE001
            print(f"  FAILED package {pkg}: {e}", file=sys.stderr)
    try:
        c.install_prebuilt_rules()
        print("  installed prebuilt detection rules (security_detection_engine)")
    except Exception as e:  # noqa: BLE001
        print(f"  FAILED prebuilt rules: {e}", file=sys.stderr)
    return 0


def cmd_enable_rules(args) -> int:
    c = _client()
    kql = " or ".join(f'alert.attributes.tags: "{t}"' for t in RULE_TAGS)
    res = c.enable_rules_by_query(kql)
    summary = res.get("attributes", {}).get("summary") or res
    print(f"  enable-rules (by Data Source tag): {json.dumps(summary)[:300]}")

    # Belt-and-suspenders: enable each scenario's expected rules by rule_id too. Some
    # (e.g. the Linux "Potential Successful SSH Brute Force Attack" / "Linux User Account
    # Creation" / "Successful SSH Authentication from Unusual IP" rules) carry NO
    # "Data Source: *" tag, so the tag query above silently skips them and the hero demo
    # never fires. Enabling by id guarantees every scenario tripwire is live.
    expected: dict[str, str] = {}
    for build in SCENARIOS.values():
        try:
            for rid, name in build().expected_rules:
                expected[rid] = name
        except Exception:  # noqa: BLE001
            pass
    ok = 0
    for rid, name in expected.items():
        try:
            c.enable_rule_by_id(rid)
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"  (could not enable {name} {rid}: {e})", file=sys.stderr)
    print(f"  enable-rules (scenario tripwires by id): {ok}/{len(expected)} enabled")
    return 0


def cmd_scenario(args) -> int:
    c = _client()
    res = SCENARIOS[args.scenario]()
    for index, mapping in getattr(res, "index_mappings", {}).items():
        c.ensure_index(index, mapping)
        print(f"  ensured index: {index}")
    for ds, docs in res.by_datastream().items():
        c.bulk(ds, docs, refresh="wait_for")
        print(f"  indexed {len(docs):4d} -> {ds}")
    _print_expectations(res, "indexed into Elasticsearch")
    print("\n  Next: `python run.py fire " + args.scenario +
          "` (or wait <=5m for the schedule), then check Security > Alerts.", file=sys.stderr)
    return 0


def cmd_fire(args) -> int:
    from datetime import timedelta
    from vgi_sim.clock import iso_ms, now_utc
    c = _client()
    res = SCENARIOS[args.scenario]()
    end = now_utc()
    start = end - timedelta(minutes=args.window)
    for rid, name in res.expected_rules:
        try:
            c.run_rule_now(rid, iso_ms(start), iso_ms(end))
            print(f"  fired: {name} ({rid})")
        except Exception as e:  # noqa: BLE001
            print(f"  could not fire {name} ({rid}): {e}", file=sys.stderr)
    return 0


def cmd_background(args) -> int:
    return _emit_or_index(background.build(minutes=args.minutes, scale=args.scale), args.out)


def cmd_seed(args) -> int:
    return _emit_or_index(background.seed_history(days=args.days, per_day=args.per_day), args.out)


def cmd_cleanup(args) -> int:
    c = _client()
    for dataset in LOG_DATASETS:
        try:
            r = c.delete_by_tag(f"logs-{dataset}-*")
            print(f"  deleted {r.get('deleted', 0):5d} from logs-{dataset}-*")
        except Exception as e:  # noqa: BLE001
            print(f"  (skip logs-{dataset}-*: {e})", file=sys.stderr)
    for dataset in METRIC_DATASETS:
        try:
            r = c.delete_by_tag(f"metrics-{dataset}-*")
            print(f"  deleted {r.get('deleted', 0):5d} from metrics-{dataset}-*")
        except Exception as e:  # noqa: BLE001
            print(f"  (skip metrics-{dataset}-*: {e})", file=sys.stderr)
    for index in PLAIN_INDICES:
        try:
            r = c.delete_by_tag(index)
            print(f"  deleted {r.get('deleted', 0):5d} from {index}")
        except Exception as e:  # noqa: BLE001
            print(f"  (skip {index}: {e})", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Vandelay Global Industries POC data generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("emit", "sample", "scenario", "fire"):
        sp = sub.add_parser(name)
        sp.add_argument("scenario", choices=sorted(SCENARIOS))
        if name == "emit":
            sp.add_argument("--out", help="write NDJSON here instead of stdout")
        if name == "fire":
            sp.add_argument("--window", type=int, default=20, help="manual-run look-back minutes")

    bg = sub.add_parser("background", help="steady-state benign traffic at the DIMA mix")
    bg.add_argument("--minutes", type=int, default=15)
    bg.add_argument("--scale", type=float, default=1.0)
    bg.add_argument("--out", help="write NDJSON here instead of indexing")

    sd = sub.add_parser("seed", help="backfill thinned log history (no metrics — TSDS)")
    sd.add_argument("--days", type=int, default=30)
    sd.add_argument("--per-day", dest="per_day", type=int, default=120)
    sd.add_argument("--out", help="write NDJSON here instead of indexing")

    sub.add_parser("install")
    sub.add_parser("enable-rules")
    sub.add_parser("cleanup")

    args = p.parse_args(argv)
    return {
        "emit": cmd_emit, "sample": cmd_sample, "scenario": cmd_scenario, "fire": cmd_fire,
        "background": cmd_background, "seed": cmd_seed,
        "install": cmd_install, "enable-rules": cmd_enable_rules, "cleanup": cmd_cleanup,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())

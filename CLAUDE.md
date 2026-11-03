# seed-kit — Claude Code instructions

This folder seeds an Elastic cluster (ECH or Serverless) for the ElastiCon crown-jewel workshop.
Stay inside it: the guide one folder up (`../workshop_content.py`, `../build_walkthrough.py`,
`../guide_check.py`) is only needed to change guide content or run the full step-by-step check.
Don't read the old notes up there (`../*.md`, `../backups/`). They describe earlier versions.

## Run it

```bash
source env.sh                     # user's credentials; if missing: cp env.example env.sh and ask the user to fill it
python3 deploy.py check           # read-only preconditions; each ❌ maps to CHECKLIST.md
python3 deploy.py setup           # once per cluster (15 idempotent phases)
python3 deploy.py seed            # every session: campaign → hunt → guardduty → wiz-refresh
python3 deploy.py verify          # ../guide_check.py if present, else the kit's data checks
python3 deploy.py setup --only <phase> | --from <phase> | --list
```

Phases, in order. setup: `check settings integrations templates entity baseline rules ml exposure agent workflows
cases roles fp-history federation`. seed: `check campaign hunt guardduty wiz-refresh`.
`campaign` waits up to 25 min for the rules to fire (`SEED_WAIT`); run it in the background and poll.

## Shared clusters and non-default spaces
Log data is cluster-wide; only Kibana objects live in a space. Set `KIBANA_SPACE` (deploy.py adds `/s/<space>` to
`KIBANA_URL` for every script it runs; export it with the suffix to run a script directly). Before seeding a
cluster other teams use: check their enabled rules and entity stores (they will see the VGI data), their ML
datafeeds' indices, and custom index templates on `logs-aws.cloudtrail-*` etc. The `templates` phase clones Fleet's
template above any rival for the kit's namespaces only. `VGI_RULES=story`, `VGI_EXCLUDE_NAMESPACES`,
`VGI_SKIP_PACKAGES`: see env.example. 9.5 installs the entity store via `/install` (no `/enable`).
The guide's own queries still print `.alerts-security.alerts-default`; in another space they need the space's index.

## Things only the user can do (say so; don't work around them)
- UI-only toggles: Entity risk score, MOTHER **Enable** (no API), GenAI default connector, Workflows/Agent Builder
  visibility on ECH. See CHECKLIST.md.
- Credentials: never write keys into any file except the user's own `env.sh`; never print them.
- The S3 reader key lives in `env.sh` (minted 2026-09-29). If it's missing, mint a new one with the user's OK
  (`aws iam create-access-key --user-name <reader-user>`; max 2 keys per user). Never hunt for a lost secret.

## Rules
- **Order matters on a new cluster:** integrations before any data; entity store on before data (3 h look-back);
  30-day baseline **before** enabling rules (event.ingested=now would fire them on history).
- **Seed 1–24 h before a session.** Everything is relative to now; the guide uses Last 24 hours. Risk rescoring is
  ~hourly, and Wiz misconfigs expire after ~26 h.
- **Never run `fp_rds_export.py --cleanup`** before a session: it deletes the closed-FP corpus Alert analysis needs.
- **GuardDuty archive = this seed's.** `guardduty` reads the seeded CloudTrail events; run it after `campaign`, never alone
  against an old seed.
- Destructive or outward actions (reseeding a cluster someone is using, overwriting the S3 archive, deleting
  workflows/cases) need the user's go-ahead.
- Names in the data are deliberate: Schwarzenegger characters, VGI/GridVault, and the easter eggs listed in README.md.
  No "GEV", "GE Vernova" or "Predix" anywhere.

## When something fails
| Symptom | Cause → fix |
|---|---|
| `Potential Successful SSH Brute Force Attack` never fires | rule 8cb84371 keys on @timestamp with a 9-min look-back: the spray must land within ~2.5 min of seeding. Re-run `--only campaign`. |
| Brute-force rule matches unreliably | system.auth @timestamp is rebuilt from the syslog prefix; the seeder writes ISO (ms) prefixes. Don't revert `_hires_syslog`. |
| No ML alert / anomaly | back-dated events are invisible to running datafeeds: `campaign` reseeds first, then resets and relearns the jobs (`--ml-reset`). |
| Host panel criticality wrong, or alerts say `high_impact` | entity-store copy drifted. The seeder re-pins it via `PUT /api/security/entity_store/entities/host?force=true` and waits; check `.entities.v2.latest*` filtered by `entity.EngineMetadata.Type: host` (user entities also match host.name). |
| Host risk *Unknown* | risk engine hasn't rescored; wait for the hourly pass. Risk lives on `entity.risk.*` in the entity store (v2), not `host.risk.*`. |
| `no handler found for uri [/_query/data_source]` | ECH 9.5: federation is off by default. The user adds `esql.federation.enabled: true` (ES) and `xpack.dataFederation.enabled: true` (Kibana) in the Cloud console → Edit → user settings. |
| `unknown setting [region]` / `unknown field [region]` on a dataset | 9.5 wants `region` on the data source, 9.6 on the dataset `settings`. `--wire` tries 9.6 and falls back; don't hand-edit. |
| `guardduty_findings` errors / missing columns | re-run `--only federation`; datasets need `schema_resolution: union_by_name`. region belongs on the dataset `settings`. |
| verify: archive out of step with the campaign | run `--only guardduty` after the campaign. |
| Wiz misconfig panel empty | 26 h retention: `--only wiz-refresh`. |
| RDS alert not auto-closed | Alert analysis floor must be 0.70 (`--only workflows`); related alerts use ±1 h, so fire `--live` ≥ 70 min after a rehearsal. |
| MOTHER verify fails | it's disabled: the user enables it in the Workflows UI. |
| Workflow redeploy creates `…-2` names | deleted names tombstone; `deploy.py` updates in place by name, so don't delete workflows. |
| Serverless `_ml/info` 410 | expected; `check` probes `_ml/anomaly_detectors` instead. |
| ES\|QL `first` / `last` as a column name | reserved words; use `t0` / `newest`. |

## Where things are
Seeded data carries tags `vgi-crownjewel` (campaign) and `vgi-sim` (baseline, hunt, Wiz, FP). Custom observable
types, template and required rules: `assets/`. Story constants: `scripts/crownjewel_seed.py` (top of file) and
`generator/vgi_sim/entities.py`.

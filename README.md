# GLaDOS vs. Skynet: workshop loader

Synthetic data, detections, an AI agent and workflows for the **GLaDOS vs. Skynet: Build the Agentic SOC**
hands-on workshop (Elastic Security). It runs inside an Instruqt sandbox on Elastic **9.5.x** (ECK on k3s) and
loads one fictional intrusion at a fictional conglomerate into **your own cluster**.

Everything here is fictional and synthetic. There are no credentials in this repository, and none should ever be
added: `env.sh` (the only file that holds a key) is git-ignored and is created on your sandbox, for your sandbox.

## Run it (in the Instruqt sandbox)

```bash
git clone --depth 1 --branch <tag> https://github.com/ScottElastic/elasticon-agentic-soc-loader.git soc
cd soc
./start.sh          # creates a key that works only on your cluster, then starts two background jobs
./soc-status        # what is done, running or failed
```

The jobs keep running if you close the terminal or move to the next challenge. `./start.sh` is safe to run again:
it resumes a job that failed and never restarts one that is running.

The sandbox's setup script (root) does the few things that need privileges, once, before you start:
the cluster CA, the LLM connectors, the S3 server, and the systemd units that run these jobs **as you**. You never
need `sudo`, and nothing here runs as root.

## What it builds

| Job | Phase | What it does | ~min |
|---|---|---|---|
| pipeline | integrations | Fleet packages and the prebuilt detection-rules package | 4 |
| | baseline, templates, entity | 30 days of normal activity, index templates, Entity Store, asset criticality | <1 |
| | rules, ml | the story's detection rules; machine-learning jobs on the auth logs | 2 |
| | campaign | last night's attack, relative to now; waits for the rules to fire | 5 |
| | hunt, fp-history | the overnight-hunt data; a month of closed false positives for Alert analysis | 5 |
| | guardduty | the GuardDuty archive, read in place by ES\|QL data federation | <1 |
| agentic | llm *(prepared by setup)* | connectors `vgi-opus` / `vgi-sonnet`; inference endpoints for ES\|QL `COMPLETION` | <1 |
| | cases, roles | the case template (a SOC playbook) and custom observable types; roles | <1 |
| | exposure | Wiz vulnerability and misconfiguration data, and the asset-exposure lookup | 5 |
| | agent, workflows | the GLaDOS agent and its tools; the TARS and MOTHER workflows | <1 |

The core (alerts, LLMs, case template) is ready about **10 minutes** after `./start.sh`; everything is done in about
15 (measured on the managed Elastic sandbox).

## How federation works with no credentials

The GuardDuty export lives on an S3-compatible server (SeaweedFS) that the sandbox runs next to Elasticsearch.
Elasticsearch reads it through `http://s3.default.svc:9000` with `auth: none`, so there is no key to leak. If that
server cannot start, the same findings are loaded as a plain index with the same name, and the queries do not change.

## Layout

```
start.sh, soc-status      the learner's entry points
deploy.py                 the orchestrator: lanes, phases, resume, status, verify (see its docstring)
scripts/sandbox_*.py      cluster discovery + key, LLM setup, S3 server, root-only prep
scripts/lab_check.py      per-lab data-readiness gates and learner checks used by the track
scripts/*_seed.py ...     the campaign, GuardDuty archive, Wiz data, false positives, GLaDOS agent and tools
generator/                ECS-shaped event emitters and the 30-day baseline
assets/, workflows/       rule set, case template, observable types; the TARS and MOTHER workflows
```

## Notes

- Tested on Elastic 9.5.2. MOTHER's definition uses the `ai.agent` workflow step, which that release rejects, so she
  stays disabled there; it should work on a newer version.
- The generators are readable on purpose, which means the investigation's answers are readable too. Do the labs first.

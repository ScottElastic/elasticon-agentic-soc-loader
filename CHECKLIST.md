# New-cluster checklist — crown-jewel workshop

Work top to bottom. **Sections 1–4 happen before any data goes in**; several change what the
cluster does with logs as they arrive, and can't be fixed afterwards without a reseed.
`python3 deploy.py check` verifies the automatable items. Every ❌ it prints maps to a line here.

Legend: 🖱 = UI only (no API) · 🤖 = `deploy.py` does it · ✔ = `check`/`verify` confirms it

---

## 1. The deployment

**Elastic Cloud Hosted (ECH)**
- [ ] 🖱 Latest **9.x** (built and tested on 9.6 Serverless). Security + ML nodes. **Enterprise** license
      (or a trial): ML, Attack Discovery, Agent Builder, Workflows, data federation and endpoint
      response actions all need it.
- [ ] 🖱 **ES|QL data federation** is experimental and **off by default on ECH 9.5**. Cloud console →
      deployment → **Edit** → Elasticsearch *Manage user settings and extensions* → `esql.federation.enabled: true`;
      Kibana *Edit user settings* → `xpack.dataFederation.enabled: true` → **Save** (rolling restart). ✔
- [ ] 🖱 **Workflows** in the Kibana nav. On ECH it may be behind an advanced setting
      (Stack Management → Advanced settings → search "workflows"); switch it on. ✔ (Workflows API)
- [ ] 🖱 **Agent Builder** in the nav. ✔ (Agent Builder API)
- [ ] 🖱 **LLMs.** Serverless ships Elastic Managed LLMs (`.anthropic-*`, `.gp-llm-*`). On ECH, check
      *Stack Management → Connectors* and `GET _inference/_all`:
      - If the Elastic Inference Service (EIS) is on, you get the same preconfigured ids. ✔
      - If not, create a Claude connector (Anthropic or Bedrock), put its **name** in
        `LLM_CONNECTOR` (env.sh), and change `COMPLETION_MODEL` / `FED_MODEL` in
        `../workshop_content.py` to inference endpoints you created. Then rebuild the guide.
- [ ] 🖱 An **admin API key** (Kibana → Stack Management → API keys, superuser) → `env.sh`. ✔

**Serverless (the original build)**
- [ ] 🖱 Security project, tier **Security Analytics Complete** + **Endpoint Protection Complete**.

**Both**
- [ ] 🖱 Space: `default` unless `KIBANA_SPACE` is set (env.example). The kit then works in that space; the
      guide's printed queries still name `.alerts-security.alerts-default`.

## 2. Switch on BEFORE any logs arrive

- [ ] 🖱🤖 **Entity Store (v2)**: Security → Manage → Entity Analytics → **Entity Store → Enable**
      (the `entity` phase tries the API first). The engine reads only a **3-hour look-back**, so
      entities are built from data as it lands: enable it first, or the hero host has no entity doc. ✔
- [ ] 🖱 **Entity risk score**: Entity Analytics → **Entity risk score → Turn on**. Risk rescores
      roughly hourly: seed **at least 1 hour before doors**, or the host panel reads *Unknown*.
- [ ] 🤖 **Asset criticality** (`entity`): `gridvault-usw2-01` extreme_impact; `VGI-LT-4471`,
      `gridvault-bastion-usw2-01` high_impact. The campaign seeder also waits for the entity store to
      agree before writing events, otherwise alerts are stamped with the wrong criticality.
- [ ] 🤖 **Integrations** (`integrations`): aws, kubernetes, system, crowdstrike, azure, endpoint, panw,
      vsphere + the prebuilt rule package. Mappings must exist **before** data: KQL rules silently
      miss on unmapped fields.
- [ ] 🤖 **Wiz** 4.8.0 (`exposure`), both `latest` transforms started.
- [ ] 🤖 **Advanced settings** (`settings`): `dateFormat:tz = UTC`, `enableESQL = true`.

## 3. Data order: history first, rules second

- [ ] 🤖 `baseline`: 30 days of thinned history + 15 minutes of background traffic with the story rules
      **off**. The Fleet final pipeline stamps `event.ingested = now`, so rules on now would fire on history.
- [ ] 🤖 `rules`: ~700 prebuilt rules by data source, then the **26 story rules** by id
      (`assets/required-rules.json`), then the custom rule *Shell Spawned by Package Manager*
      (`assets/rule-vgi-lab3-shell-from-package-manager.json`).
- [ ] 🤖 `ml`: prebuilt **security_auth** module over `logs-*`; `auth_high_count_logon_fails_ea`,
      `auth_rare_source_ip_for_a_user_ea`, `suspicious_login_activity_ea` open and started 35 days back. ✔

## 4. AI

- [ ] ✔ Connector named `LLM_CONNECTOR` (default `Anthropic-Claude-Sonnet-4-5`). TARS and MOTHER pin it.
- [ ] ✔ Inference endpoints `.gp-llm-v2-completion` (Lab 2 COMPLETION) and
      `.anthropic-claude-4.5-sonnet-completion` (Lab 3 federation). See §1 for ECH.
- [ ] 🤖 **Alert analysis** managed workflow (`workflows`): on, auto-close on, confidence floor **0.70**
      (the default 0.85 never closes the RDS lead), attached to *AWS RDS Snapshot Export* only.
      Connector: `ALERT_ANALYSIS_CONNECTOR`.
- [ ] 🖱 **GenAI settings**: default AI connector = a Claude model (AI summary, Add to chat, Attack Discovery).
- [ ] 🖱 Load test once: 4–5 people on Add to chat / Attack Discovery at the same time. Watch for 429s.

## 5. Agentic layer

- [ ] 🤖 `agent`: GLaDOS (`vgi-glados`) + 13 tools (`vgi.aws.*`, `vgi.correlate.by_ip`,
      `vgi.host.investigation`, `vgi.identity.timeline`, `vgi.asset.exposure`, 3 platform tools).
- [ ] 🤖 `workflows`: **TARS** (attendee-safe, simulated containment, `lookback_days`) and **MOTHER**
      (daily IOC hunt; Kibana URL and connector rewritten for this cluster).
- [ ] 🖱 **Workflows → MOTHER — Daily Threat Hunt → Enable.** It is created disabled and has no enable API. ✔
- [ ] 🤖 `cases`: template **VGI — Crown jewel investigation** (SOC playbook, auto-extract observables on)
      + custom observable types User account, Kubernetes secret, Cloud identity, CVE.

## 6. S3 / GuardDuty archive (Lab 3 federation)

- [ ] 🖱 An S3 bucket (`GD_BUCKET` / `GD_BUCKET_REGION`) your AWS CLI identity can write to. ✔
- [ ] 🖱 A read-only IAM user for Elasticsearch: `s3:GetObject` on `arn:aws:s3:::<bucket>/*`, `s3:ListBucket`
      on the bucket. Key pair → `GD_S3_ACCESS_KEY` / `GD_S3_SECRET`. For the default bucket the user is
      `<reader-user>`; its current key (minted 2026-09-29) is already in `env.sh`. The
      2026-09-23 key is still active for the old Serverless cluster: delete it once that cluster is retired.
- [ ] ✔ **ES|QL data federation** answers (`GET _query/data_source` = 200). Re-check after upgrades.
- [ ] 🤖 `federation` (setup): data source `vgi_guardduty_archive`, datasets `guardduty_findings` +
      `guardduty_findings_flat`, **`schema_resolution: union_by_name`**.
- [ ] 🤖 `guardduty` (seed): rebuilt **around each campaign** (findings pinned to the seeded CloudTrail
      events, all before DeleteDetector). Never pair an old archive with a new seed.

## 7. People and endpoints

- [ ] 🤖 `roles`: `elasticon-attendee` (no response actions) and `elasticon-facilitator`.
- [ ] 🖱 Users: on ECH create native users (or SSO role mappings) with **elasticon-attendee**; the
      facilitator gets **elasticon-facilitator**. (Serverless: invite to the Cloud org and assign the role.)
- [ ] 🖱 *(Lab 5 WATCH step only)* one Linux host with **Elastic Defend** for the live isolate. Confirm the
      **Respond** button appears on it. Competing lead 1 no longer needs it: that alert is seeded.
- [ ] 🤖 `fp-history`: one real *AWS RDS Snapshot Export* alert, closed as a false positive and cloned onto
      28 prior nights with analyst notes. This is the corpus Alert analysis reads.

---

## Every session

```bash
cd seed-kit && source env.sh
python3 deploy.py seed      # campaign + criticality check + ML relearn + wait for rules, MOTHER data, GuardDuty archive, Wiz refresh
python3 deploy.py verify    # exit 0 = go
```

- [ ] Seed **≥ 1 hour before doors** (risk rescoring) and **< 24 hours** before (the guide says Last 24 hours;
      Wiz misconfigs expire after ~26 h).
- [ ] MOTHER enabled.
- [ ] One Attack Discovery generated at the front (Attacks → Settings → Select a connector → Save and run).
- [ ] Lab 5 start: `python3 scripts/fp_rds_export.py --live` (≥ 70 min after any rehearsal fire).
- [ ] After: release the Defend host if it was isolated.

# Azure AI Foundry setup

## Authentication: decide this first

| Symptom | Meaning | Path |
|---|---|---|
| Key auth works | Keys permitted | Store the key in secret scope `foundry` / `api_key` |
| `403 AuthenticationTypeDisabled` | `disableLocalAuth` policy is on | Use Entra ID, below |

### Entra ID (service principal) path

1. Entra ID → **App registrations** → New registration. Note the **Application (client) ID** and
   your **Directory (tenant) ID**.
2. **Certificates & secrets** → New client secret. Copy the value immediately.
3. Store it: `databricks secrets put-secret foundry sp_secret`
4. On the **Foundry resource** → Access control (IAM) → add **two** role assignments to that
   service principal:
   - `Cognitive Services OpenAI User`
   - `Cognitive Services User`

> ⚠️ **Both roles are required.** With only one you get `403 PermissionDenied` on the model call,
> which looks identical to a missing-role error. Allow **5–15 minutes** for RBAC to propagate
> before concluding something is wrong.

The notebooks fetch a token with `client_credentials` against scope
`https://cognitiveservices.azure.com/.default` and send it as a bearer token.

## Reasoning model parameters

The kit targets **reasoning models**. They differ from chat models:

| Chat models | Reasoning models |
|---|---|
| `max_tokens` | **`max_completion_tokens`** |
| `temperature`, `top_p` supported | **rejected — do not send** |
| — | `reasoning_effort`: `low` / `medium` / `high` |

`max_completion_tokens` is shared with hidden reasoning tokens, so budget generously (4000 is a
sane default for this workload).

## Smoke test

Run this before anything else. It must return **200**.

```python
import requests, json
r = requests.post(CHAT_URL, headers=HEADERS,
                  data=json.dumps({"messages":[{"role":"user","content":"ping"}],
                                   "max_completion_tokens":50}), timeout=60)
print(r.status_code, r.text[:300])
```

| Response | Cause |
|---|---|
| 200 | Good |
| 401 | Token expired or wrong scope |
| 403 `AuthenticationTypeDisabled` | Key auth disabled — use Entra ID |
| 403 `PermissionDenied` | Missing a role, or RBAC has not propagated yet |
| 404 | Wrong deployment name or API version |
| `JSONDecodeError` | Usually an unfilled `<placeholder>` in the config block |

---

# 09 — End-to-end deployment guide: Databricks → Azure AI Foundry → Execution

The single "do this from zero" guide. Where `08_end_to_end_demo_runbook.md` is the
*presenter's script*, this is the *build sheet*: every account, resource, permission,
command, and file, in order, from an empty subscription to a working detection that
scores an obfuscated PII query and raises an alert.

There are two LLM wiring options. Do **Path A** for the fastest working demo; add
**Path B** only if the customer wants the SOC/Sentinel integration.

- **Path A — Inline `ai_query()`** (all inside Databricks; a Foundry deployment is
  reached through a Databricks *external model* serving endpoint). ~90 min.
- **Path B — Event Hubs → Azure Function → Foundry** (the enterprise pipeline).
  +2 hrs.

Legend for who runs each step: **[AzAdmin]** Azure subscription/RBAC, **[DbxAdmin]**
Databricks account+metastore admin, **[Analyst]** the temporary-access insider.

---

## PHASE 0 — Accounts, roles, tooling (30 min) [AzAdmin/DbxAdmin]

| # | Item | How / check |
|---|------|-------------|
| 0.1 | **Azure subscription** with rights to create Azure AI Foundry (and, for Path B, Event Hubs + Function App). | Contributor on a resource group. |
| 0.2 | **Azure Databricks Premium** workspace, **Unity Catalog enabled**. | Workspace opens; a Unity Catalog metastore is attached. |
| 0.3 | You are a **Databricks account admin** AND **metastore admin**. | Account console → Users shows both roles. |
| 0.4 | **Databricks CLI ≥ 0.205** installed and authenticated. | `databricks auth login`; `databricks current-user me` returns you. |
| 0.5 | **Azure CLI** installed and logged in. | `az login`; `az account show`. |
| 0.6 | A **SQL Warehouse** (serverless or pro) in the workspace. | Runs `SELECT 1`. |
| 0.7 | Python 3.10+ locally for the helper scripts (Path B / the offline scorer test). | `python --version`. |

> **Region tip:** put the Databricks workspace, the Foundry resource, and (Path B) the
> Event Hub in the **same Azure region** to minimise latency and avoid cross-region
> egress review.

---

## PHASE 1 — Unity Catalog foundation (20 min) [DbxAdmin]

### 1.1 Enable the system tables you need
System tables are per-metastore and several are **off by default**. You need
`system.query` and `system.access`.

Check what's on:
```sql
SELECT schema_name FROM system.information_schema.schemata WHERE catalog_name='system';
```
Enable the missing schemas with the Unity Catalog API (replace `<metastore-id>`; get
it from `SELECT current_metastore()`):
```bash
# list schema shares and their state
databricks api get /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas

# enable the two we need
databricks api put /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas/query
databricks api put /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas/access
```
Records begin flowing within ~1 hour of enablement.

### 1.2 Make sure you can read raw SQL text (critical)
`system.query.history.statement_text` returns `<REDACTED>` for everyone except
account admins and members of the **account group `databricks_pii_access`**.
```sql
SELECT statement_text FROM system.query.history LIMIT 1;   -- must NOT be <REDACTED>
```
If redacted: account console → Groups → create/open `databricks_pii_access` → add the
identity that will run detection (you, and for Path B the detector service principal).

### 1.3 Create the demo groups and the analyst identity
Account console → Groups:
- `pii-temp-access` — the time-boxed insider group; add a **test user or service
  principal** to act as **[Analyst]**.
- `data-security-team` — reads detection output.
- (`databricks_pii_access` from 1.2.)

### 1.4 Create the hashing secret used by the "good" control
```bash
databricks secrets create-scope pii_demo
databricks secrets put-secret pii_demo hash_salt   # paste any long random string
```
This is what makes benign control **B3** a genuinely strong (secret-salted) hash.

---

## PHASE 2 — Load the sensitive data + tags (5 min) [DbxAdmin]

Open a SQL editor on your warehouse and run **`sql/01_setup_demo_data.sql`** end to end.

It creates `pii_demo.gold.customer_master` (10 rows of realistic PII), **tags the 7
sensitive columns**, creates the `security` output tables, and grants
`pii-temp-access` SELECT on gold + write only into `sandbox`.

**Checkpoint:** the final query returns 7 tagged columns. If not, stop and fix — every
downstream control keys off these tags.

---

## PHASE 3 — Simulate the insider (5 min) [Analyst]

Sign in as the `pii-temp-access` member and run **`sql/02_attacker_playbook.sql`** on the
warehouse. 12 obfuscation techniques (concat-pad, column split, reversal,
base64/hex, per-char explosion, arithmetic, JSON packing, two-hop laundering, a view,
bulk copy, an **unsalted hash**, and a **quasi-identifier** table) plus 4 benign
controls.

**Checkpoint:** all statements succeed; `pii_demo.sandbox` now holds the derived
tables.

> ⏳ **Wait 30–60 minutes** for `system.query.history` and `system.access.column_lineage`
> to populate before Phase 5. Verify:
> ```sql
> SELECT count(*) FROM system.access.column_lineage WHERE event_date = current_date();
> ```
> Lineage `statement_id` is only set for **SQL-warehouse** runs — make sure the attacks
> ran on the warehouse, not an interactive all-purpose cluster.

---

## PHASE 4 — Azure AI Foundry: deploy the judge model (20 min) [AzAdmin]

Both paths call the same model. Deploy it once.

### 4.1 Create the Foundry resource + project
Azure portal → **Azure AI Foundry** → create a resource (this provisions an
Azure OpenAI-compatible endpoint), then open **Foundry portal** (ai.azure.com) and
create/select a **project**.

### 4.2 Deploy a chat model
Foundry portal → **Models + endpoints** → **Deploy model** → pick **`gpt-4o-mini`**
(ample and cheap for this classification task) → give the deployment a name, e.g.
`pii-dlp-judge`.

### 4.3 Capture the three values you'll need
From the deployment's **Details** / **Endpoint** panel:
- **Endpoint base URL** — `https://<your-resource>.openai.azure.com/`
- **Deployment name** — `pii-dlp-judge`
- **API key** (Path A external model / offline test) **or** plan to use **Managed
  Identity** (Path B, recommended — no keys).
- **API version** — e.g. `2024-10-21` (use the version shown for your resource).

### 4.4 Privacy hardening (do before sending real data)
`statement_text` can contain PII in literals. For a customer engagement, deploy the
model in **their** tenant, turn **off** content logging / abuse-monitoring retention
where policy requires, and put a **Private Endpoint** in front of the resource so
traffic never traverses the public internet. Document the choice — their privacy team
will ask.

---

## PHASE 5 — PATH A: inline `ai_query()` (30 min) [DbxAdmin]

### 5.1 Store the Foundry key as a Databricks secret
```bash
databricks secrets create-scope foundry            # skip if it exists
databricks secrets put-secret foundry api_key       # paste the key from 4.3
```

### 5.2 Create the external model serving endpoint
Two ways — UI or SDK. The endpoint **name** (`pii-dlp-judge`) is what you put in
`ai_query()`.

**UI:** Serving → **Create serving endpoint** → **External model** → provider
**Azure OpenAI** → paste base URL, deployment name, API version, and select the
`foundry/api_key` secret → name it `pii-dlp-judge`.

**SDK (reproducible):** run **`create_serving_endpoint.py`** from this kit, or:
```python
import mlflow.deployments
client = mlflow.deployments.get_deploy_client("databricks")
client.create_endpoint(
    name="pii-dlp-judge",
    config={"served_entities": [{
        "name": "pii-dlp-judge",
        "external_model": {
            "name": "gpt-4o-mini",
            "provider": "openai",
            "task": "llm/v1/chat",
            "openai_config": {
                "openai_api_type": "azure",
                "openai_api_key": "{{secrets/foundry/api_key}}",
                "openai_api_base": "https://<your-resource>.openai.azure.com",
                "openai_deployment_name": "pii-dlp-judge",
                "openai_api_version": "2024-10-21",
            },
        },
    }]},
)
```
**Checkpoint:** Serving shows the endpoint **Ready**. Smoke-test it:
```sql
SELECT ai_query('pii-dlp-judge', 'Reply with the single word OK.') AS ping;
```

### 5.3 Run detection
Open **`sql/03_detection.sql`**:
1. Run **Steps A–C** (tag dictionary → lineage write-events → candidates + rules).
   - Checkpoint: `SELECT * FROM security.v_pii_candidates ORDER BY rule_score DESC;`
     returns your attacks; `region_code_lookup` shows `pii_col_count=1,
     target_col_count=3`.
2. In **Step D**, replace `<endpoint-name>` with `pii-dlp-judge` (the refined v2 prompt
   is already loaded into `security.llm_prompt_config` by the script — nothing to
   paste). Run D1→D4.
   - Checkpoint: verdicts table — attacks come back LIKELY_EXFILTRATION / SUSPICIOUS,
     benign controls BENIGN. The **unsalted hash → SUSPICIOUS** and **secret-salted
     hash → BENIGN** pair is the proof the refined prompt works.

Path A is complete. Jump to Phase 7.

---

## PHASE 6 — PATH B: Event Hubs → Azure Function → Foundry (2 hrs) [AzAdmin + DbxAdmin]

Use this when the security team owns the pipeline or it must land in Sentinel/Fabric.

### 6.1 Event Hubs [AzAdmin]
```bash
az eventhubs namespace create -g <rg> -n <ns> -l <region> --sku Standard
az eventhubs eventhub create  -g <rg> --namespace-name <ns> -n pii-query-events \
    --partition-count 2 --retention-time-in-hours 24
```
RBAC (Managed Identity, no connection strings):
- Databricks job's identity → **Azure Event Hubs Data Sender** on the hub.
- Function App's identity → **Azure Event Hubs Data Receiver** on the hub.

### 6.2 Databricks detector job [DbxAdmin]
1. Import **`05_detector_job_eventhub.py`** as a notebook.
2. Secrets: `databricks secrets put-secret pii-demo eh-namespace` (value
   `<ns>.servicebus.windows.net`) and `... eh-name` (value `pii-query-events`).
3. Cluster libraries: `azure-eventhub`, `azure-identity`.
4. Run the job **as the detector service principal** (account admin or
   `databricks_pii_access` member — see 1.2).
5. Schedule every **15 minutes**. It watermarks + looks back 90 min to absorb the ~1h
   system-table lag, dedupes on `statement_id`, and publishes only candidates.

**Checkpoint:** after a run, `security.pii_query_candidates` has rows and the job log
prints "Published N events".

### 6.3 Function App → Foundry [AzAdmin]
1. Deploy **`06_foundry_scorer.py`** (Python v2 model):
   ```bash
   func init pii-scorer --python -m V2
   # add azure-functions, azure-identity, openai, databricks-sql-connector to requirements.txt
   func azure functionapp publish <function-app-name>
   ```
2. App settings:
   - `FOUNDRY_ENDPOINT` = `https://<your-resource>.openai.azure.com/`
   - `FOUNDRY_DEPLOYMENT` = `pii-dlp-judge`
   - `FOUNDRY_API_VERSION` = `2024-10-21`
   - `EVENTHUB_NAME` = `pii-query-events`
   - `EventHubConnection__fullyQualifiedNamespace` = `<ns>.servicebus.windows.net`
   - `DATABRICKS_HOST`, `DATABRICKS_HTTP_PATH` (from the SQL warehouse connection details)
   - `ALERT_THRESHOLD` = `70`
3. RBAC: Function identity → **Cognitive Services OpenAI User** on the Foundry
   resource; and a Databricks service principal with **INSERT** on
   `pii_demo.security`.

**Checkpoint (offline, before wiring anything):**
```bash
export FOUNDRY_ENDPOINT="https://<your-resource>.openai.azure.com/"
export FOUNDRY_DEPLOYMENT="pii-dlp-judge"
python 06_foundry_scorer.py sample_event.json
# -> prints a LIKELY_EXFILTRATION verdict with reversibility_class=trivially_invertible
```
Then end-to-end: re-run one attack (Phase 3), wait for the 15-min job, and
`SELECT * FROM pii_demo.security.pii_query_verdicts ORDER BY scored_at DESC;`.

---

## PHASE 7 — Alerting + dashboard (20 min) [DbxAdmin]

### 7.1 SQL Alert
Create a Databricks SQL query:
```sql
SELECT count(*) AS high_risk
FROM   pii_demo.security.pii_query_verdicts
WHERE  scored_at > current_timestamp() - INTERVAL 15 MINUTES
  AND  risk_score >= 70;
```
Schedule every 5–10 min; alert when `high_risk > 0` → Teams webhook / email to
`data-security-team`.

### 7.2 Dashboard (4 tiles)
- High-risk verdicts over time.
- Top actors by count of PII columns touched.
- **`reversibility_class`** distribution (now a real column).
- Open `sandbox` tables derived from PII with **no** `pii_transform_allowlist` entry.

### 7.3 (Path B) Sentinel
Ship the Function's App Insights logs (the structured `PII_EXFIL_ALERT` lines) into
Microsoft Sentinel and build an analytics rule on `risk_score >= 70`.

---

## PHASE 8 — Prevention (the point) (15 min) [DbxAdmin]

Run **`sql/04_preventive_controls.sql`** to apply column masks + the ABAC policy on every
`pii_direct`-tagged column. Then, as **[Analyst]**, re-run Attack 2 and query the
result: `region_cd='XXX'`, `seq_no=` last-4 only. The attack completes and extracts
nothing. Re-run detection to show you still get the alert.

Closing line: *"Detection tells you it happened. Masking makes it not matter. Do both —
but do masking first."*

---

## Execution order at a glance

```
PHASE 0  accounts, CLI, warehouse            [AzAdmin/DbxAdmin]
PHASE 1  enable system tables, groups, secret[DbxAdmin]
PHASE 2  run sql/01_setup_demo_data.sql          [DbxAdmin]
PHASE 3  run sql/02_attacker_playbook.sql        [Analyst]   -> wait ~1h
PHASE 4  deploy gpt-4o-mini in Foundry       [AzAdmin]
   PATH A                             |   PATH B
PHASE 5  external model endpoint +    |   PHASE 6 Event Hub + Job(05) +
         run sql/03_detection.sql (D)     |           Function(06) + Foundry
PHASE 7  SQL Alert + dashboard        [DbxAdmin]
PHASE 8  sql/04_preventive_controls.sql   [DbxAdmin]  (the closer)
```

---

## Appendix A — RBAC / permissions summary

| Identity | Needs | Where |
|---|---|---|
| Detector (you / SP) | Account admin **or** `databricks_pii_access`; SELECT on `system.query`, `system.access`, `system.information_schema` | Databricks account |
| Analyst | Member of `pii-temp-access`; SELECT on `gold.customer_master`; write on `sandbox` | Granted by `01` |
| Databricks job (Path B) | Azure Event Hubs **Data Sender** | Event Hub |
| Function App (Path B) | Event Hubs **Data Receiver**; Cognitive Services **OpenAI User**; INSERT on `pii_demo.security` | Event Hub / Foundry / UC |

## Appendix B — Environment variables (Path B)

| Var | Example |
|---|---|
| `FOUNDRY_ENDPOINT` | `https://myres.openai.azure.com/` |
| `FOUNDRY_DEPLOYMENT` | `pii-dlp-judge` |
| `FOUNDRY_API_VERSION` | `2024-10-21` |
| `EVENTHUB_NAME` | `pii-query-events` |
| `EventHubConnection__fullyQualifiedNamespace` | `myns.servicebus.windows.net` |
| `DATABRICKS_HOST` | `adb-1234.7.azuredatabricks.net` |
| `DATABRICKS_HTTP_PATH` | `/sql/1.0/warehouses/abc123` |
| `ALERT_THRESHOLD` | `70` |

## Appendix C — Cost & scale note
Stage 1 (lineage + rules) is free and cuts millions of daily statements to tens.
Only those tens hit the model, so at `gpt-4o-mini` rates this is typically **cents per
day**. Never send raw `system.query.history` to a model — cost and false positives
both explode.

## Appendix D — Teardown
```sql
DROP CATALOG IF EXISTS pii_demo CASCADE;
```
```bash
# Path A
databricks serving-endpoints delete pii-dlp-judge
# Path B
az eventhubs namespace delete -g <rg> -n <ns>
az functionapp delete -g <rg> -n <function-app-name>
# Foundry: delete the deployment / resource in the portal
```

## Appendix E — Version caveat
The `ai_query()` signature, the external-model config keys, and the Foundry portal
flow move faster than the system-table schemas. The external-model config in Phase 5.2
is grounded in the current Databricks "external models" tutorial (`task: llm/v1/chat`,
`openai_config` with `openai_api_type: azure`). Re-validate the `openai_api_version`
and the `ai_query` named arguments against your workspace's runtime before a customer
session.

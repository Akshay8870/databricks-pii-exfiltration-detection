# Complete setup guide

From an empty subscription to a working end-to-end demo. **Follow in order.** Every step has a
verification you must pass before moving on — this matters, because a failure at step 12 is nearly
impossible to diagnose if step 4 was silently wrong.

**Total time:** 2–3 hours for a first run, ~30 minutes once you have done it before.

| Need | Guide |
|---|---|
| 45-minute path, prerequisites already met | [QUICKSTART.md](QUICKSTART.md) |
| **Full setup from nothing** | **this document** |
| Something is broken | [docs/07-troubleshooting.md](docs/07-troubleshooting.md) |
| Why it is built this way | [docs/00-architecture.md](docs/00-architecture.md) |

## Who needs to do what

Three roles. One person can hold all three, but in a customer environment they are usually
separate — identify who holds each **before** you start, because waiting on an Entra admin
mid-setup is the most common delay.

| Role | Needs | Steps |
|---|---|---|
| **Azure admin** | Subscription Contributor; Entra privileges for app registration + role assignment | 1, 11–14 |
| **Databricks admin** | Account admin + metastore admin | 2–10, 15–18 |
| **Analyst** (demo persona) | Temporary SELECT on the PII table | 19 |

---

# Part A · Azure Databricks foundation

## Step 1 — Create the workspace · *Azure admin · 10 min*

Azure portal → **Create a resource** → **Azure Databricks**.

| Field | Value |
|---|---|
| Resource group | new, e.g. `rg-pii-demo` |
| Workspace name | e.g. `dbx-pii-demo` |
| Region | one that supports Unity Catalog **and** your Foundry region |
| **Pricing tier** | **Premium** — Unity Catalog requires it. Standard will not work. |

Create, then **Launch workspace**.

> **Region matters twice.** Pick a region where both Databricks and your intended Foundry model are
> available, and that satisfies your data-residency obligations. Changing it later means rebuilding.

**✅ Verify:** the workspace opens and the left nav shows **Catalog**.

## Step 2 — Confirm Unity Catalog · *Databricks admin · 5 min*

In the workspace: **Catalog** in the left nav.

- **A metastore is attached** → continue to step 3.
- **"No metastore assigned"** → account console (`accounts.azuredatabricks.net`) → **Catalog** →
  **Create metastore** (one per region) → open it → **Workspaces** tab → **Assign to workspace**.

**✅ Verify:**
```sql
SELECT current_metastore();
```
Returns an id. **Copy it — you need it at step 5.**

## Step 3 — Get account admin and metastore admin · *Azure admin + Databricks admin · 15 min*

You need **both** roles. If **Manage account** does not appear in your workspace, this is an
**Entra ID elevation**, not a Databricks setting:

1. Azure portal → activate your **Global Administrator** role (via PIM if your org uses it).
2. **Entra ID** → **Properties** → scroll to **Access management for Azure resources** →
   toggle **Yes**. This grants User Access Administrator at root scope.
3. Open `accounts.azuredatabricks.net`. You now have access.
4. **User management** → your user → grant **Account admin**.
5. **Catalog** → your metastore → **Admins** → add yourself as **Metastore admin**.
6. **Turn the step-2 toggle back OFF.** It is a standing privilege escalation and should not persist.

> Accounts created after November 2023 may have **no** metastore admin assigned at all.

**✅ Verify:** account console → User management shows both roles against your user.

## Step 4 — Create compute · *Databricks admin · 10 min*

You need **two** things, and the second trips people up.

**4a. SQL Warehouse** — for all SQL steps.
**SQL Warehouses** → **Create** → Serverless (simplest), size 2X-Small, auto-stop 10 min.

**4b. A UC-governed cluster** — for the notebook steps.
**Compute** → **Create compute** → single node is fine →
**Access mode must be `Shared` or `Single user`**.

> ⚠️ **This is the single most common silent failure in the whole setup.** On a No-isolation shared
> cluster everything runs fine, writes succeed, and **no lineage is produced at all**. You will see
> an empty detection result with no error anywhere.

**✅ Verify:** both start successfully. On the cluster, run `spark.sql("SELECT current_metastore()").show()`.

## Step 5 — Enable system schemas · *Databricks admin · 10 min*

There is **no UI toggle** for this. Install the CLI and authenticate:

```bash
pip install databricks-cli
databricks configure --host https://<your-workspace>.azuredatabricks.net
```

Using the metastore id from step 2:

```bash
# see current state
databricks api get /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas

# enable the two this solution needs
databricks api put /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas/query
databricks api put /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas/access
```

> A **403 on a schema already reported as `MANAGED`** is harmless — it is already enabled.

**✅ Verify** (data may take a few minutes to begin populating):
```sql
SELECT count(*) FROM system.access.column_lineage WHERE event_date >= current_date() - 7;
SELECT count(*) FROM system.access.table_lineage  WHERE event_date >= current_date() - 7;
SELECT count(*) FROM system.query.history WHERE start_time >= current_timestamp() - INTERVAL 1 DAY;
```
All three must run without error.

## Step 6 — Confirm statement text is not redacted · *Databricks admin · 5 min*

```sql
SELECT statement_text FROM system.query.history
WHERE start_time >= current_timestamp() - INTERVAL 1 HOUR LIMIT 5;
```

**If you see `<REDACTED>`**, Stage 1's text rules cannot fire. Fix it: account console →
**User management** → **Groups** → create `databricks_pii_access`, add the detector identity, and
grant it access to query history. Reading as an account admin also works.

**✅ Verify:** real SQL text, not `<REDACTED>`.

## Step 7 — Create secret scopes · *Databricks admin · 5 min*

**Never put a key in a notebook.**

```bash
databricks secrets create-scope foundry
databricks secrets create-scope pii_demo

# a genuine random salt - this makes the BENIGN example actually benign
databricks secrets put-secret pii_demo hash_salt
```

**✅ Verify:**
```bash
databricks secrets list-scopes
```

---

# Part B · Azure AI Foundry

## Step 8 — Create the Foundry resource · *Azure admin · 10 min*

Azure portal → **Create a resource** → **Azure AI Foundry** (Azure AI Services).

Same resource group as Databricks. Choose a region consistent with your data-residency
requirements — see [docs/08-privacy.md](docs/08-privacy.md).

**✅ Verify:** the resource deploys and you can open Azure AI Foundry Studio.

## Step 9 — Deploy a reasoning model · *Azure admin · 10 min*

Foundry Studio → your project → **Deployments** → **Deploy model**.

Choose a **reasoning model** — `o4-mini`, `gpt-5-mini`, `o3-mini` class. The kit is written and
tested against these.

**Capture three values from the endpoint panel:**

| Value | Example |
|---|---|
| Endpoint host | `https://<resource>.cognitiveservices.azure.com` |
| Deployment name | `pii-dlp-judge` |
| API version | `2025-04-01-preview` |

> **Reasoning models are not chat models.** They use `max_completion_tokens` (not `max_tokens`),
> accept `reasoning_effort`, and **reject `temperature` and `top_p` outright**. The notebooks
> already handle this — do not "fix" them by adding `temperature`.

**✅ Verify:** the deployment shows **Succeeded**.

## Step 10 — Decide your auth path · *Azure admin · 5 min*

Try the key first:

```bash
curl -X POST "https://<resource>.cognitiveservices.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>" \
  -H "api-key: <key>" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"ping"}],"max_completion_tokens":50}'
```

| Result | Path |
|---|---|
| **200** | Key auth works → **step 11a**, skip 11b |
| **403 `AuthenticationTypeDisabled`** | Policy blocks keys → **step 11b** |

## Step 11a — Key auth · *5 min*

```bash
databricks secrets put-secret foundry api_key
```
Skip to step 12.

## Step 11b — Entra ID service principal · *Azure admin · 20 min*

1. **Entra ID** → **App registrations** → **New registration**. Name it, e.g. `sp-pii-detector`.
   Capture the **Application (client) ID** and **Directory (tenant) ID**.
2. **Certificates & secrets** → **New client secret**. **Copy the value immediately** — it is shown
   once.
3. Store it:
   ```bash
   databricks secrets put-secret foundry sp_secret
   ```
4. **Foundry resource** → **Access control (IAM)** → **Add role assignment**. Assign **BOTH** to
   that service principal:
   - `Cognitive Services OpenAI User`
   - `Cognitive Services User`

> ⚠️ **Both roles are mandatory.** With only one you get `403 PermissionDenied` on the model call,
> which looks identical to having no role at all. **RBAC takes 5–15 minutes to propagate** — if it
> fails immediately after assignment, wait before changing anything.

**✅ Verify:** you hold tenant id, client id, and the secret is stored.

---

# Part C · Deploy the solution

## Step 12 — Get the code into the workspace · *Databricks admin · 5 min*

Either clone via **Workspace → Repos → Add Repo**, or **Workspace → Import → File** for the files
you need.

Import these **as notebooks**:
- `notebooks/scorer_03_spark.py`
- `notebooks/attacker_pyspark.py`

## Step 13 — Set your catalog name · *Databricks admin · 2 min*

The repo ships with `pii_demo` as the catalog name. Change it to yours:

```bash
grep -rl 'pii_demo' sql/ notebooks/ | xargs sed -i 's/pii_demo/<your_catalog>/g'
```
macOS: use `sed -i ''`.

> Leave it as `pii_demo` if you are building a throwaway demo catalog — simpler, and the runbooks
> match verbatim.

## Step 14 — Create the demo data and tags · *Databricks admin · 5 min*

Run **`sql/01_setup_demo_data.sql`** in the SQL warehouse.

This creates `gold.customer_master` (10 rows of synthetic PII) and — critically — **tags seven
columns**. The tags drive everything downstream; nothing works without them.

> `CREATE TAG` is **not** needed and fails with `PARSE_SYNTAX_ERROR` on most workspaces.
> `ALTER TABLE … SET TAGS` creates tag keys implicitly. The shipped SQL does it correctly.

**✅ Verify:**
```sql
SELECT column_name, tag_name, tag_value
FROM   system.information_schema.column_tags
WHERE  catalog_name = '<your_catalog>';
```
**Expect 7 tagged columns.** If this returns nothing, stop — everything downstream will be empty.

## Step 15 — Build the detection views · *Databricks admin · 5 min*

Run **in this order**. Each is additive and safe to re-run.

| File | Creates | Needed for |
|---|---|---|
| `sql/03_detection.sql` | `v_pii_candidates` | SQL warehouse statements |
| `sql/05_multihop_lineage.sql` | `v_pii_candidates_mh` | + derived-table laundering |
| `sql/06_notebook_spark_detection.sql` | `v_pii_candidates_all` | + notebooks and storage paths |

**✅ Verify:**
```sql
SELECT count(*) FROM <your_catalog>.security.v_pii_candidates_all;
```
Must not error. **Zero rows is correct here** — nothing has been attacked yet.

## Step 16 — Configure and smoke-test the scorer · *Databricks admin · 10 min*

Open `scorer_03_spark.py`. Fill the config block with your step 9 and 11 values:

```python
FOUNDRY_HOST = "https://<your-foundry-resource>.cognitiveservices.azure.com"
DEPLOYMENT   = "<your-deployment-name>"
API_VERSION  = "<from the endpoint panel>"
TENANT_ID    = "<directory-tenant-id>"
CLIENT_ID    = "<app-registration-client-id>"
ONLY_TODAY   = True          # keep this on for demos
```

Attach to the UC cluster from step 4b. **Run only the auth cell**, then:

```python
import requests, json
r = requests.post(CHAT_URL, headers=HEADERS,
                  data=json.dumps({"messages":[{"role":"user","content":"ping"}],
                                   "max_completion_tokens":50}), timeout=60)
print(r.status_code, r.text[:300])
```

> 🛑 **STOP HERE if this is not 200.** Do not continue. Every later failure becomes far harder to
> diagnose, and the error you will see downstream will not point at this.

| Code | Cause |
|---|---|
| 200 | Good — continue |
| 401 | Token expired or wrong scope |
| 403 `AuthenticationTypeDisabled` | Key auth disabled → step 11b |
| 403 `PermissionDenied` | Missing a role, or RBAC not propagated — wait 15 min |
| 404 | Wrong deployment name or API version |
| `JSONDecodeError` | An unfilled `<placeholder>` in the config block |

## Step 17 — Apply preventive controls *(optional but recommended)* · *5 min*

Run **`sql/04_preventive_controls.sql`**.

This is the honest centre of the whole story: with a column mask in place, a temporary-access user
never sees raw values, so every obfuscation technique operates on already-masked data. **Detection
is the net; masking is the fence.**

Keep it un-applied for the demo (so attacks produce recoverable data), then apply it live as the
closer.

---

# Part D · First end-to-end run

## Step 18 — Fire the attacks · *Analyst · 5 min*

**SQL attacks:** run `sql/02_attacker_playbook.sql`.

**Notebook attacks:** first create a write target —
```sql
CREATE VOLUME IF NOT EXISTS <your_catalog>.sandbox.exfil_vol;
```
or set `BASE` in `attacker_pyspark.py` to a real ADLS path (needs an external location and storage
credential — more convincing on stage).

Run `attacker_pyspark.py` **on the UC cluster from step 4b**, then paste the `%scala` cell it prints
into a new cell and run that too.

## Step 19 — Wait for lineage · *5–15 min*

Documented as up to an hour; in practice usually minutes. Deep chains land **progressively** —
hop 1 must exist before hop 2 resolves.

```sql
SELECT count(*) FROM system.access.column_lineage WHERE event_date = current_date();

SELECT entity_type, count(*) FROM system.access.column_lineage
WHERE event_date = current_date() GROUP BY entity_type;
```

Seeing **`NOTEBOOK`** rows confirms the notebook path is live.

For path targets:
```sql
-- ALWAYS lead with % - Databricks records Volume paths as dbfs:/Volumes/...
SELECT target_path, target_type, entity_type, count(*) AS col_edges
FROM   system.access.column_lineage
WHERE  event_date = current_date() AND target_path IS NOT NULL
GROUP BY target_path, target_type, entity_type;
```

> ⚠️ **Never anchor a path `LIKE` at the start.** `LIKE '/Volumes/...%'` returns zero because the
> recorded value begins `dbfs:`. This costs people an hour the first time.

## Step 20 — Stage 1 results · *2 min*

```sql
SELECT target_object, target_type, entity_type, rule_score, rule_reasons
FROM   <your_catalog>.security.v_pii_candidates_all
ORDER BY rule_score DESC;
```

Every attack should appear with its rule reasons. **If this is empty but lineage has rows**, the
tags did not land — go back to step 14.

## Step 21 — Stage 2: score with the model · *5 min*

Run `scorer_03_spark.py` in full.

**Expected shape — this is the acceptance test:**

| Target | Verdict | Why |
|---|---|---|
| split / padded / encoded | LIKELY_EXFILTRATION 90+ | Trivially reversible |
| unsalted hash | **SUSPICIOUS ~70–85** | Weak one-way, low entropy |
| quasi-identifier cohort | **SUSPICIOUS** | Re-identification by combination |
| secret-salted hash | **BENIGN ~12** | Genuinely strong one-way |

> 🛑 **If everything scores 95+, the setup is wrong** — almost certainly the salted-hash example is
> not using a real secret from the `pii_demo` scope (step 7). The nuanced verdicts are the entire
> point; a detector that screams at everything gets muted in a week.

---

# Verification checklist

Tick all before presenting.

```
FOUNDATION
[ ]  1. Workspace is Premium tier
[ ]  2. Unity Catalog metastore attached; current_metastore() returns an id
[ ]  3. You are account admin AND metastore admin
[ ]  3. Entra root-scope toggle turned back OFF
[ ]  4. SQL warehouse running
[ ]  4. Cluster access mode is Shared or Single User   ← silent failure if wrong
[ ]  5. system.access and system.query queryable
[ ]  6. statement_text is NOT <REDACTED>
[ ]  7. Secret scopes foundry and pii_demo exist; hash_salt is a real random value

FOUNDRY
[ ]  9. Reasoning model deployed, status Succeeded
[ ]  9. Host, deployment name, API version captured
[ ] 11. Auth path chosen; if Entra, BOTH Cognitive Services roles assigned
[ ] 16. Smoke test returns 200                          ← hard gate

SOLUTION
[ ] 13. Catalog name matches your environment everywhere
[ ] 14. 7 tagged columns confirmed                      ← hard gate
[ ] 15. v_pii_candidates_all queries without error
[ ] 19. Lineage shows NOTEBOOK rows and PATH targets
[ ] 21. Verdicts include at least one BENIGN and one SUSPICIOUS
```

# The three failures that cause most lost time

1. **Non-UC cluster** (step 4b) — everything succeeds, no lineage exists, no error anywhere.
2. **Only one Cognitive Services role** (step 11b) — `403 PermissionDenied`, indistinguishable from
   having no role. And RBAC needs 15 minutes before the failure means anything.
3. **Path `LIKE` anchored at the start** (step 19) — returns zero and looks like nothing was
   captured, when in fact everything was.

# What next

| Goal | Go to |
|---|---|
| Present it | [runbooks/README.md](runbooks/README.md) — 11 scripts with talk-track |
| Understand the internals | [docs/06-detection-internals.md](docs/06-detection-internals.md) |
| Answer "what leaves Databricks?" | [docs/08-privacy.md](docs/08-privacy.md) |
| Move toward production | [docs/00-architecture.md](docs/00-architecture.md#deployment-options) and the production notes in [sql/README.md](sql/README.md) |
| Something broke | [docs/07-troubleshooting.md](docs/07-troubleshooting.md) |

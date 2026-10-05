# Prerequisites

Work through this list before anything else. Most failed setups trace back to items 3, 4 or 6.

## 1. Azure Databricks

- **Premium tier** workspace (Unity Catalog requires it)
- **Unity Catalog enabled**, with a metastore attached to the workspace
- A **SQL Warehouse** (serverless is fine) for the SQL steps
- A **UC-governed cluster** for the notebook steps — access mode **Shared** or **Single User**

> ⚠️ **Lineage is only captured on UC-governed compute.** On a no-isolation cluster everything runs
> fine, writes succeed, and **nothing appears in lineage at all**. This is the single most common
> cause of a silent, confusing failure.

## 2. Your identity

You need to be **both**:
- a Databricks **account admin**, and
- a **metastore admin**

Check in the account console under Users and under Catalog → your metastore → Admins.

If "Manage account" does not appear in your workspace, see
[02-databricks-setup.md](02-databricks-setup.md#getting-account-admin) — this is an Entra ID
elevation, not a Databricks setting.

## 3. System schemas enabled

The solution reads four system objects:

| Object | Schema | Default state |
|---|---|---|
| `system.access.column_lineage` | `access` | often **off** |
| `system.access.table_lineage` | `access` | often **off** |
| `system.query.history` | `query` | often **off** |
| `system.information_schema.column_tags` | always available | on |

Verify:
```sql
SELECT * FROM system.information_schema.schemata WHERE catalog_name = 'system';
```

Enabling them is an API call, not a UI toggle — see
[02-databricks-setup.md](02-databricks-setup.md#enabling-system-schemas).

> Some workspaces report system schemas as already `MANAGED`. A 403 when trying to enable them in
> that state is harmless — they are already on.

## 4. Unredacted statement text

`system.query.history.statement_text` is **redacted** unless the reading identity is an account
admin or a member of a group granted access. If you see `<REDACTED>`, Stage 1's text rules cannot
fire. Create and join an account group (commonly named `databricks_pii_access`) or read as an
account admin.

## 5. Azure AI Foundry

- A Foundry (Azure AI Services) resource
- A **chat/reasoning model deployment** — the kit is tested against reasoning models
  (`o4-mini`, `gpt-5-mini`, `o3-mini` class)
- The **deployment name** and **API version** from the endpoint panel

> **Reasoning models reject `temperature` and `top_p`.** They use `max_completion_tokens` (not
> `max_tokens`) and accept `reasoning_effort`. The notebooks already account for this.

## 6. Authentication to Foundry

Two paths. Check which your organisation permits **before** you build:

| Path | When | Setup |
|---|---|---|
| **API key** | Key auth allowed on the resource | Store in a Databricks secret scope |
| **Entra ID (service principal)** | Key auth disabled by policy (`disableLocalAuth`) | App registration + client secret + **two role assignments** |

> ⚠️ If key auth is disabled you will get `403 AuthenticationTypeDisabled`. The service principal
> path needs **both** `Cognitive Services OpenAI User` **and** `Cognitive Services User` on the
> Foundry resource. One alone returns `403 PermissionDenied`. RBAC propagation takes 5–15 minutes.

Full walkthrough: [03-foundry-setup.md](03-foundry-setup.md).

## 7. Databricks secret scopes

Never put a key or secret in a notebook. Create scopes with the Databricks CLI:

```bash
databricks secrets create-scope foundry
databricks secrets put-secret foundry api_key        # key auth
databricks secrets put-secret foundry sp_secret      # Entra ID path

databricks secrets create-scope pii_demo
databricks secrets put-secret pii_demo hash_salt     # for the BENIGN salted-hash example
```

## 8. For the notebook / Spark demo only

A writable storage target. Either:

```sql
CREATE VOLUME IF NOT EXISTS <catalog>.sandbox.exfil_vol;
```

or a real ADLS path with an **external location** and **storage credential** your user can write
to. The ADLS path is more convincing on stage; the Volume needs no setup.

---

## Pre-flight check

Run this. All four must return without error.

```sql
SELECT count(*) FROM system.access.column_lineage WHERE event_date >= current_date() - 7;
SELECT count(*) FROM system.access.table_lineage  WHERE event_date >= current_date() - 7;
SELECT count(*) FROM system.query.history         WHERE start_time >= current_timestamp() - INTERVAL 1 DAY;
SELECT current_metastore();
```

Then confirm statement text is visible, not redacted:

```sql
SELECT statement_text FROM system.query.history
WHERE start_time >= current_timestamp() - INTERVAL 1 HOUR LIMIT 5;
```

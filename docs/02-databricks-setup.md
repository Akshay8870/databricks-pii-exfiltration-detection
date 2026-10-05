# Databricks workspace setup

Covers workspace, Unity Catalog, admin rights, system schemas and secret scopes.
Prerequisites list: [01-prerequisites.md](01-prerequisites.md).

## Getting account admin

If **Manage account** does not appear in your workspace, this is an **Entra ID** elevation, not a
Databricks setting. The sequence is:

1. In the Azure portal, activate your **Global Administrator** role (via PIM if your org uses it).
2. Entra ID → **Properties** → scroll to **Access management for Azure resources** → toggle **Yes**.
   This grants your account User Access Administrator at the root scope.
3. Open the **Databricks account console** (`accounts.azuredatabricks.net`). You now have access.
4. Grant your own user the **Account admin** role explicitly.
5. Catalog → your metastore → **Admins** → add yourself as **Metastore admin**.
6. **Turn the toggle in step 2 back off** once finished. It is a standing privilege escalation.

> Accounts created after November 2023 may have **no** metastore admin assigned by default.

## Enabling system schemas

System schemas are per-metastore and several are off by default. There is no UI toggle — use the
API. Get your metastore id with `SELECT current_metastore();`.

```bash
# what is available and what state is it in
databricks api get /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas

# enable the two we need
databricks api put /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas/query
databricks api put /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas/access
```

A **403 on a schema already reported as `MANAGED`** is harmless — it is already enabled.

Data takes a short while to begin populating after enablement.

---

# 10 — Azure Databricks workspace → demo data (detailed, click-by-click)

The zero-to-data runbook: from an empty Azure subscription to
`pii_demo.gold.customer_master` populated and tagged, ready for the attack playbook.
This expands Phases 0–2 of `docs/03-foundry-setup.md` into portal-level
detail. Budget ~40 minutes (plus workspace provisioning time).

At the end you will have: a Premium Databricks workspace on Unity Catalog, a SQL
Warehouse, the `system.query` + `system.access` system tables enabled, the demo
groups, and the sensitive table created **and column-tagged**.

---

## Prerequisites

| Need | Detail |
|------|--------|
| Azure subscription | With rights to create resources (Contributor on a resource group). |
| Azure AD role | Ability to be/assign a Databricks **account admin** (Global Admin or the account owner does the first-time account setup). |
| Tier | You must choose the **Premium** pricing tier — Unity Catalog, column tags, masks, and system tables are **not** available on Standard. |
| Region | Pick a region where you'll also deploy Foundry later; system tables are regional. |

---

## PART 1 — Create the Azure Databricks workspace (Azure portal)

1. Azure portal → **Create a resource** → search **Azure Databricks** → **Create**.
2. **Basics** tab:
   - **Subscription** / **Resource group** — pick or create a resource group, e.g. `rg-pii-demo`.
   - **Workspace name** — e.g. `dbx-pii-demo`.
   - **Region** — e.g. `Central India` / `East US` (keep everything in one region).
   - **Pricing Tier** — **Premium (+ Role-based access controls)**. Do **not** pick Standard or Trial-Standard.
   - **Workspace type** — **Serverless** for this demo. It needs no VNet/storage setup, uses Databricks-managed storage + serverless compute, and fully supports Unity Catalog, system tables, tags, masks, and a serverless SQL warehouse (which is what captures lineage `statement_id`). Choose **Hybrid** (classic — compute + storage in your own Azure account, custom compute) only for a real deployment that needs your own ADLS, VNet injection / private endpoints, customer-managed keys, or specific instance types.
3. **Networking** tab (Hybrid only): leave defaults for a demo ("No" to Secure Cluster Connectivity/VNet injection unless the customer requires it). For a customer's real environment, VNet injection + private connectivity is where you'd harden. (Serverless workspaces skip most of this.)
4. **Encryption / Tags** — defaults are fine for the demo.
5. **Review + create** → **Create**. Provisioning takes ~5 minutes.
6. When done → **Go to resource** → **Launch Workspace**. This SSO's you into the workspace at `https://adb-<id>.<n>.azuredatabricks.net`.

**Checkpoint:** the Databricks workspace UI opens and you land on the home page.

---

## PART 2 — Confirm (or enable) Unity Catalog + admin roles

Since **9 Nov 2023**, Databricks auto-enables new workspaces for Unity Catalog with an
auto-provisioned metastore, so a brand-new workspace is usually already on UC. Verify:

1. In the workspace, click **Catalog** (left nav). If you see a **catalog explorer** with
   a `system` catalog and can create catalogs, UC is enabled — skip to 2.4.

### If UC is NOT yet enabled (older/existing workspace)
2.1 Go to the **account console** (`accounts.azuredatabricks.net`) as an **account admin**.
2.2 **Catalog** → if no metastore exists in your region, **Create metastore**
    (name, region, and — optionally — an ADLS Gen2 container for managed storage).
    You can create **one metastore per region**.
2.3 Open the metastore → **Workspaces** tab → **Assign to workspace** → select
    `dbx-pii-demo` → **Assign** → **Enable**. (This is irreversible.)

### Confirm your admin roles (needed for system tables and tagging)
2.4 Account console → **User management** → ensure your user is an **Account admin**.
2.5 Account console → **Catalog** → your metastore → **Admins** → ensure your user is the
    **Metastore admin**. (Accounts created after Nov 2023 may have **no** metastore admin
    by default — set one here.)
2.6 The metastore must be on **Privilege Model Version 1.0** to access system tables. If
    the account console shows an "Upgrade to privilege inheritance" prompt for this
    metastore, complete it.

**Checkpoint:** you are both **account admin** and **metastore admin**, and the workspace
shows a `system` catalog under Catalog.

---

## PART 3 — Create a SQL Warehouse

You'll run all the SQL on this, and — importantly — **lineage `statement_id` is only
captured for SQL-warehouse (or serverless) runs**, so the demo must run here.

1. Left nav → **SQL Warehouses** → **Create SQL warehouse**.
2. Name `pii-demo-wh`; **Serverless** (fastest to start) or **Pro**; size **2X-Small**
   is plenty for the demo. **Create**.
3. Wait for **Running**, then open a **SQL Editor** (New → Query) and confirm:
   ```sql
   SELECT 1;
   ```

**Checkpoint:** `SELECT 1` returns 1.

---

## PART 4 — Enable the system tables (query + access)

System tables live in the `system` catalog but several schemas are **off by default**.
You need `system.query` (query history) and `system.access` (audit + table/column lineage).

### 4.1 See what's already enabled
```sql
SELECT schema_name FROM system.information_schema.schemata WHERE catalog_name = 'system';
```

### 4.2 Get your metastore id
```sql
SELECT current_metastore();   -- e.g. azure:centralindia:11111111-2222-...
```
(or CLI: `databricks metastores current`.)

### 4.3 Enable the two schemas via the Unity Catalog API
From a terminal with the Databricks CLI authenticated (`databricks auth login`):
```bash
MET=<paste the id from 4.2>

# list current state
databricks api get /api/2.1/unity-catalog/metastores/$MET/systemschemas

# enable the two we need
databricks api put /api/2.1/unity-catalog/metastores/$MET/systemschemas/query
databricks api put /api/2.1/unity-catalog/metastores/$MET/systemschemas/access
```
> No CLI? Do it from a notebook with a PAT:
> ```python
> import requests, os
> host = "https://adb-<id>.<n>.azuredatabricks.net"
> tok  = dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiToken().get()
> met  = spark.sql("SELECT current_metastore()").first()[0]
> for s in ("query", "access"):
>     r = requests.put(f"{host}/api/2.1/unity-catalog/metastores/{met}/systemschemas/{s}",
>                      headers={"Authorization": f"Bearer {tok}"})
>     print(s, r.status_code, r.text)
> ```

### 4.4 Grant read access (if the detector identity isn't a metastore admin)
Account/metastore admins already have access. To let a specific detector SP/group read:
```sql
GRANT USE CATALOG ON CATALOG system TO `data-security-team`;
GRANT USE SCHEMA  ON SCHEMA  system.query  TO `data-security-team`;
GRANT USE SCHEMA  ON SCHEMA  system.access TO `data-security-team`;
GRANT SELECT      ON SCHEMA  system.query  TO `data-security-team`;
GRANT SELECT      ON SCHEMA  system.access TO `data-security-team`;
```

### 4.5 Make sure you can read raw SQL text (critical for detection)
`system.query.history.statement_text` is `<REDACTED>` for everyone except account admins
and members of the account group **`databricks_pii_access`**.
```sql
SELECT statement_text FROM system.query.history LIMIT 1;   -- must NOT be <REDACTED>
```
If redacted: account console → **Groups** → create/open `databricks_pii_access` → add the
detector identity.

**Checkpoint:** 4.1 now lists `query` and `access`; 4.5 returns real SQL text.
> Records take up to ~1 hour to appear after enablement — that's fine, you don't need
> them until after the attacks run.

---

## PART 5 — Create the demo groups, secret, and analyst identity

### 5.1 Groups (account console → User management → Groups)
- `pii-temp-access` — the time-boxed insider group; add a **test user or service
  principal** to play the attacker.
- `data-security-team` — reads detection output.
- `databricks_pii_access` — from 4.5 (unredacted query text).
- *(optional, used by the masking demo later)* `pii-full-access` — those allowed to see raw PII.

### 5.2 The hashing secret (makes the "good" benign control genuinely strong)
```bash
databricks secrets create-scope pii_demo
databricks secrets put-secret pii_demo hash_salt      # paste any long random string
```

**Checkpoint:** the three groups exist; `SELECT secret('pii_demo','hash_salt')` runs
(value shows as `[REDACTED]`, which is expected).

---

## PART 6 — Create and tag the demo data

1. Open a **SQL Editor** on `pii-demo-wh`, as your **admin** identity.
2. Open **`sql/01_setup_demo_data.sql`** from this kit, paste it in, and **Run all**.
   It creates catalog `pii_demo`, schemas `gold`/`sandbox`/`security`, the
   `gold.customer_master` table (10 rows of realistic phone / Aadhaar / PAN / email /
   DOB), **tags the 7 sensitive columns**, creates the detection output tables, and
   grants `pii-temp-access` SELECT on gold + write only into `sandbox`.
3. Confirm the data:
   ```sql
   SELECT * FROM pii_demo.gold.customer_master LIMIT 5;
   ```
4. Confirm the **tags landed** (this is the backbone of the whole solution):
   ```sql
   SELECT column_name, tag_name, tag_value
   FROM   system.information_schema.column_tags
   WHERE  catalog_name = 'pii_demo' AND table_name = 'customer_master'
   ORDER BY column_name, tag_name;
   ```

**Checkpoint (must pass before moving on):** step 4 returns **7 tagged columns** —
`full_name`(name), `phone_number`(phone), `email`(email), `aadhaar_number`(national_id),
`pan_number`(national_id), `dob`(dob), `city`(quasi). If it returns nothing, the tags
didn't apply and **nothing downstream will work** — re-run the `ALTER TABLE ... SET TAGS`
statements and check you're the metastore/owner of the table.

---

## What's next

You now have data + tags. Continue with the main flow:
- **Run the attacks** → `sql/02_attacker_playbook.sql` as the `pii-temp-access` user, then
  wait ~30–60 min for `system.access.column_lineage` to populate.
- **Detect** → `sql/03_detection.sql` (Path A) — see Phase 5 of `docs/03-foundry-setup.md`
  for the Foundry serving-endpoint wiring.
- **Prevent** → `sql/04_preventive_controls.sql`.

Full presenter script with checkpoints and talk tracks: `08_end_to_end_demo_runbook.md`.

---

## Verification checklist

- [ ] Workspace is **Premium** and opens.
- [ ] `system` catalog visible; you are **account admin + metastore admin**.
- [ ] Metastore on **Privilege Model v1.0**.
- [ ] SQL Warehouse **Running**; `SELECT 1` works.
- [ ] `system.query` and `system.access` listed in `information_schema.schemata`.
- [ ] `statement_text` is not `<REDACTED>` for the detector identity.
- [ ] Groups `pii-temp-access`, `data-security-team`, `databricks_pii_access` exist.
- [ ] Secret `pii_demo/hash_salt` set.
- [ ] `pii_demo.gold.customer_master` has 10 rows; **7 tagged columns** confirmed.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| **"Manage account" missing** from the top-right user menu | You are not an Azure Databricks **account admin** | If an account admin exists, have them enable Account admin on your user (Account console → User management). If none exists and you hold Entra **Global Administrator**: Azure portal → Microsoft Entra ID → Properties → set **"Access management for Azure resources" = Yes**, sign in to accounts.azuredatabricks.net, assign yourself account admin, then set the toggle back to No. In a **managed/lab tenant** where you can't self-elevate, ask the tenant owner to grant account admin, or use a subscription in a tenant you control. |
| Account console redirects to the workspace picker | Same as above — not an account admin | Same fix as above. |
| No `system` catalog / can't create catalogs | Workspace not on Unity Catalog | Part 2 — assign a metastore in the account console. |
| Can't enable system schemas | Not a metastore admin, or metastore below Privilege Model v1.0 | Set yourself as metastore admin (2.5); complete the privilege-model upgrade (2.6). |
| `statement_text` shows `<REDACTED>` | Identity not an account admin / not in `databricks_pii_access` | Add to the `databricks_pii_access` account group (4.5). |
| Tag query returns nothing | `ALTER ... SET TAGS` didn't run, or you don't own the table | Re-run the tagging block in `01` as the table owner/metastore admin. |
| `column_lineage` empty after attacks | Ran on all-purpose cluster, or <1h elapsed | Re-run attacks on the **SQL warehouse**; wait up to an hour. |
| "Premium features not available" | Workspace is Standard tier | Recreate the workspace on **Premium** (tier can't be changed in place). |

---

## Sources
Microsoft Learn (Azure Databricks), retrieved 8 Sep 2026:
- *Enable a workspace for Unity Catalog* — new workspaces auto-enabled since 9 Nov 2023;
  assigning a metastore; one metastore per region.
  https://learn.microsoft.com/en-us/azure/databricks/data-governance/unity-catalog/enable-workspaces
- *System tables reference* — system tables governed by Unity Catalog; account+metastore
  admins have access by default; grant USE CATALOG/USE SCHEMA/SELECT on `system`;
  metastore must be on Privilege Model v1.0; accounts after Nov 2023 may lack a metastore
  admin by default.
  https://learn.microsoft.com/en-us/azure/databricks/admin/system-tables/
- Query-history `<REDACTED>` behaviour and the `databricks_pii_access` group: Databricks
  *Query history system table reference* (grounded earlier in this kit).

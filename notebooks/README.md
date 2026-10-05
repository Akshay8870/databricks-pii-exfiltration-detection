# Notebooks

Import into Databricks via **Workspace → Import → File**, as **notebooks** (not files).

## The scorers

| Notebook | Scores | Requires |
|---|---|---|
| `scorer_01_sql.py` | `v_pii_candidates` | `sql/03_detection.sql` |
| `scorer_02_multihop.py` | `v_pii_candidates_mh` | + `sql/05_multihop_lineage.sql` |
| **`scorer_03_spark.py`** | `v_pii_candidates_all` | + `sql/06_notebook_spark_detection.sql` |

**Use `scorer_03_spark.py`** unless you are deliberately demonstrating a narrower one. Its view is
a superset: direct SQL writes come back alongside notebook and path events.

## Configure before running

Each scorer has a config block at the top shipped with **placeholders**. Fill in:

```python
FOUNDRY_HOST = "https://<your-foundry-resource>.cognitiveservices.azure.com"
DEPLOYMENT   = "<your-deployment-name>"
API_VERSION  = "<from the endpoint panel>"
TENANT_ID    = "<directory-tenant-id>"        # Entra ID auth path
CLIENT_ID    = "<app-registration-client-id>"
```

Secrets come from a Databricks secret scope — **never hard-code them**:

```python
CLIENT_SECRET = dbutils.secrets.get("foundry", "sp_secret")
```

### Useful toggles

| Setting | Effect |
|---|---|
| `CANDIDATE_VIEW` | Switch detection layer without editing SQL — useful for showing the gap live |
| `ONLY_TODAY = True` | Score only today's events. **Keep this on for demos** — the views carry no time window, so old attack tables accumulate |
| `ALERT_THRESHOLD` | Risk score at which the console prints `<== ALERT` |
| `REASONING_EFFORT` | `low` / `medium` / `high` |

## Behaviour

- **Retries** `429/5xx` three times with backoff; **fails fast** on `400/401/403` (those are
  configuration errors, not transient)
- **Re-scoring is safe.** Verdicts append; display queries keep only the newest per statement. Re-run
  freely after a prompt change
- A **run summary** names anything still unscored after retries

## `attacker_pyspark.py`

Six PySpark attacks plus a Scala cell, writing Parquet/CSV/JSON to storage and tables via the
DataFrame API. **No SQL is submitted anywhere in it** — that is the point.

Set `BASE` to a UC Volume (no setup needed) or a real ADLS path (more convincing on stage):

```python
BASE = "/Volumes/<catalog>/sandbox/exfil_vol"
# or
BASE = "abfss://<container>@<account>.dfs.core.windows.net/exfil_demo"
```

> ⚠️ **Attach to a UC-governed cluster** — access mode Shared or Single User. On a non-UC cluster
> the writes succeed and **no lineage is produced at all**.

A cleanup cell is printed at the end for repeat runs.

# Spark notebook coverage: Python, Scala, R and ADLS file writes

**File:** `sql/06_notebook_spark_detection.sql` · **Scorer:** `notebooks/scorer_03_spark.py`

## What works out of the box

Unity Catalog captures lineage for the **Spark DataFrame API in every language** — SQL, Python,
Scala, R. PySpark compiles to the same resolved plan SQL does, so the column mapping is recorded
identically.

And `column_lineage` carries **`target_path`** with **`target_type = 'PATH'`**, so:

```python
df.write.parquet("abfss://container@account.dfs.core.windows.net/export")
```

is recorded **at column level**, and the path appears as a node in the lineage graph.

## What breaks, and why it needed separate work

From the Databricks system-table reference, on `statement_id`:

> *"This value is only set when the query is run from a SQL warehouse."*

Base Stage 1 joins `column_lineage` to `query.history` on `statement_id`. For a notebook that is
**NULL**, the join finds nothing, and the event silently never appears.

`sql/06_notebook_spark_detection.sql` re-keys detection on **`event_id`** plus the entity fields
(`entity_type`, `entity_id`, `entity_run_id`, `notebook_id`, `job_id`), and treats the target as
`coalesce(target_table_full_name, target_path)`.

## The honest limitation

**There is no source code for a notebook event.** Databricks records no statement text for the
DataFrame API, so every regex rule (`substr`, `base64`, `concat`…) is unavailable.

Detection becomes **structural** — it reasons about the column-to-column map itself. That is
arguably stronger: the map is ground truth regardless of the language or the cleverness of the
code.

The regex rules are gated on `statement_text IS NOT NULL`, so a notebook never receives a false
`no_hashing` signal merely because its code is invisible.

### Text-free rule signals

| Signal | Fires when |
|---|---|
| `column_fanout` | One PII column expanded into several target columns |
| `column_rename` | Target columns renamed away from their source column |
| `path_target` | Written to cloud storage, not a governed table |
| `bulk_path_export` | 3+ distinct PII columns to a single path |
| `notebook_source` | Produced by a notebook/job — no SQL text exists |
| `view_target` | Persisted as a view |

### Recovering the code (optional)

**Verbose audit logging** (Settings → Advanced → Verbose Audit Logs) exposes notebook command text
in `system.access.audit`. It is **off by default** and is a log-volume decision — treat it as an
option, not a dependency. Do not promise it without the platform team's agreement.

## The governance point

A `PATH` target sits **outside Unity Catalog's control plane**. Table grants, row filters and
column masks **do not apply** to those files. Anything holding storage credentials can read them,
including tools entirely outside Databricks.

CSV and JSON are plain text. Parquet is only marginally less readable.

This reframes the conversation usefully: it is not only *"yes, notebooks are covered"* — it is
*"the notebook case is a more serious exposure than the SQL one."*

## Prevention differs here

| Control | What it protects |
|---|---|
| **Column masking** on the source table | The **read** — in any language. A masked read means the file contains masked digits. |
| **External locations / storage credentials** | The **write** — no credential for a container means `df.write` to it fails outright. |
| Detection | The residual: permitted volumes and external locations |

## Views created

```
v_pii_write_events_all   lineage keyed on event_id, table OR path targets
v_pii_candidates_all     + optional query text + text-free and text rules
v_pii_llm_input_all      evidence envelope with column_map as primary evidence
```

`v_pii_candidates_all` covers **everything** — SQL statements, notebooks, tables and paths. It is
the view to use in production.

## Querying path lineage

> ⚠️ **Two traps, both returning a misleading zero.**
>
> **1.** Path targets have a NULL `target_table_full_name`. Filter on `target_path`.
>
> **2.** **Never anchor a path `LIKE` at the start.** Databricks records a Volume path as
> `dbfs:/Volumes/...`, not `/Volumes/...`, and an ADLS target may be the resolved storage URL
> rather than the string passed to `.write()`. Always lead with `%`.

```sql
-- correct: prefix-agnostic
SELECT target_path, target_type, entity_type, count(*) AS col_edges
FROM   system.access.column_lineage
WHERE  event_date = current_date() AND target_path IS NOT NULL
GROUP BY target_path, target_type, entity_type
ORDER BY target_path;
```

This only ever affects manual queries — `v_pii_candidates_all` never filters on path text.

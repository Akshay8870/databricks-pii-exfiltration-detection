# Architecture

## The insight

To execute any statement — SQL or DataFrame — Databricks must resolve **which source columns feed
which output columns**. It cannot build an execution plan otherwise. Unity Catalog harvests that
resolved plan automatically and writes it to system tables.

This is why the approach works where text scanning fails:

| The insider does | Text scanning | Lineage |
|---|---|---|
| Renames the column | misses it | resolves to the source column |
| Splits into 3 columns | needs a pattern per variant | records 1 source → 3 targets |
| `base64` / `hex` / `concat` | needs a pattern per function | source column still recorded as input |
| Writes a view not a table | often missed | captured, `target_type = 'VIEW'` |
| Uses PySpark instead of SQL | **completely blind** | identical capture, no SQL needed |
| Writes files to ADLS | **completely blind** | captured, `target_type = 'PATH'` |

Nobody instruments anything. No agent, no config, no change to any existing workload.

## The two stages

```
                  ┌─────────────────────────────────────────────┐
                  │  system.access.column_lineage               │
   Unity Catalog  │  system.access.table_lineage                │
   captures ─────►│  system.query.history                       │
   automatically  │  system.information_schema.column_tags      │
                  └──────────────────┬──────────────────────────┘
                                     │
          ┌──────────────────────────▼──────────────────────────┐
          │  STAGE 1 — DETERMINISTIC (pure SQL, no AI)          │
          │                                                     │
          │  v_pii_columns        which columns are PII (tags)  │
          │         ↓                                           │
          │  v_pii_write_events   lineage ∩ tagged columns      │
          │         ↓                                           │
          │  v_pii_candidates     + SQL text + ~12 rules        │
          │                                                     │
          │  millions of statements  →  tens of candidates      │
          └──────────────────────────┬──────────────────────────┘
                                     │  metadata envelope only
                                     │  (NO PII VALUES)
          ┌──────────────────────────▼──────────────────────────┐
          │  STAGE 2 — ADJUDICATION (Azure AI Foundry)          │
          │                                                     │
          │  "Is the original value actually RECOVERABLE?"      │
          │                                                     │
          │  → verdict, risk_score, reversibility_class,        │
          │    evidence_expression, rationale, action           │
          └──────────────────────────┬──────────────────────────┘
                                     │
                      security.pii_query_verdicts  →  alerts
```

**Stage 1 is deterministic**, which matters for two reasons: it cannot hallucinate, and it sets a
risk **floor** the model may raise but never lower.

**Stage 2 answers the question rules cannot.** `base64(phone)` and `sha2(concat(phone, secret))`
look structurally identical — both are "a function applied to a PII column". Only reasoning about
*reversibility* separates them.

## Deployment options

### Option A — inline, everything inside Databricks (recommended)

Databricks notebook calls Foundry over HTTPS, writes verdicts to a Delta table. No Event Hub, no
Function App, no egress beyond the model call itself. This is what the notebooks in `notebooks/`
implement, and what the runbooks demonstrate.

### Option B — Event Hub + Function App

For organisations where the SOC owns detection and wants events in Sentinel. A Databricks job
publishes candidates to Event Hub; an Azure Function scores them and forwards verdicts. Code in
`deployment/`.

Start with Option A. Add Option B only if the customer needs the pipeline.

## The three detection layers

Each builds on the previous. Run the SQL files in order; each is additive and changes nothing
before it.

| Layer | File | Adds |
|---|---|---|
| Base | `sql/03_detection.sql` | SQL warehouse statements, tagged sources |
| Multi-hop | `sql/05_multihop_lineage.sql` | Laundering through untagged derived tables |
| Notebook / path | `sql/06_notebook_spark_detection.sql` | PySpark/Scala events, ADLS file targets |

The third produces `v_pii_candidates_all`, which covers everything. That is the view to use in
production.

# DEMO DAY RUNBOOK — one page

The live run-of-show. Everything is already deployed (workspace, tags,
`pii-dlp-judge`, the service principal + roles, the detection views,
`sql/05_multihop_lineage.sql`, `notebooks/scorer_02_multihop.py`).
The trick: **fire the attack first, present slides during the ~5–10 min lineage
lag, then show the results.** Total live time ~20–25 min.

---

## T‑15 min — Pre-flight (before anyone joins)

1. **Start** the SQL Warehouse `pii-demo-wh` (serverless cold-start ~1 min) and the notebook cluster.
2. **Smoke-test the model** — run the smoke-test cell; confirm `STATUS 200 + OK`.
3. **Confirm data + views:**
   ```sql
   SELECT count(*) FROM pii_demo.gold.customer_master;           -- 10
   SELECT count(*) FROM pii_demo.security.v_pii_candidates;      -- returns rows
   SELECT count(*) FROM pii_demo.security.v_pii_candidates_mh;   -- returns rows
   ```
   **If the third query errors**, `sql/05_multihop_lineage.sql` has not been run. Run it once
   (SQL editor, Run All, takes seconds). The scorer notebook reads the `_mh` view, so it
   is now a hard prerequisite even for this single-hop demo. It is purely additive --
   it creates three views and changes nothing existing.
4. Open tabs ready: the **deck**, the **SQL editor**, the **`notebooks/scorer_02_multihop.py`** notebook.

## T‑0 — Fire the attack (3 categories, as you start)

Run these as the "insider", note the time, then start presenting. Three
different categories so the audience sees the breadth:
```sql
-- CATEGORY 1 · SUBSTITUTION CIPHER + REVERSAL (string)
CREATE OR REPLACE TABLE pii_demo.sandbox.reward_points AS
SELECT customer_id,
       translate(phone_number,'0123456789','QWERTYUIOP') AS pts,
       reverse(pan_number) AS tier_ref
FROM pii_demo.gold.customer_master;

-- CATEGORY 2 · ARITHMETIC OFFSET (math — subtract 7 / divide 3 to recover)
CREATE OR REPLACE TABLE pii_demo.sandbox.score_shift AS
SELECT customer_id,
       cast(phone_number AS BIGINT) + 7 AS score_a,
       cast(phone_number AS BIGINT) * 3 AS score_b
FROM pii_demo.gold.customer_master;

-- CATEGORY 3 · JSON / STRUCT PACKING (nesting)
CREATE OR REPLACE TABLE pii_demo.sandbox.attr_blob AS
SELECT customer_id,
       to_json(named_struct('a',phone_number,'b',email,'c',aadhaar_number)) AS attrs
FROM pii_demo.gold.customer_master;
```
(More options in `sql/07_live_detection_test.sql` and `sql/08_more_sample_queries.sql`.)

## During slides — the narrative (~10–12 min, fills the lineage lag)

Walk the deck in order:
1. Problem → the insider disguises PII (the customer's scenario).
2. Approach → lineage detects, the model judges.
3. Architecture + **Option A inline** → mostly inside Databricks, one external hop.
4. Attack catalog → 18 disguises, all caught.
5. Detection internals → the three chained views.
6. How the model reasons + **Verdict schema** → recoverability + alertable fields.

## Show the lineage in the Unity Catalog UI (do this BEFORE the SQL)

The UI makes the SQL land harder. Two minutes, three clicks.

**A. The attack table's upstream**
1. Left nav -> **Catalog** -> `pii_demo` -> `sandbox` -> **`reward_points`**
2. Click the **Lineage** tab -> **Upstream**
3. It shows `pii_demo.gold.customer_master` -- say out loud: *"nobody told Databricks these two were related. It worked that out from the query plan."*

**B. The column-level mapping (the money shot)**
4. Click **See lineage graph** (icon top-right of the Lineage tab)
5. Click the edge between `customer_master` and `reward_points`, or expand the node to column level
6. You now see the tagged PII column mapping straight onto the renamed target columns.
   Line to use: *"they renamed every column and reshaped the value. The graph still points at `phone_number`."*

**C. The blast-radius reversal (optional, strong for the admin persona)**
7. Open `pii_demo.gold.customer_master` -> **Lineage** -> **Downstream**
8. Every table derived from the PII master fans out in one view -- that is the admin's daily question answered.

Also on that Lineage tab: **Notebooks / Jobs / Queries** shows *who* produced the table, so you can pivot from "this table is suspicious" to "this person ran it."

### How the capture works (the 30-second explanation)

Nobody instruments anything. When a statement runs on UC-governed compute, Databricks resolves the query plan -- it already knows which source columns feed which output columns, because it needs that to execute. Unity Catalog harvests that resolved plan automatically and writes it to the system tables.

Because it is captured from the **plan, not the SQL text**:
- rename a column -> still resolves to the source column
- `substr` / `split` / `concat` / `base64` / `to_json` -> source column still recorded as an input
- split one column into three -> recorded as **1 source column -> 3 target columns** (this *is* the `column_fanout` rule signal)
- write a **view** instead of a table -> still captured, with `target_type = 'VIEW'`

| System table | What it contributes |
|---|---|
| `system.access.column_lineage` | ground truth: source/target table + **column**, `target_type`, `created_by`, `event_time` |
| `system.query.history` | context: `statement_text` (the actual SQL), `executed_by`, row counts, `start_time` |

Joined on `statement_id`. Lineage tells you **what** moved; query history tells you **how** and **who**. Neither alone is enough -- lineage carries no SQL text, query history carries no reliable column mapping.

That join is Stage 1, and it is fully deterministic -- no LLM, so no false negative from a clever disguise:
```sql
FROM system.access.column_lineage cl
JOIN security.v_pii_columns p
  ON  p.table_full_name = cl.source_table_full_name
  AND p.column_name     = cl.source_column_name
WHERE cl.target_table_full_name IS NOT NULL
```
In English: *"every statement where a column I tagged as PII was used to write something new."* The model only arrives at Stage 2, to judge whether what was written is **recoverable**.

**Say the limits before they ask:** UC-governed objects only; lineage retained ~365 days, query history ~90 days; capture lag up to ~1 hour per the docs (in this environment it has been landing in minutes).

## Check lineage has populated (poll until non-zero)

Run this every couple of minutes; move on once it returns 3 (or non-zero):
```sql
SELECT count(*) FROM system.access.column_lineage
WHERE target_table_full_name IN
      ('pii_demo.sandbox.reward_points',
       'pii_demo.sandbox.score_shift',
       'pii_demo.sandbox.attr_blob')
  AND event_date = current_date();
```

## Show it working — live detection

1. **Prove capture** (lineage caught all three, whatever the disguise):
   ```sql
   SELECT target_table, pii_col_count, target_col_count, rule_score, rule_reasons
   FROM   pii_demo.security.v_pii_candidates
   WHERE  target_table IN ('pii_demo.sandbox.reward_points',
                           'pii_demo.sandbox.score_shift',
                           'pii_demo.sandbox.attr_blob');
   ```
   *Talk-track:* "Cipher, arithmetic, JSON packing — three different tricks, all traced back to the PII column."
2. **Run `notebooks/scorer_02_multihop.py`** (whole notebook, ~30–40s) → writes verdicts.
   It scores `v_pii_candidates_mh`, which covers direct writes (`hop0`) **and** writes
   laundered through derived tables. Retries transient Foundry errors automatically.
3. **Show verdicts with the query:**
   ```sql
   SELECT c.target_table, v.verdict, v.risk_score, v.reversibility_class,
          v.rationale, v.recommended_action, c.statement_text AS query
   FROM (SELECT * FROM pii_demo.security.pii_query_verdicts
         QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC)=1) v
   JOIN pii_demo.security.v_pii_candidates c USING (statement_id)
   WHERE c.target_table IN ('pii_demo.sandbox.reward_points',
                            'pii_demo.sandbox.score_shift',
                            'pii_demo.sandbox.attr_blob')
   ORDER BY v.risk_score DESC;
   ```
   All three → **LIKELY_EXFILTRATION**.
   *Money moment (from the full set):* `contact_hash` (unsalted → LIKELY, 83) vs
   `customer_pseudo` (secret-salted → BENIGN, 12) — same `sha2()`, opposite verdicts.

## The closer — prevention

Run `sql/04_preventive_controls.sql`, then as the insider re-run the split attack and
`SELECT * FROM pii_demo.sandbox.region_code_lookup` → shows `XXX` / last-4 only.
*Close with:* "Detection tells you it happened; masking makes it not matter —
do both, masking first."

---

## What's extracted vs. what's passed to the model (privacy)

**Extracted from Unity Catalog (metadata only):** `column_tags` (which columns are
PII + type) · `access.column_lineage` (which PII column fed which new column) ·
`query.history` (the SQL text, actor, row counts).

**Passed to the model (per query) — 13 metadata fields, no values:** `sql · actor ·
source_tables · pii_source_columns · pii_types · target_table · target_type ·
target_columns · target_schema_is_sandbox · rows_read · rows_written · filter_present ·
deterministic_signals`.

**No PII values ever leave** — no phone, Aadhaar, PAN or email; the model judges the
query's *shape*, never the data. *Caveat:* `statement_text` can contain a literal
(`WHERE phone='9764445335'`) — for production, redact quoted literals > 6 chars, or use
an in-tenant Foundry deployment with retention off behind a Private Endpoint.

## Variants with different sample SQL

Running more than one pass? Use `DEMO_DAY_RUNBOOK_1.md` (hex encode + split) and
`DEMO_DAY_RUNBOOK_2.md` (email rearrange + array packing) — each fires a different
attack table so nothing overlaps.

---

## Safety nets

- **Lineage still lagging at the live section?** Show the **prior run's verdicts**
  already in `pii_query_verdicts` — same story. Poll with:
  ```sql
  SELECT count(*) FROM system.access.column_lineage WHERE event_date = current_date();
  ```
- **Model call fails?** The notebook now retries 429/5xx up to 3 times on its own; `06b` fetches a fresh token
  each run, so just re-run it (RBAC can take 5–15 min after any role change).
- **Tag query returns nothing?** Re-run the tagging block in `01` — everything
  downstream depends on it.

## Timing at a glance

| Segment | Min |
|---|---|
| Pre-flight | 15 (before) |
| Fire attack + slides | 10–12 |
| Live detection | 5–6 |
| Prevention closer | 4 |
| **Live total** | **~20–25** |

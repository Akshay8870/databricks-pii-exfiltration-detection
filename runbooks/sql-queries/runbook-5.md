# DEMO DAY RUNBOOK — variant 5 (weak crypto & multi-step)

Live run-of-show. Everything is already deployed. Fire the attack first, present
slides during the ~5–10 min lineage lag, then show results. Live time ~20–25 min.

> **This variant uses different sample SQL** (unsalted hash · regex spacing · ASCII
> codepoints). The unsalted hash is the star — it *looks* safe but scores
> **SUSPICIOUS**, which is the best proof the model reasons rather than
> keyword-matches.

---

## T‑15 min — Pre-flight

1. Start SQL Warehouse `pii-demo-wh` and the notebook cluster.
2. Smoke-test the model — run the smoke-test cell → `STATUS 200 + OK`.
3. Confirm data + views:
   ```sql
   SELECT count(*) FROM pii_demo.gold.customer_master;           -- 10
   SELECT count(*) FROM pii_demo.security.v_pii_candidates;      -- returns rows
   SELECT count(*) FROM pii_demo.security.v_pii_candidates_mh;   -- returns rows
   ```
   **If the third query errors**, `sql/05_multihop_lineage.sql` has not been run. Run it once
   (SQL editor, Run All, takes seconds). The scorer notebook reads the `_mh` view, so it
   is now a hard prerequisite even for this single-hop demo. It is purely additive --
   it creates three views and changes nothing existing.
4. Open tabs: deck, SQL editor, the **`notebooks/scorer_02_multihop.py`** notebook.

## T‑0 — Fire the attack (variant 5 · 3 categories)

Run these as the "insider", note the time, then start presenting:
```sql
-- CATEGORY 1 · WEAK HASH (unsalted sha2 of a 10-digit phone — looks safe, isn't)
CREATE OR REPLACE TABLE pii_demo.sandbox.phone_digest AS
SELECT customer_id, sha2(phone_number,256) AS phone_hash, city
FROM pii_demo.gold.customer_master;

-- CATEGORY 2 · REGEX DELIMITER INSERTION (space the Aadhaar; strip dashes to restore)
CREATE OR REPLACE TABLE pii_demo.sandbox.spaced_aadhaar AS
SELECT customer_id, regexp_replace(aadhaar_number,'(....)','$1-') AS spaced_id
FROM pii_demo.gold.customer_master;

-- CATEGORY 3 · ASCII CODEPOINTS (each digit as its char code, dot-joined)
CREATE OR REPLACE TABLE pii_demo.sandbox.cp_stream AS
SELECT customer_id,
       concat_ws('.', transform(split(phone_number,''), x -> cast(ascii(x) AS STRING))) AS cp_string
FROM pii_demo.gold.customer_master;
```

## During slides (~10–12 min, fills the lineage lag)

Problem → Approach → Architecture + Option A inline → Attack catalog →
Detection internals → Data flow & privacy → How the model reasons → Verdict schema.

## Show the lineage in the Unity Catalog UI (do this BEFORE the SQL)

The UI makes the SQL land harder. Two minutes, three clicks.

**A. The attack table's upstream**
1. Left nav -> **Catalog** -> `pii_demo` -> `sandbox` -> **`phone_digest`**
2. Click the **Lineage** tab -> **Upstream**
3. It shows `pii_demo.gold.customer_master` -- say out loud: *"nobody told Databricks these two were related. It worked that out from the query plan."*

**B. The column-level mapping (the money shot)**
4. Click **See lineage graph** (icon top-right of the Lineage tab)
5. Click the edge between `customer_master` and `phone_digest`, or expand the node to column level
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
      ('pii_demo.sandbox.phone_digest',
       'pii_demo.sandbox.spaced_aadhaar',
       'pii_demo.sandbox.cp_stream')
  AND event_date = current_date();
```

## Show it working — live detection

1. Prove capture (weak hash, spaced ID, codepoints — all caught):
   ```sql
   SELECT target_table, pii_col_count, target_col_count, rule_score, rule_reasons
   FROM   pii_demo.security.v_pii_candidates
   WHERE  target_table IN ('pii_demo.sandbox.phone_digest',
                           'pii_demo.sandbox.spaced_aadhaar',
                           'pii_demo.sandbox.cp_stream');
   ```
   *Talk-track:* "The hash looks like de-identification — but a 10-digit phone has only ~10^10 values, so an unsalted hash is brute-forceable. Watch the model catch that."
2. Run `notebooks/scorer_02_multihop.py` (~30–40s) → writes verdicts.
   Scores `v_pii_candidates_mh` — direct writes (`hop0`) **and** derived-table laundering.
   Retries transient Foundry errors automatically.
3. Show verdicts with the query:
   ```sql
   SELECT c.target_table, v.verdict, v.risk_score, v.reversibility_class,
          v.rationale, v.recommended_action, c.statement_text AS query
   FROM (SELECT * FROM pii_demo.security.pii_query_verdicts
         QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC)=1) v
   JOIN pii_demo.security.v_pii_candidates c USING (statement_id)
   WHERE c.target_table IN ('pii_demo.sandbox.phone_digest',
                            'pii_demo.sandbox.spaced_aadhaar',
                            'pii_demo.sandbox.cp_stream')
   ORDER BY v.risk_score DESC;
   ```
   Expect: `phone_digest` → **SUSPICIOUS** (`weak_oneway_low_entropy` — the star of this
   run); `spaced_aadhaar` + `cp_stream` → **LIKELY_EXFILTRATION** (`trivially_invertible`).
   *Reinforce (from the full set):* `phone_digest` (unsalted) sits opposite
   `customer_pseudo` (secret-salted → BENIGN, 12) — same `sha2()`, opposite verdicts.

## The closer — prevention

Run `sql/04_preventive_controls.sql`, re-run a split attack as the insider, and
`SELECT * FROM pii_demo.sandbox.region_code_lookup` → shows `XXX` / last-4 only.
*Close:* "Detection tells you it happened; masking makes it not matter — do both, masking first."

---

## What's extracted vs. what's passed to the model (privacy)

**Extracted from Unity Catalog (metadata only):**
- `system.information_schema.column_tags` — which columns are PII + type
- `system.access.column_lineage` — which PII column fed which new column
- `system.query.history` — the SQL text, actor, row counts

**Passed to the model (per query) — 13 metadata fields, no values:**
`sql · actor · source_tables · pii_source_columns · pii_types · target_table ·
target_type · target_columns · target_schema_is_sandbox · rows_read · rows_written ·
filter_present · deterministic_signals`

**No PII values ever leave** — no phone, Aadhaar, PAN or email. The model judges the
query's *shape*, never the data.
*Caveat:* `statement_text` can contain a literal (`WHERE phone='9764445335'`) — for
production, redact quoted literals > 6 chars, or use an in-tenant Foundry deployment
with retention/abuse-logging off behind a Private Endpoint. The demo's CREATE-AS-SELECT
queries carry no literal PII.

---

## Safety nets

- **Lineage still lagging?** Show the prior run's verdicts already in
  `pii_query_verdicts`. Poll: `SELECT count(*) FROM system.access.column_lineage WHERE event_date = current_date();`
- **Model call fails?** The notebook now retries 429/5xx up to 3 times on its own. If a
  table is still unscored, the run summary names it — just re-run the notebook, re-scoring is safe.
- **Token error / JSONDecodeError?** Check `TENANT_ID` and `CLIENT_ID` are filled in (they ship
  as placeholders) and that the `foundry` secret scope is readable.
- **Tag query empty?** Re-run the tagging block in `01`.

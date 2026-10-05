# FROM DERIVED TABLES — PII DETECT · RUNBOOK 2
## "Views, joins and reassembly": rebuilding PII that was already split apart

**The scenario you are proving.** Runbook 1 showed laundering through a staging table. This one is
nastier and more realistic: the insider never writes a table that *looks* like PII at any single
step. They split the data across tables, hide a hop behind a **view**, and then — days later —
**join the pieces back together**. No individual statement looks alarming. The chain does.

**Why this runbook exists.** Same root cause as Runbook 1: Unity Catalog does not propagate tags
to derived objects. Run `sql/05_multihop_lineage.sql` before this runbook.

**The standout moment here is Category 2 — reassembly.** It is the strongest single demo in the
whole kit, because it answers the customer's original question directly: *what happens after they
split the phone number into three columns?* Answer: they put it back together, and lineage catches
that too.

---

## T‑20 min — Pre-flight

1. `sql/01_setup_demo_data.sql`, `sql/03_detection.sql`, **and `sql/05_multihop_lineage.sql`** have all run.
2. Scorer notebook **`notebooks/scorer_02_multihop.py`** open and authenticated (200 on the token call).
   Fill in `FOUNDRY_HOST`, `DEPLOYMENT`, `TENANT_ID`, `CLIENT_ID` — they ship as placeholders.
3. Clean slate:
```sql
DROP VIEW  IF EXISTS pii_demo.sandbox.v_stg_contact;
DROP TABLE IF EXISTS pii_demo.sandbox.contact_from_view;
DROP TABLE IF EXISTS pii_demo.sandbox.split_parts_src;
DROP TABLE IF EXISTS pii_demo.sandbox.reassembled_contact;
DROP TABLE IF EXISTS pii_demo.sandbox.agg_staging;
DROP TABLE IF EXISTS pii_demo.sandbox.agg_final;
```

---

## T‑0 — Fire the attack (3 categories)

### Category 1 — Hide the hop behind a VIEW

A view holds no data, so it feels harmless and is rarely reviewed. It is still a lineage node.

**Hop 1 — a view, not a table.**
```sql
CREATE VIEW pii_demo.sandbox.v_stg_contact AS
SELECT customer_id,
       phone_number AS cref,
       email        AS eref
FROM   pii_demo.gold.customer_master;
```

**Hop 2 — materialise from the view, with padding applied.**
```sql
CREATE TABLE pii_demo.sandbox.contact_from_view AS
SELECT customer_id,
       concat('zz', cref, 'qq')          AS padded_cref,
       regexp_replace(eref,'@',' [at] ') AS masked_eref
FROM   pii_demo.sandbox.v_stg_contact;
```

### Category 2 — Split, then REASSEMBLE (the one to slow down on)

**Hop 1 — split the phone three ways. This is the customer's own example.**
```sql
CREATE TABLE pii_demo.sandbox.split_parts_src AS
SELECT customer_id,
       substr(phone_number,1,3) AS p1,
       substr(phone_number,4,3) AS p2,
       substr(phone_number,7,4) AS p3
FROM   pii_demo.gold.customer_master;
```

**Hop 2 — glue them back into a single working phone number.**
```sql
CREATE TABLE pii_demo.sandbox.reassembled_contact AS
SELECT customer_id,
       concat(p1, p2, p3) AS mobile_no
FROM   pii_demo.sandbox.split_parts_src;
```
> Read hop 2 aloud. There is no PII word in it, no tagged table, no suspicious function —
> `concat` of three innocuous columns. And the output is a live, dialable phone number.

### Category 3 — Aggregate staging, then re-expand

```sql
-- hop 1: collect the values into an array column, one row per city
CREATE TABLE pii_demo.sandbox.agg_staging AS
SELECT city,
       collect_list(phone_number) AS contact_list,
       count(*)                   AS n
FROM   pii_demo.gold.customer_master
GROUP BY city;

-- hop 2: explode it straight back out to one row per person
CREATE TABLE pii_demo.sandbox.agg_final AS
SELECT city, n, explode(contact_list) AS contact_val
FROM   pii_demo.sandbox.agg_staging;
```

---

## During slides — the narrative (~10–12 min)

- "Every statement here would pass a code review on its own. That is the point."
- On the view: "a view stores nothing, so it feels safe to create and safe to ignore. Lineage still
  records it, and reports `target_type = VIEW`."
- On reassembly: **"this is the exact question your team asked me. They split the phone into three
  columns — so what? So this. Two weeks later they concatenate it back, in a statement that
  mentions no PII column and no PII table."**
- "Aggregate-then-explode is the same trick wearing an analytics costume. `GROUP BY` looks like
  reporting. `explode` undoes it exactly."
- "None of this is caught by reading SQL text. All of it is caught by walking lineage."

---

## Show the lineage chain in the Unity Catalog UI

1. **Catalog** → `pii_demo` → `sandbox` → **`reassembled_contact`** → **Lineage** → **Upstream**
   → `split_parts_src` → expand again → `gold.customer_master`.
2. Open the **column-level** graph on that second edge: `p1`, `p2`, `p3` all trace back to the single
   `phone_number` column — then forward into one `mobile_no`. **Three-to-one convergence.**
   Say: *"fan-out on the way in, fan-in on the way out. Both are recorded."*
3. For Category 1, open **`v_stg_contact`** — a view has its own Lineage tab, upstream and downstream.
4. Reverse view: `gold.customer_master` → **Downstream** shows all six objects in one picture.

---

## Check lineage has populated (poll until non-zero)

Expect **6**:
```sql
SELECT count(DISTINCT target_table_full_name) FROM system.access.column_lineage
WHERE target_table_full_name IN
      ('pii_demo.sandbox.v_stg_contact',
       'pii_demo.sandbox.contact_from_view',
       'pii_demo.sandbox.split_parts_src',
       'pii_demo.sandbox.reassembled_contact',
       'pii_demo.sandbox.agg_staging',
       'pii_demo.sandbox.agg_final')
  AND event_date = current_date();
```

---

## Show it working — live detection

### 1. The gap first

```sql
SELECT target_table, rule_score
FROM   pii_demo.security.v_pii_candidates
WHERE  target_table LIKE 'pii_demo.sandbox.%'
ORDER BY target_table;
```
`reassembled_contact`, `contact_from_view` and `agg_final` are **missing** — the tag stopped one
table back.

### 2. The closure discovers them

```sql
SELECT table_full_name, column_name, pii_type, hop, origin_column
FROM   pii_demo.security.v_pii_columns_transitive
WHERE  hop > 0
ORDER BY hop, table_full_name;
```
Note `p1`, `p2`, `p3` **and** `mobile_no` all resolve to origin column `phone_number`.

### 3. The convergence query — reassembly made visible

This is worth a slide of its own. It finds targets where **several** source columns descend from
**one** origin column — i.e. something was put back together:

```sql
SELECT cl.target_table_full_name AS target_table,
       cl.target_column_name     AS target_column,
       count(DISTINCT cl.source_column_name)    AS parts_combined,
       collect_set(p.origin_column)             AS origin,
       collect_set(cl.source_column_name)       AS combined_from
FROM   system.access.column_lineage cl
JOIN   pii_demo.security.v_pii_columns_transitive p
  ON   p.table_full_name = cl.source_table_full_name
  AND  p.column_name     = cl.source_column_name
WHERE  cl.target_table_full_name IS NOT NULL
GROUP BY 1,2
HAVING count(DISTINCT cl.source_column_name) > 1
   AND size(collect_set(p.origin_column)) = 1     -- all the parts share ONE origin column
ORDER BY parts_combined DESC;
```
`reassembled_contact.mobile_no` comes back with **`parts_combined = 3`** and origin
`phone_number`. Say: *"that single row is a reconstructed phone number, and we found it without
reading one data value."*

### 4. Multi-hop candidates

```sql
SELECT target_table, source_hop, target_type, source_tables AS read_from,
       pii_origin_columns AS traced_back_to, rule_score, rule_reasons
FROM   pii_demo.security.v_pii_candidates_mh
ORDER BY source_hop DESC, rule_score DESC;
```
Watch for `view_target` on the Category 1 row and `derived_source` on all three hop-2 rows.

### 5. Score it with the model

Run **`notebooks/scorer_02_multihop.py`** — it is already pointed at `v_pii_candidates_mh`.

| Table | Expected | Why |
|---|---|---|
| `reassembled_contact` | LIKELY_EXFILTRATION, very high | `trivially_invertible` — the value *is* the phone number |
| `contact_from_view` | LIKELY_EXFILTRATION | padding strips off; `[at]` reverses to `@` |
| `agg_final` | LIKELY_EXFILTRATION | explode restores per-person rows exactly |
| `split_parts_src` | LIKELY_EXFILTRATION | the hop-1 split, caught as always |
| `v_stg_contact` | LIKELY_EXFILTRATION | rename-only view over tagged columns |

### 6. Full detail with the SQL text

```sql
SELECT c.target_table, c.source_hop, c.target_type, v.verdict, v.risk_score,
       v.reversibility_class, v.evidence_expression, v.rationale, v.recommended_action,
       c.pii_origin_columns, c.rule_reasons, c.statement_text AS query
FROM (
  SELECT * FROM pii_demo.security.pii_query_verdicts
  QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC) = 1
) v
JOIN pii_demo.security.v_pii_candidates_mh c USING (statement_id)
ORDER BY v.risk_score DESC;
```

---

## The closer — prevention

1. **Masking beats detection.** `sql/04_preventive_controls.sql` — mask `phone_number` on
   `gold.customer_master` and `split_parts_src` never contains real digits, so there is nothing to
   reassemble.
2. **Sandbox schemas should not be a blind spot.** The convergence query in step 3 makes a good
   standing alert on its own, independent of the LLM.
3. **Allowlist the legitimate pipelines** (`security.pii_transform_allowlist`) so the signal stays
   clean — a real ETL job reassembling data is fine *once it is declared*.

Closing line: *"they can split it, stage it, hide it behind a view, and rebuild it a week later.
Every one of those moves is an edge in a graph we already have."*

---

## What's extracted vs. what's passed to the model (privacy)

**No PII values leave Databricks.** The model sees SQL text, column and table *names*, row counts,
rule signals, `source_hop`, and `pii_origin_columns`. The convergence query in step 3 is pure
metadata — it detects a rebuilt phone number **without ever reading one**.

---

## Safety nets

- **Convergence query returns nothing?** Hop 2 lineage has not landed yet. Poll again.
- **`size(collect_set(...))` errors in the HAVING clause** on an older DBR — replace the HAVING with
  a wrapping subquery, or drop the second condition (you will get a few extra benign rows).
- **View has no Lineage tab?** Check the view was created in UC (`pii_demo.sandbox`), not as a temp view.
- **`explode` fails in Category 3** — confirm hop 1 created `contact_list` as an array
  (`DESCRIBE pii_demo.sandbox.agg_staging;`).
- **Short on time?** Category 2 alone. Four statements, and it is the strongest story in the kit.

---

## Timing at a glance

| Time | What |
|---|---|
| T‑20 | Pre-flight + `sql/05_multihop_lineage.sql` |
| T‑0 | Fire the 3 categories (7 statements) |
| T+1 | Slides / narrative |
| T+6 | UI graph — three-to-one convergence on `reassembled_contact` |
| T+10 | Poll lineage |
| T+12 | Show the base detector misses hop 2 |
| T+14 | Closure, then the convergence query |
| T+18 | Multi-hop candidates + model verdicts |
| T+23 | Closer — masking and the standing alert |

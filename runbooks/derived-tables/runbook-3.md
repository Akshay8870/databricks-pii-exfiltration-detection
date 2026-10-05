# FROM DERIVED TABLES — PII DETECT · RUNBOOK 3
## "The deep chain": four levels down, and a fan-in from two branches

**The scenario you are proving.** Runbooks 1 and 2 proved two hops. This one goes deeper and is
built specifically to produce **`source_hop = 2` and `source_hop = 3` rows** — the depths that
trigger the `laundering_chain` signal. If your earlier run only ever showed `hop 0` and `hop 1`,
this is the runbook that fixes that.

**Why depth matters on stage.** A single derived table can be explained away as sloppy ETL. A
four-level chain, each step individually innocuous, cannot. Depth is the argument.

**Prerequisite.** `sql/05_multihop_lineage.sql` must have run. The closure ships at 3 hops, which is
exactly what Category 1 exercises.

---

## T‑20 min — Pre-flight

1. `sql/01_setup_demo_data.sql`, `sql/03_detection.sql`, **and `sql/05_multihop_lineage.sql`** have all run.
2. Scorer notebook **`notebooks/scorer_02_multihop.py`** open and authenticated
   (token call returns 200). Fill in `FOUNDRY_HOST`, `DEPLOYMENT`, `TENANT_ID`, `CLIENT_ID` —
   they ship as placeholders.
3. Confirm the closure is live:
```sql
SELECT count(*) FROM pii_demo.security.v_pii_candidates_mh;   -- must not error
```
4. Clean slate (only this runbook's throwaway tables):
```sql
DROP TABLE IF EXISTS pii_demo.sandbox.dq_raw_intake;
DROP TABLE IF EXISTS pii_demo.sandbox.dq_norm;
DROP TABLE IF EXISTS pii_demo.sandbox.dq_enrich;
DROP TABLE IF EXISTS pii_demo.sandbox.dq_publish;
DROP TABLE IF EXISTS pii_demo.sandbox.br_left;
DROP TABLE IF EXISTS pii_demo.sandbox.br_right;
DROP TABLE IF EXISTS pii_demo.sandbox.br_merge;
DROP TABLE IF EXISTS pii_demo.sandbox.br_export;
DROP VIEW  IF EXISTS pii_demo.sandbox.vw_mid_layer;
DROP TABLE IF EXISTS pii_demo.sandbox.mid_layer_out;
```

---

## T‑0 — Fire the attack (3 categories)

**Run every statement separately.** Each needs its own `statement_id`, and each hop's lineage must
land before the next hop's edge is meaningful.

### Category 1 — Four levels deep (this is the one that produces hop 2 AND hop 3)

```sql
-- LEVEL 0 -> hop 0. Looks like a routine intake copy.
CREATE TABLE pii_demo.sandbox.dq_raw_intake AS
SELECT customer_id,
       phone_number AS src_val,
       email        AS src_alt,
       city
FROM   pii_demo.gold.customer_master;
```

```sql
-- LEVEL 1 -> hop 1. "Normalisation." Trims and uppercases. Nothing alarming.
CREATE TABLE pii_demo.sandbox.dq_norm AS
SELECT customer_id,
       trim(src_val)   AS norm_val,
       upper(src_alt)  AS norm_alt,
       city
FROM   pii_demo.sandbox.dq_raw_intake;
```

```sql
-- LEVEL 2 -> hop 2. The split happens HERE, two tables from anything tagged.
--            This row carries the laundering_chain signal.
CREATE TABLE pii_demo.sandbox.dq_enrich AS
SELECT customer_id,
       substr(norm_val,1,4)              AS seg_a,
       substr(norm_val,5,3)              AS seg_b,
       substr(norm_val,8,3)              AS seg_c,
       split_part(norm_alt,'@',2)        AS dom,
       city
FROM   pii_demo.sandbox.dq_norm;
```

```sql
-- LEVEL 3 -> hop 3. Reassembly at the far end of the chain.
CREATE TABLE pii_demo.sandbox.dq_publish AS
SELECT customer_id,
       concat(seg_a, seg_b, seg_c) AS publish_key,
       dom,
       city
FROM   pii_demo.sandbox.dq_enrich;
```

> Read `dq_publish` aloud. It reads from `dq_enrich`. It mentions no PII column, no tagged table,
> and no suspicious function — just `concat` of three columns called `seg_a/b/c`.
> Its output is a working phone number, and it is **three tables** from anything anyone tagged.

### Category 2 — Fan-in from two separate branches, at depth

```sql
-- two independent hop-0 branches
CREATE TABLE pii_demo.sandbox.br_left AS
SELECT customer_id, substr(aadhaar_number,1,7) AS l_part FROM pii_demo.gold.customer_master;
```
```sql
CREATE TABLE pii_demo.sandbox.br_right AS
SELECT customer_id, substr(aadhaar_number,9,6) AS r_part FROM pii_demo.gold.customer_master;
```
```sql
-- hop 1: merge the branches
CREATE TABLE pii_demo.sandbox.br_merge AS
SELECT a.customer_id, a.l_part, b.r_part
FROM   pii_demo.sandbox.br_left a JOIN pii_demo.sandbox.br_right b USING (customer_id);
```
```sql
-- hop 2: reassemble into a complete national ID
CREATE TABLE pii_demo.sandbox.br_export AS
SELECT customer_id, concat(l_part, r_part) AS ref_id
FROM   pii_demo.sandbox.br_merge;
```

### Category 3 — A VIEW in the middle of the chain

A view holds no data, so it is rarely reviewed — but it is still a lineage node, and the closure
walks straight through it.

```sql
CREATE VIEW pii_demo.sandbox.vw_mid_layer AS
SELECT customer_id, norm_val, norm_alt FROM pii_demo.sandbox.dq_norm;
```
```sql
CREATE TABLE pii_demo.sandbox.mid_layer_out AS
SELECT customer_id,
       reverse(norm_val)                  AS rev_val,
       regexp_replace(norm_alt,'@',' AT ') AS alt_txt
FROM   pii_demo.sandbox.vw_mid_layer;
```

---

## During slides — the narrative (~10–12 min, fills the lineage lag)

- "Each of those four statements would pass review on its own. Intake. Normalise. Enrich. Publish.
  That is a normal pipeline vocabulary — deliberately."
- "The split happens at level 2 and the reassembly at level 3. By then the source column is called
  `seg_a`, and the source table is called `dq_enrich`. Nothing says phone number."
- "Depth is not a mitigating factor, it is evidence. Real pipelines are documented and declared.
  Laundering chains are not."
- On Category 2: "two branches, each holding a fragment that is useless alone. Joined at the end.
  This is how people think they beat column-level controls."
- On Category 3: "a view stores nothing, so it feels safe to create and safe to ignore. Lineage
  records it anyway."

---

## Show the lineage chain in the Unity Catalog UI

1. **Catalog** → `pii_demo` → `sandbox` → **`dq_publish`** → **Lineage** → **Upstream**.
2. Click **See lineage graph**, then expand upstream **three times**:
   `dq_enrich` → `dq_norm` → `dq_raw_intake` → `gold.customer_master`.
   Say: *"four expansions. Every one of them was a separate day's work for the insider, and none of
   them looked like anything."*
3. Open the **column-level** view on the `dq_norm → dq_enrich` edge — one `norm_val` fanning out to
   `seg_a`, `seg_b`, `seg_c`. Then the next edge folds them back into one.
4. For Category 2, open **`br_export`** and expand — the graph forks into two branches and both
   land on `customer_master.aadhaar_number`.
5. Reverse view: `gold.customer_master` → **Downstream** shows the whole tree in one screen.

---

## Check lineage has populated (poll until it reaches 10)

```sql
SELECT count(DISTINCT target_table_full_name) FROM system.access.column_lineage
WHERE target_table_full_name IN
      ('pii_demo.sandbox.dq_raw_intake','pii_demo.sandbox.dq_norm',
       'pii_demo.sandbox.dq_enrich','pii_demo.sandbox.dq_publish',
       'pii_demo.sandbox.br_left','pii_demo.sandbox.br_right',
       'pii_demo.sandbox.br_merge','pii_demo.sandbox.br_export',
       'pii_demo.sandbox.vw_mid_layer','pii_demo.sandbox.mid_layer_out')
  AND event_date = current_date();
```

**Deep chains land progressively.** Level 1 lineage must exist before level 2 resolves, so the hop
numbers climb over a few minutes. If you see `hop 1` but not yet `hop 3`, wait and re-query — the
views are live, nothing needs re-running.

---

## Show it working — live detection

### 1. The gap first

```sql
SELECT target_table, rule_score
FROM   pii_demo.security.v_pii_candidates
WHERE  target_table LIKE 'pii_demo.sandbox.dq_%'
    OR target_table LIKE 'pii_demo.sandbox.br_%'
ORDER BY target_table;
```
Only `dq_raw_intake`, `br_left` and `br_right` appear — the three that read the tagged table
directly. **`dq_publish` is absent.** Say: *"the one that produces a working phone number is the
one we cannot see."*

### 2. The closure, by depth

```sql
SELECT hop, count(*) AS cols
FROM   pii_demo.security.v_pii_columns_transitive
GROUP BY hop ORDER BY hop;
```
Expect rows at hop 0, 1, 2 **and 3**.

### 3. The multi-hop candidates — deepest first

```sql
SELECT target_table, source_hop, source_tables AS read_from,
       pii_origin_columns AS traced_back_to, target_columns, rule_score, rule_reasons
FROM   pii_demo.security.v_pii_candidates_mh
WHERE  source_hop >= 1
ORDER BY source_hop DESC, rule_score DESC;
```
`dq_publish` at **`source_hop = 3`** with `laundering_chain` in the reasons, traced back to
`pii_demo.gold.customer_master.phone_number`. `br_export` at `hop 2`.

### 4. Score it with the model

Run **`notebooks/scorer_02_multihop.py`** (already pointed at `v_pii_candidates_mh`).

| Table | hop | Expected | Why |
|---|---|---|---|
| `dq_publish` | 3 | LIKELY_EXFILTRATION, very high | `trivially_invertible` — the value *is* the phone number |
| `dq_enrich` | 2 | LIKELY_EXFILTRATION | the split itself, plus `laundering_chain` |
| `br_export` | 2 | LIKELY_EXFILTRATION | rebuilt national ID from two branches |
| `mid_layer_out` | 2 | LIKELY_EXFILTRATION | `reverse` is trivially invertible; ` AT ` → `@` |
| `dq_norm` | 1 | LIKELY_EXFILTRATION | rename-and-trim copy |
| `dq_raw_intake` | 0 | LIKELY_EXFILTRATION | the direct copy |

### 5. Full detail, newest first

```sql
SELECT c.target_table, c.start_time, c.source_hop, v.verdict, v.risk_score,
       v.reversibility_class, v.evidence_expression, v.rationale, v.recommended_action,
       c.pii_origin_columns, c.rule_reasons, c.statement_text AS query
FROM (
  SELECT * FROM pii_demo.security.pii_query_verdicts
  QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC) = 1
) v
JOIN pii_demo.security.v_pii_candidates_mh c USING (statement_id)
ORDER BY c.source_hop DESC, c.start_time DESC;
```

---

## The closer — prevention

1. **Depth is configurable.** The closure ships at 3 hops. Copy the `h3` block to an `h4` and add
   it to the `allhops` UNION for deeper real pipelines — and say plainly that a 6-level pipeline
   needs a 6-level closure.
2. **Masking kills the chain at level 0.** `sql/04_preventive_controls.sql` — mask
   `gold.customer_master.phone_number` and `dq_raw_intake` never holds real digits, so there is
   nothing to normalise, split, or republish.
3. **Declare the real pipelines.** `security.pii_transform_allowlist` keeps genuine ETL out of the
   alert stream, which is what makes a laundering chain stand out.

Closing line: *"they went four tables deep to hide one phone number. The graph is four edges long.
That is not a hard problem once you stop reading SQL and start walking lineage."*

---

## What's extracted vs. what's passed to the model (privacy)

**No PII values ever leave Databricks.** The model receives metadata only — SQL text, column and
table *names*, row counts, rule signals, plus `source_hop` (an integer) and `pii_origin_columns`
(fully-qualified column *names*). A reassembled phone number at hop 3 is detected **without
reading a single data value**.

---

## Safety nets

- **Only seeing hop 0 and hop 1?** Deep lineage lands progressively — level 2 cannot resolve until
  level 1's edge exists. Wait a few minutes, re-run the query. No re-run of the SQL file needed.
- **`dq_publish` missing entirely?** Check `dq_enrich` was created successfully; if level 2 failed,
  level 3 read nothing.
- **Hop number lower than expected?** `source_hop` reports the **shortest** path. If a column is
  reachable both 1 and 3 hops back, it reports 1. Deliberate and conservative.
- **Model call fails?** The notebook retries 429/5xx up to 3 times. The run summary names anything
  still unscored — just re-run it, re-scoring is safe.
- **Short on time?** Category 1 only. Four statements, and it is the deepest proof in the kit.

---

## Timing at a glance

| Time | What |
|---|---|
| T‑20 | Pre-flight; confirm `_mh` view exists |
| T‑0 | Fire Category 1 (4 statements), then 2 and 3 |
| T+1 | Slides / narrative |
| T+6 | UI graph — expand upstream four times on `dq_publish` |
| T+10 | Poll lineage until 10 |
| T+12 | Show the base detector missing `dq_publish` |
| T+14 | Closure by depth, then candidates ordered hop DESC |
| T+18 | Score with the model |
| T+23 | Closer — masking and allowlisting |

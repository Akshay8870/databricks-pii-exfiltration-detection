# FROM DERIVED TABLES — PII DETECT · RUNBOOK 4
## "Pipeline mimicry": laundering disguised as a medallion architecture

**The scenario you are proving.** The most effective disguise is not clever SQL — it is
**looking like everyone else's job**. This insider names their tables `bronze_`, `silver_`,
`gold_`, uses the vocabulary of a normal data pipeline, and schedules the steps days apart. To a
reviewer scrolling a table list, the laundering chain is indistinguishable from the platform team's
own work.

**Why this runbook is the best one for a governance audience.** It moves the conversation from
*"can you catch a clever query?"* to *"can you tell a real pipeline from a fake one?"* — and the
answer is the allowlist plus lineage depth, not pattern matching. This is the runbook to pick if
your audience is the data-governance or platform team rather than security.

**Prerequisite.** `sql/05_multihop_lineage.sql` must have run.

---

## T‑20 min — Pre-flight

1. `sql/01_setup_demo_data.sql`, `sql/03_detection.sql`, **and `sql/05_multihop_lineage.sql`** have all run.
2. Scorer notebook **`notebooks/scorer_02_multihop.py`** open and authenticated
   (token call returns 200). Fill in `FOUNDRY_HOST`, `DEPLOYMENT`, `TENANT_ID`, `CLIENT_ID`.
3. Confirm the closure is live:
```sql
SELECT count(*) FROM pii_demo.security.v_pii_candidates_mh;   -- must not error
```
4. Clean slate:
```sql
DROP TABLE IF EXISTS pii_demo.sandbox.bronze_cust_feed;
DROP TABLE IF EXISTS pii_demo.sandbox.silver_cust_clean;
DROP TABLE IF EXISTS pii_demo.sandbox.gold_cust_ref;
DROP TABLE IF EXISTS pii_demo.sandbox.ops_ticket_stage;
DROP TABLE IF EXISTS pii_demo.sandbox.ops_ticket_idx;
DROP TABLE IF EXISTS pii_demo.sandbox.ops_ticket_final;
DROP TABLE IF EXISTS pii_demo.sandbox.rpt_daily_base;
DROP TABLE IF EXISTS pii_demo.sandbox.rpt_daily_pivot;
```

---

## T‑0 — Fire the attack (3 categories)

**Run every statement separately.**

### Category 1 — A fake medallion pipeline (bronze → silver → gold)

```sql
-- BRONZE (hop 0). "Raw landing." An exact copy with pipeline-standard renames.
CREATE TABLE pii_demo.sandbox.bronze_cust_feed AS
SELECT customer_id      AS cust_key,
       phone_number     AS attr_01,
       aadhaar_number   AS attr_02,
       email            AS attr_03,
       city             AS attr_04
FROM   pii_demo.gold.customer_master;
```

```sql
-- SILVER (hop 1). "Cleansing." Strips spaces -- which happens to normalise the Aadhaar.
CREATE TABLE pii_demo.sandbox.silver_cust_clean AS
SELECT cust_key,
       regexp_replace(attr_01,'[^0-9]','') AS attr_01_c,
       regexp_replace(attr_02,'\\s','')    AS attr_02_c,
       lower(attr_03)                      AS attr_03_c,
       attr_04
FROM   pii_demo.sandbox.bronze_cust_feed;
```

```sql
-- GOLD (hop 2). "Conformed reference." Packs everything into one JSON column.
CREATE TABLE pii_demo.sandbox.gold_cust_ref AS
SELECT cust_key,
       to_json(named_struct('a', attr_01_c, 'b', attr_02_c, 'c', attr_03_c)) AS ref_doc,
       attr_04
FROM   pii_demo.sandbox.silver_cust_clean;
```

> `gold_cust_ref` is a single JSON column named `ref_doc`, produced by a table called `gold_*`,
> sitting at the end of a bronze/silver/gold chain. It contains a phone number, a normalised
> national ID and an email address, all in clear text. **Nothing in its SQL says so.**

### Category 2 — "Operational tooling" with an index table

```sql
-- hop 0: a support-ticket staging table. Entirely plausible.
CREATE TABLE pii_demo.sandbox.ops_ticket_stage AS
SELECT customer_id AS ticket_ref,
       phone_number AS caller_id,
       dob,
       city
FROM   pii_demo.gold.customer_master;
```
```sql
-- hop 1: "build a lookup index" -- hex-encodes the caller id.
CREATE TABLE pii_demo.sandbox.ops_ticket_idx AS
SELECT ticket_ref,
       hex(caller_id) AS caller_idx,
       dob,
       city
FROM   pii_demo.sandbox.ops_ticket_stage;
```
```sql
-- hop 2: "publish the operational extract." unhex restores the original exactly.
CREATE TABLE pii_demo.sandbox.ops_ticket_final AS
SELECT ticket_ref,
       cast(unhex(caller_idx) AS STRING) AS caller_out,
       year(dob) AS yr,
       city
FROM   pii_demo.sandbox.ops_ticket_idx;
```

### Category 3 — "Daily reporting" that is really a quasi-identifier build

```sql
-- hop 0: looks like an aggregate feed
CREATE TABLE pii_demo.sandbox.rpt_daily_base AS
SELECT customer_id, dob, city, segment, lifetime_value
FROM   pii_demo.gold.customer_master;
```
```sql
-- hop 1: a "pivot" that is really a re-identifiable cohort of one
CREATE TABLE pii_demo.sandbox.rpt_daily_pivot AS
SELECT dob, city, segment,
       count(*)              AS n,
       max(lifetime_value)   AS top_val
FROM   pii_demo.sandbox.rpt_daily_base
GROUP BY dob, city, segment;
```
> Expect `SUSPICIOUS` with `reidentification_by_combination = true` on this one, not
> LIKELY_EXFILTRATION. **That is the right answer** — and showing the model getting a nuanced case
> right is worth more than another maximum score.

---

## During slides — the narrative (~10–12 min)

- "Look at these table names. Bronze, silver, gold. If you scanned a catalog list, which of these
  would you stop on?"
- "The disguise is not the SQL. It is the vocabulary. They named their exfiltration after your
  architecture."
- On silver: "'cleansing' and 'strip non-numerics' is real pipeline work. It is also exactly how
  you normalise an Aadhaar number into a matchable key."
- On Category 2: "`hex` and `unhex`. An index and a publish step. Both are real engineering
  patterns. Together they are a round trip to clear text."
- On Category 3: "this one is *not* maximum risk, and the model says so. Date of birth plus city
  plus segment identifies one person in this dataset — that is re-identification by combination,
  not extraction. A tool that screams at everything gets muted."
- Land it: **"you cannot solve this by blocking table names or reading SQL. You solve it by knowing
  which pipelines are declared, and treating everything else at depth as suspicious."**

---

## Show the lineage chain in the Unity Catalog UI

1. **Catalog** → `pii_demo` → `sandbox` → **`gold_cust_ref`** → **Lineage** → **Upstream** →
   expand twice: `silver_cust_clean` → `bronze_cust_feed` → `gold.customer_master`.
2. Say: *"the name says gold. The lineage says sandbox copy of your PII master, three steps back."*
3. Open the **column-level** graph on the last edge — `attr_01_c`, `attr_02_c`, `attr_03_c` all
   converge into the single `ref_doc` column. **Three PII columns into one.**
4. For Category 2, open **`ops_ticket_final`** and expand twice — the `hex`/`unhex` round trip is
   two edges that return to where they started.
5. Reverse view: `gold.customer_master` → **Downstream** — say *"every one of these was named to
   look like it belonged."*

---

## Check lineage has populated (poll until it reaches 8)

```sql
SELECT count(DISTINCT target_table_full_name) FROM system.access.column_lineage
WHERE target_table_full_name IN
      ('pii_demo.sandbox.bronze_cust_feed','pii_demo.sandbox.silver_cust_clean',
       'pii_demo.sandbox.gold_cust_ref','pii_demo.sandbox.ops_ticket_stage',
       'pii_demo.sandbox.ops_ticket_idx','pii_demo.sandbox.ops_ticket_final',
       'pii_demo.sandbox.rpt_daily_base','pii_demo.sandbox.rpt_daily_pivot')
  AND event_date = current_date();
```

---

## Show it working — live detection

### 1. The gap first

```sql
SELECT target_table, rule_score
FROM   pii_demo.security.v_pii_candidates
WHERE  target_table LIKE 'pii_demo.sandbox.bronze_%'
    OR target_table LIKE 'pii_demo.sandbox.silver_%'
    OR target_table LIKE 'pii_demo.sandbox.gold_%'
    OR target_table LIKE 'pii_demo.sandbox.ops_%'
ORDER BY target_table;
```
Only `bronze_cust_feed` and `ops_ticket_stage` appear. **`gold_cust_ref` and `ops_ticket_final` —
the two tables that actually hold recoverable PII — are invisible.**

### 2. The closure

```sql
SELECT table_full_name, column_name, hop, origin_column
FROM   pii_demo.security.v_pii_columns_transitive
WHERE  hop > 0
ORDER BY hop, table_full_name;
```
`ref_doc` and `caller_out` now resolve back to `phone_number` / `aadhaar_number` / `email`.

### 3. The multi-hop candidates

```sql
SELECT target_table, source_hop, source_tables AS read_from,
       pii_origin_columns AS traced_back_to, target_columns, rule_score, rule_reasons
FROM   pii_demo.security.v_pii_candidates_mh
WHERE  source_hop >= 1
ORDER BY source_hop DESC, rule_score DESC;
```
Both `gold_cust_ref` and `ops_ticket_final` at `source_hop = 2`, carrying `derived_source` **and**
`laundering_chain`.

### 4. Score it with the model

Run **`notebooks/scorer_02_multihop.py`**.

| Table | hop | Expected | Why |
|---|---|---|---|
| `gold_cust_ref` | 2 | LIKELY_EXFILTRATION, very high | `trivially_invertible` — JSON holds three PII fields in clear text |
| `ops_ticket_final` | 2 | LIKELY_EXFILTRATION, very high | `public_encoding` — `unhex` restores the caller id exactly |
| `ops_ticket_idx` | 1 | LIKELY_EXFILTRATION | `hex` is encoding, not protection |
| `silver_cust_clean` | 1 | LIKELY_EXFILTRATION | normalised PII, still clear text |
| `rpt_daily_pivot` | 1 | **SUSPICIOUS**, `reidentification_by_combination = true` | quasi-identifiers, not direct extraction |
| `bronze_cust_feed` | 0 | LIKELY_EXFILTRATION | the direct copy |

### 5. Full detail, newest first

```sql
SELECT c.target_table, c.start_time, c.source_hop, v.verdict, v.risk_score,
       v.reversibility_class, v.reidentification_by_combination AS reident,
       v.evidence_expression, v.rationale, v.recommended_action,
       c.pii_origin_columns, c.rule_reasons, c.statement_text AS query
FROM (
  SELECT * FROM pii_demo.security.pii_query_verdicts
  QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC) = 1
) v
JOIN pii_demo.security.v_pii_candidates_mh c USING (statement_id)
ORDER BY c.source_hop DESC, v.risk_score DESC;
```

---

## The closer — prevention

This runbook's closer is different from the others, and stronger for a governance audience:

1. **Declare your real pipelines.** `security.pii_transform_allowlist` is the control that makes
   this tractable. A genuine bronze/silver/gold pipeline is registered once; everything else
   running the same pattern at depth is, by definition, undeclared.
```sql
INSERT INTO pii_demo.security.pii_transform_allowlist
VALUES ('pii_demo.analytics.silver_customer_conformed', 'Declared ETL - owner: data-platform');
```
2. **Mask at the source.** `sql/04_preventive_controls.sql` — if `bronze_cust_feed` never holds real
   digits, no amount of downstream cleansing recovers them.
3. **Sandbox schemas are where this happens.** Alert on `source_hop >= 1` into any non-declared
   schema as a standing rule, independent of the model.

Closing line: *"they did not beat your controls with clever SQL. They beat them by looking like
your own pipeline. The allowlist is what tells the difference, and lineage is what makes the
allowlist enforceable."*

---

## What's extracted vs. what's passed to the model (privacy)

**No PII values ever leave Databricks.** The model receives SQL text, column and table *names*, row
counts, rule signals, `source_hop` and `pii_origin_columns` — metadata only. Note that
`gold_cust_ref.ref_doc` contains clear-text PII in the *data*, and the detector never reads it:
the verdict comes entirely from the structure of the statement and the lineage graph.

---

## Safety nets

- **`regexp_replace` with `\\s` errors** — some editors strip the escape. Use `'[ ]'` instead;
  the demo point is unchanged.
- **`unhex` returns binary** — the `cast(... AS STRING)` is required. If Category 2 hop 2 fails,
  check the cast survived the paste.
- **`rpt_daily_pivot` scores lower than you expected** — that is correct, not a failure. Quasi-
  identifier re-identification is a genuinely different class from direct extraction. Use it.
- **Only hop 0 rows appear?** Hop-1 lineage has not landed. Wait, re-query — no SQL re-run needed.
- **Model call fails?** The notebook retries 429/5xx automatically; the run summary names anything
  still unscored. Re-running is safe.
- **Short on time?** Category 1 alone — three statements, and the bronze/silver/gold reveal is the
  strongest single moment in this runbook.

---

## Timing at a glance

| Time | What |
|---|---|
| T‑20 | Pre-flight; confirm `_mh` view exists |
| T‑0 | Fire the 3 categories (8 statements) |
| T+1 | Slides / narrative — lead with the table names |
| T+6 | UI graph — `gold_cust_ref` upstream, twice |
| T+10 | Poll lineage until 8 |
| T+12 | Show the base detector missing `gold_cust_ref` |
| T+14 | Closure, then candidates at `source_hop >= 1` |
| T+18 | Score with the model — include the nuanced `rpt_daily_pivot` result |
| T+23 | Closer — the allowlist as the real control |

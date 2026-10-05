# FROM DERIVED TABLES — PII DETECT · RUNBOOK 1
## "The patient insider": launder through a boring staging table first

**The scenario you are proving.** The insider knows a direct copy off `gold.customer_master` is
noisy. So they make one dull, innocent-looking staging table today, and do the real disguise
*from that table* — where the source column carries no PII tag at all. Then they do it again, one
hop deeper.

**Why this runbook exists.** Unity Catalog does **not** propagate tags to derived tables. Base
Stage 1 joins lineage to *tagged* columns only, so hop 2 slips straight through. `sql/05_multihop_lineage.sql`
closes that hole with a transitive lineage closure. Run that file before this runbook.

---

## T‑20 min — Pre-flight

1. `sql/01_setup_demo_data.sql` has run; `gold.customer_master` exists with tags on 7 columns.
2. `sql/03_detection.sql` has run (the three base views exist).
3. **`sql/05_multihop_lineage.sql` has run** — creates `v_pii_columns_transitive`,
   `v_pii_write_events_mh`, `v_pii_candidates_mh`. This runbook does not work without it.
4. Scorer notebook **`notebooks/scorer_02_multihop.py`** open and authenticated (token call returns 200).
   Fill in `FOUNDRY_HOST`, `DEPLOYMENT`, `TENANT_ID`, `CLIENT_ID` — they ship as placeholders.
5. Clean slate:
```sql
DROP TABLE IF EXISTS pii_demo.sandbox.stg_loyalty_base;
DROP TABLE IF EXISTS pii_demo.sandbox.loyalty_final;
DROP TABLE IF EXISTS pii_demo.sandbox.stg_acct_note;
DROP TABLE IF EXISTS pii_demo.sandbox.acct_note_enc;
DROP TABLE IF EXISTS pii_demo.sandbox.stg_ref_a;
DROP TABLE IF EXISTS pii_demo.sandbox.stg_ref_b;
DROP TABLE IF EXISTS pii_demo.sandbox.ref_final;
```

---

## T‑0 — Fire the attack (3 categories, each a CHAIN)

Run these as the "temporary access" user. **Run hop 1 and hop 2 as separate statements** — that
separation is the whole point; each gets its own `statement_id` and its own lineage edge.

### Category 1 — Rename-only staging, then the split (2 hops)

**Hop 1 — looks completely benign.** No transformation, just a rename. A reviewer glancing at
this would pass it.
```sql
CREATE TABLE pii_demo.sandbox.stg_loyalty_base AS
SELECT customer_id,
       phone_number AS contact_ref,
       city         AS branch_city,
       segment
FROM   pii_demo.gold.customer_master;
```

**Hop 2 — the real exfiltration, sourced from the staging table.**
```sql
CREATE TABLE pii_demo.sandbox.loyalty_final AS
SELECT customer_id,
       substr(contact_ref,1,3)  AS zone_cd,
       substr(contact_ref,4,3)  AS route_cd,
       substr(contact_ref,7,4)  AS member_seq,
       branch_city
FROM   pii_demo.sandbox.stg_loyalty_base;
```
> Note what hop 2 does **not** contain: the word `phone_number`, and the table `customer_master`.
> Nothing in that SQL text says "PII". Only lineage knows.

### Category 2 — Staging concat, then reversible encoding (2 hops)

**Hop 1**
```sql
CREATE TABLE pii_demo.sandbox.stg_acct_note AS
SELECT customer_id,
       concat('AC', phone_number, '-', substr(aadhaar_number,1,4)) AS acct_note
FROM   pii_demo.gold.customer_master;
```

**Hop 2 — base64 on top, so the final table looks like opaque tokens.**
```sql
CREATE TABLE pii_demo.sandbox.acct_note_enc AS
SELECT customer_id,
       base64(cast(acct_note AS BINARY)) AS note_token
FROM   pii_demo.sandbox.stg_acct_note;
```

### Category 3 — Three-hop chain (the depth test)

```sql
-- hop 1
CREATE TABLE pii_demo.sandbox.stg_ref_a AS
SELECT customer_id, email AS ref_a, dob FROM pii_demo.gold.customer_master;

-- hop 2
CREATE TABLE pii_demo.sandbox.stg_ref_b AS
SELECT customer_id, reverse(ref_a) AS ref_b, dob FROM pii_demo.sandbox.stg_ref_a;

-- hop 3 — three tables away from anything tagged
CREATE TABLE pii_demo.sandbox.ref_final AS
SELECT customer_id,
       split_part(reverse(ref_b),'@',1) AS handle,
       split_part(reverse(ref_b),'@',2) AS domain,
       year(dob)                        AS birth_yr
FROM   pii_demo.sandbox.stg_ref_b;
```

---

## During slides — the narrative (~10–12 min, fills the lineage lag)

Talk-track for this runbook specifically:

- "Tag-based controls stop at the tagged table. The moment data lands in a derived table, the tag
  is gone — Unity Catalog does not propagate it. Every tag-only DLP tool goes blind right here."
- "Our insider knows that. So they build a boring staging table first and wait."
- "Lineage does not care. It recorded the edge `customer_master.phone_number → stg_loyalty_base.contact_ref`
  when hop 1 ran, and `stg_loyalty_base.contact_ref → loyalty_final.zone_cd` when hop 2 ran.
  Walking those edges reconstructs the whole chain."
- "And the chain itself is now *evidence* — a two-hop path to a tagged column is a stronger signal
  than a one-hop path, not a weaker one. Legitimate pipelines are documented; laundering chains are not."

---

## Show the lineage chain in the Unity Catalog UI

1. **Catalog** → `pii_demo` → `sandbox` → **`loyalty_final`** → **Lineage** → **Upstream**
2. It shows `stg_loyalty_base` — one hop. Now click **See lineage graph** and **expand the upstream node again**.
3. `gold.customer_master` appears behind it. Say: *"two clicks, and the boring staging table stops being boring."*
4. For the depth test, open **`ref_final`** and expand upstream three times — `stg_ref_b` → `stg_ref_a` → `customer_master`.
5. Reverse view: open `gold.customer_master` → **Downstream**. The staging tables and their children
   all fan out from one screen.

---

## Check lineage has populated (poll until non-zero)

Expect **7** (3 chains, 7 tables total):
```sql
SELECT count(DISTINCT target_table_full_name) FROM system.access.column_lineage
WHERE target_table_full_name IN
      ('pii_demo.sandbox.stg_loyalty_base',
       'pii_demo.sandbox.loyalty_final',
       'pii_demo.sandbox.stg_acct_note',
       'pii_demo.sandbox.acct_note_enc',
       'pii_demo.sandbox.stg_ref_a',
       'pii_demo.sandbox.stg_ref_b',
       'pii_demo.sandbox.ref_final')
  AND event_date = current_date();
```

---

## Show it working — live detection

### 1. Prove the base detector MISSES hop 2 (do this first — it earns the rest)

```sql
SELECT target_table, rule_score
FROM   pii_demo.security.v_pii_candidates
WHERE  target_table LIKE 'pii_demo.sandbox.%'
ORDER BY target_table;
```
Only the **hop‑1 staging tables** appear. `loyalty_final`, `acct_note_enc`, `ref_final` are absent.
Say: *"that is the gap, and it is not a bug in our rules — it is what happens to every tag-driven
control the moment data moves one table sideways."*

### 2. Now the transitive closure

```sql
SELECT table_full_name, column_name, pii_type, hop, origin_table, origin_column
FROM   pii_demo.security.v_pii_columns_transitive
WHERE  hop > 0
ORDER BY hop, table_full_name;
```
Every derived column is now classified as PII, with the **origin column it descends from**.

### 3. The multi-hop candidate set — the money query

```sql
SELECT target_table, source_hop, source_tables AS read_from,
       pii_origin_columns AS traced_back_to, target_columns,
       rule_score, rule_reasons
FROM   pii_demo.security.v_pii_candidates_mh
ORDER BY source_hop DESC, rule_score DESC;
```
`loyalty_final` now appears with `source_hop = 1` and `traced_back_to` containing
`pii_demo.gold.customer_master.phone_number`, carrying the new `derived_source` reason.
`ref_final` appears at `source_hop = 2` or `3` with `laundering_chain` on top.

### 4. Score it with the model

Run **`notebooks/scorer_02_multihop.py`**. It already points at `v_pii_candidates_mh` (see `CANDIDATE_VIEW`
in the config block), so no edit is needed. Expected verdicts:

| Table | Expected | Why |
|---|---|---|
| `loyalty_final` | LIKELY_EXFILTRATION, high | `trivially_invertible` — three parts concatenate back to the phone |
| `acct_note_enc` | LIKELY_EXFILTRATION, high | `public_encoding` — base64 is decoding, not protection |
| `ref_final` | LIKELY_EXFILTRATION | handle + domain rebuilds the email exactly |
| staging tables | LIKELY_EXFILTRATION / SUSPICIOUS | direct copies, caught at hop 0 as always |

### 5. Full detail with the SQL text

```sql
SELECT c.target_table, c.source_hop, v.verdict, v.risk_score, v.reversibility_class,
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

Two points, both landing on the same idea:

1. **Detection now survives laundering.** Depth is configurable — the closure ships at 3 hops;
   raise it for deeper real pipelines.
2. **Better still, propagate the classification.** Show `sql/04_preventive_controls.sql`: a column mask
   on `gold.customer_master.phone_number` means the staging table never contains a real phone
   number to launder in the first place. Detection is the net; masking is the fence.

Closing line: *"the insider's advantage was that your controls stop at the tagged table.
Lineage does not stop there, so neither does this."*

---

## What's extracted vs. what's passed to the model (privacy)

Unchanged from the base runbooks, with one addition. **No PII values ever leave Databricks.**
The model receives metadata only — SQL text, column *names*, table names, row counts, rule signals —
plus, in multi-hop mode, two extra metadata fields: `source_hop` (an integer) and
`pii_origin_columns` (fully-qualified column *names*). Still no data values.

---

## Safety nets

- **Hop 2 not appearing?** Lineage for hop 1 must land before hop 2's edge is useful. Re-run the
  poll; give it a few more minutes.
- **`v_pii_columns_transitive` returns only hop 0?** `sql/05_multihop_lineage.sql` ran before the attack
  queries. Views are not materialised, so just re-query it — no need to recreate.
- **Nothing at all in the closure?** Check `sql/03_detection.sql` ran and `v_pii_columns` is non-empty
  (`SELECT * FROM pii_demo.security.v_pii_columns;`).
- **Chain looks shorter than expected** — `source_hop` reports the *shortest* path. If a column is
  reachable both 1 and 3 hops back, it reports 1. That is deliberate and conservative.
- **Running short on time?** Fire Category 1 only. Two statements, and it proves the entire point.

---

## Timing at a glance

| Time | What |
|---|---|
| T‑20 | Pre-flight + `sql/05_multihop_lineage.sql` |
| T‑0 | Fire the 3 chains (7 statements) |
| T+1 | Slides / narrative |
| T+6 | UI lineage graph, expand upstream twice |
| T+10 | Poll lineage |
| T+12 | Show base detector MISSES hop 2 |
| T+14 | Closure + multi-hop candidates |
| T+18 | Score with the model, show verdicts |
| T+23 | Closer — masking as the fence |

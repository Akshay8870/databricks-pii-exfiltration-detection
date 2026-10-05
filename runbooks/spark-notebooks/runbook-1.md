# NOTEBOOK / SPARK PII DETECT · RUNBOOK 1
## "It is not just SQL": Python and Scala notebooks writing files to ADLS

**The feedback this answers.** *"This PoC only covers SQL queries. What if a Python notebook
reads a PII table, builds a DataFrame, and writes it to a file in ADLS?"*

**The short answer: it is caught, and the same lineage backbone does it.** Unity Catalog captures
lineage for the **Spark DataFrame API in every language** — SQL, Python, Scala, R — because it
harvests the resolved query plan, not the text. And `column_lineage` carries `target_path` and
`target_type = 'PATH'`, so a DataFrame written to `abfss://...` is recorded **at column level**.

**But one thing genuinely breaks, and you should say so before they find it.** In the lineage
system tables, `statement_id` is populated **only for SQL warehouse queries**. For a notebook it is
NULL. The original Stage 1 joins `column_lineage` to `query.history` on `statement_id`, so notebook
events silently never appear. `sql/06_notebook_spark_detection.sql` re-keys detection on `event_id`
and the entity fields, which is what makes notebooks visible.

**The consequence to be honest about:** there is **no source code** for a notebook event.
Databricks does not record statement text for the DataFrame API. So the regex rules
(`substr`, `base64`, `concat`…) cannot fire, and detection becomes **structural** — it reasons about
the column-to-column map itself. That turns out to be enough, and it is arguably stronger: the map
is ground truth regardless of the language or the cleverness of the code.

---

## T‑20 min — Pre-flight

1. `sql/01_setup_demo_data.sql` and `sql/03_detection.sql` have run.
2. **`sql/06_notebook_spark_detection.sql` has run.** Verify:
```sql
SELECT count(*) FROM pii_demo.security.v_pii_candidates_all;   -- must not error
```
3. Scorer notebook **`notebooks/scorer_03_spark.py`** open and authenticated (token call returns
   200). Fill in `FOUNDRY_HOST`, `DEPLOYMENT`, `TENANT_ID`, `CLIENT_ID` — they ship as placeholders.
4. **A writable storage location.** Easiest is a UC Volume, no external-location setup needed:
```sql
CREATE VOLUME IF NOT EXISTS pii_demo.sandbox.exfil_vol;
```
   For the customer's exact scenario use a real ADLS path instead — set `BASE` in
   `notebooks/attacker_pyspark.py` to `abfss://<container>@<account>.dfs.core.windows.net/...`.
   Behaviour and lineage capture are identical; the raw path is just more convincing on stage.
5. Import **`notebooks/attacker_pyspark.py`** as a notebook and attach it to a
   **Unity Catalog-enabled cluster** (shared or single-user UC access mode). This matters — lineage
   is only captured on UC-governed compute.
6. Clean slate if you have run this before — the cleanup cell is printed at the end of the attack
   notebook.

---

## T‑0 — Fire the attack (run the notebook)

Run `notebooks/attacker_pyspark.py` top to bottom. Six attacks, **none of them a SQL statement**:

| # | What it does | Written as |
|---|---|---|
| N1 | Splits the phone three ways — the customer's original example, in Python | **Parquet** to storage |
| N2 | Pads and concatenates (`aabb` + phone + `xxzz`), plus a name+email blob | **CSV** to storage |
| N3 | Base64-encodes Aadhaar and PAN | **JSON** to storage |
| N4 | Full copy, every column renamed to `attr_00`, `attr_01`, … | **Parquet** to storage |
| N5 | Two hops: intermediate **table**, then reversed phone to storage | table → Parquet |
| N6 | DataFrame API write to a governed **table** (not a file) | UC table |

Then paste the **`%scala` cell** the notebook prints into a new cell and run it. Same attack in
Scala — the point being that lineage does not care which language produced the plan.

**Call out N2 specifically.** CSV is the worst case for the customer: plain text, no schema, no
governance, readable by anything with storage access.

---

## During slides — the narrative (~10–12 min, fills the lineage lag)

- "The objection was fair. Everything we showed you was SQL. Here is the same insider working in
  Python, and never submitting a single SQL statement."
- "Two things changed. The data left as **files**, not tables — so Unity Catalog grants, row
  filters and column masks do not apply to the copy at all. And there is **no SQL text anywhere**,
  so anything that works by scanning query text is blind to all six of these."
- "What did not change is the part that matters. Databricks resolves a query plan to execute the
  DataFrame code, and Unity Catalog harvests that plan. The mapping from `phone_number` to
  `zone_cd`, `route_cd` and `member_seq` is recorded exactly as it was for SQL."
- **On the honest gap:** "we do lose the code. Databricks does not store statement text for the
  DataFrame API. So for notebooks we detect structurally — one PII column feeding three renamed
  target columns at a storage path is damning on its own, whatever the code looked like."
- "If they want the code as well, verbose audit logging exposes notebook command text. It is off by
  default and it is a volume decision, so we treat it as an option, not a dependency."

---

## Show the lineage in the Unity Catalog UI

**This is the strongest visual in the whole kit**, because a file path appearing as a lineage node
surprises people.

1. **Catalog** → `pii_demo` → `gold` → **`customer_master`** → **Lineage** → **Downstream**.
2. Among the tables, **the storage paths appear as nodes too**. Say: *"that node is not a table.
   That is a folder of Parquet files in ADLS, and it is in the graph."*
3. Click **See lineage graph**, then click the edge into `nb_phone_parts` and expand to column
   level — `phone_number` → `zone_cd` / `route_cd` / `member_seq`.
4. On the Lineage tab, open the **Notebooks** section — it names the notebook that produced it, so
   you pivot straight from "this file is suspicious" to "this person, this notebook, this run."

---

## Check lineage has populated (poll until non-zero)

**Two traps here, both of which return a misleading zero.**

**Trap 1 - query by `target_path`, not by table name.** A path target has a NULL
`target_table_full_name`, so a table-name filter finds nothing.

**Trap 2 - NEVER anchor the LIKE at the start of the path.** Databricks records a Volume path as
`dbfs:/Volumes/...`, NOT `/Volumes/...`, and a real ADLS target may be recorded as the resolved
storage URL rather than the path you wrote. Always lead with `%`:

```sql
-- prefix-agnostic: works for dbfs:/Volumes, /Volumes and abfss:// alike
SELECT count(DISTINCT target_path) FROM system.access.column_lineage
WHERE target_path LIKE '%exfil_vol%'
  AND event_date = current_date();
```
Expect **6** (5 if you have not yet run the Scala cell).

Better still, look at what was actually recorded rather than guessing - this output IS a demo
exhibit in its own right:

```sql
SELECT target_path, target_type, entity_type, count(*) AS col_edges
FROM   system.access.column_lineage
WHERE  event_date = current_date() AND target_path IS NOT NULL
GROUP BY target_path, target_type, entity_type
ORDER BY target_path;
```
Every row comes back `target_type = PATH`, `entity_type = NOTEBOOK`. Put it on screen and say:
*"five writes to cloud storage, every one recorded, and not one of them was a SQL statement."*

Check the entity side landed too:
```sql
SELECT entity_type, count(*) FROM system.access.column_lineage
WHERE event_date = current_date() GROUP BY entity_type;
```
You should see `NOTEBOOK` rows. That is the proof the notebook path is live.

---

## Show it working — live detection

### 1. The gap first — prove the SQL-only detector is blind

```sql
SELECT count(*) AS caught_by_sql_only
FROM   pii_demo.security.v_pii_candidates
WHERE  target_table LIKE '%nb_%';
```
Returns **0**, or only `nb_api_table` / `nb_stage_mid`. Every file write is invisible. Say:
*"not a bug — those events have no statement_id, so the join to query history finds nothing.
This is exactly what your existing text-based tooling would do."*

### 2. What the notebook-aware detector sees

```sql
SELECT entity_type, executed_by, target_object, target_type,
       pii_source_columns, target_columns, column_map, rule_score, rule_reasons
FROM   pii_demo.security.v_pii_candidates_all
WHERE  statement_id IS NULL
ORDER BY rule_score DESC;
```
All six notebook events, each with its **column map** — the source-to-target pairs that are the
whole evidence base when there is no code.

### 3. Everything that left as files rather than tables

```sql
SELECT executed_by, target_path, entity_type, pii_types,
       pii_source_columns, target_columns, rule_score
FROM   pii_demo.security.v_pii_candidates_all
WHERE  target_type = 'PATH'
ORDER BY start_time DESC;
```
Governance line to use: *"every row here is PII sitting outside Unity Catalog's control plane. A
column mask on the source table does nothing for these files."*

### 4. The unified view — SQL and notebooks together

```sql
SELECT coalesce(entity_type,'SQL_WAREHOUSE') AS origin,
       target_object, target_type, executed_by, rule_score, start_time
FROM   pii_demo.security.v_pii_candidates_all
ORDER BY start_time DESC;
```
One detector, both worlds. This is the slide-worthy result.

### 5. Score it with the model

Run **`notebooks/scorer_03_spark.py`**. Its startup line reports how many candidates came from
notebooks with no SQL text, and how many went to storage paths.

| Target | Origin | Expected | Why |
|---|---|---|---|
| `nb_phone_parts` | NOTEBOOK | LIKELY_EXFILTRATION, very high | `trivially_invertible` — three parts concatenate back |
| `nb_padded_csv` | NOTEBOOK | LIKELY_EXFILTRATION, very high | padding strips off; **plain-text CSV** in storage |
| `nb_encoded_json` | NOTEBOOK | LIKELY_EXFILTRATION | `public_encoding` — base64 is not protection |
| `nb_full_attr` | NOTEBOOK | LIKELY_EXFILTRATION | full copy; renaming to `attr_NN` hides nothing |
| `nb_stage_final` | NOTEBOOK | LIKELY_EXFILTRATION | `reverse` is trivially invertible |
| `nb_scala_parts` | NOTEBOOK | LIKELY_EXFILTRATION | same attack, different language |
| `nb_api_table` | NOTEBOOK | LIKELY_EXFILTRATION | DataFrame write to a governed table |

The model should say explicitly in its rationale that the verdict came from **lineage structure
rather than code**, and that a PATH target sits outside Unity Catalog's controls. Read one
rationale aloud — that is the moment the objection is answered.

### 6. The stage moment — only what SQL-only detection misses

Cell 7 of the scorer displays exactly this: notebook events plus anything written to a path, with
verdict and recommended action. Put that on screen and stop talking.

---

## The closer — prevention

The preventive story is **different here**, and stronger. Say this plainly:

1. **Masking still works, and it works earlier.** A column mask on `gold.customer_master` applies
   when the DataFrame reads the table — so `nb_phone_parts` contains masked digits and there is
   nothing to reassemble. The mask protects the read, whatever language performs it.
2. **Control where files can be written.** External locations and storage credentials are the UC
   control for path writes. If the sandbox cluster has no credential for a general-purpose
   container, `df.write.parquet("abfss://...")` fails outright.
3. **Detection covers the residual.** Volumes and permitted external locations are legitimate and
   will stay writable — that is where `v_pii_candidates_all` earns its place.

Closing line: *"your question was whether this only works for SQL. It works for the query plan,
and every language compiles to a query plan. What changes for notebooks is not whether we see it —
it is that the copy lands outside Unity Catalog, which is a bigger problem than the one you asked
about."*

---

## What's extracted vs. what's passed to the model (privacy)

**No PII values ever leave Databricks — including for file targets.** The model receives metadata
only: the column map (column *names*), table and path *names*, the target type, row counts, rule
signals, and the notebook/job identifiers. The contents of the Parquet, CSV and JSON files are
never read by the detector at any stage.

---

## Safety nets

- **Nothing in lineage at all?** The cluster is almost certainly not UC-enabled. Check the cluster's
  access mode — lineage is only captured on Unity Catalog governed compute.
- **Table-name query returns nothing** — path targets have a NULL `target_table_full_name`. Filter
  on `target_path`. This trips everyone up once.
- **Poll returns 0 but lineage is clearly working?** It is the LIKE prefix, not the capture.
  Databricks records Volume paths as `dbfs:/Volumes/...`. Check the real format with
  `SELECT DISTINCT target_path FROM system.access.column_lineage WHERE event_date = current_date()
  AND target_path IS NOT NULL;` and always lead your pattern with `%`. Note this only ever affects
  the MANUAL poll - `v_pii_candidates_all` never filters on path text, so detection was working
  the whole time.
- **`nb_*` paths missing but tables present?** Path lineage can land a little behind table lineage.
  Poll again; the views are live and need no re-run.
- **Write fails with a credential error** — you do not have an external location for that container.
  Switch `BASE` to the UC Volume; the demo is unchanged.
- **Scala cell fails** — make sure it is in its own cell starting with `%scala`.
- **Verbose audit logging** is what would recover the notebook code. It is off by default and is a
  log-volume decision. Do not promise it without checking with their platform team.
- **Short on time?** N1 and N2 only. A split phone in Parquet and a plain-text CSV of names and
  emails, both invisible to SQL-based detection, both caught here.

---

## Timing at a glance

| Time | What |
|---|---|
| T‑20 | Pre-flight; create the Volume; confirm `v_pii_candidates_all` exists |
| T‑0 | Run the attack notebook (6 attacks), then the Scala cell |
| T+1 | Slides / narrative — lead with "the objection was fair" |
| T+6 | UI lineage graph — a **file path** as a node is the visual |
| T+10 | Poll lineage by `target_path` |
| T+12 | Show the SQL-only detector returning zero |
| T+14 | `v_pii_candidates_all` — notebook events with their column maps |
| T+16 | The `target_type = 'PATH'` query — PII outside UC governance |
| T+18 | Score with the model; read one rationale aloud |
| T+23 | Closer — masking protects the read; external locations control the write |

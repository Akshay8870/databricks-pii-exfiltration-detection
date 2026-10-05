# Detecting Disguised PII Exfiltration in Azure Databricks

Detect insiders who copy PII out of governed tables while disguising it — padding, splitting
columns, renaming, encoding, hashing, packing into JSON, or writing DataFrames to cloud storage.

Built on **Unity Catalog column lineage** (deterministic) plus an **Azure AI Foundry reasoning
model** (adjudication). No agents, no code changes to existing workloads, and **no PII values ever
leave Databricks**.

---

## The problem

An employee is granted temporary access to a table containing PII. They read it and create a new
table — but they disguise the data on the way out:

```sql
-- the phone number 9764445335 becomes...
SELECT substr(phone_number,1,3) AS zone_cd,     -- 976
       substr(phone_number,4,3) AS route_cd,    -- 444
       substr(phone_number,7,4) AS member_seq   -- 5335
FROM   gold.customer_master;

-- ...or this
SELECT concat('aabb', phone_number, 'xxzz') AS ref_string FROM gold.customer_master;
```

Every attempt uses a different combination. Scanning SQL text for patterns does not scale, and it
fails completely the moment the insider switches to a Python notebook.

## The approach

**Unity Catalog already knows.** To execute any statement, Databricks resolves which *source
columns* feed which *output columns*. Unity Catalog harvests that resolved plan automatically into
system tables — so the disguise is irrelevant. A renamed column still resolves to its source. A
split is recorded as one source column feeding three target columns.

Detection runs in two stages:

| Stage | What it does | Technology |
|---|---|---|
| **1 — Narrow** | Join column lineage to tagged PII columns. Score with ~12 structural rules. Millions of statements → a handful of candidates. | Pure SQL. Deterministic. No AI. |
| **2 — Adjudicate** | Ask a reasoning model the question rules cannot answer: *is the original value actually recoverable?* | Azure AI Foundry |

Stage 2 is where the value is. A base64-encoded column and a securely salted hash look identical to
a rule engine. The model treats the first as reversible and the second as benign — and flags an
*unsalted* phone hash as weak, because a 10-digit number space is trivially brute-forced.

## What it catches

| Technique | Example | Verdict |
|---|---|---|
| Column splitting | `substr` into 3 parts | LIKELY_EXFILTRATION |
| Padding / concatenation | `'aabb' \|\| phone \|\| 'xxzz'` | LIKELY_EXFILTRATION |
| Reversible encoding | `base64()`, `hex()` | LIKELY_EXFILTRATION |
| Renaming | `phone_number AS attr_01` | LIKELY_EXFILTRATION |
| Packing | `to_json(named_struct(...))` | LIKELY_EXFILTRATION |
| Reassembly | `concat(p1,p2,p3)` days later | LIKELY_EXFILTRATION |
| Laundering through derived tables | staging table, then disguise | LIKELY_EXFILTRATION |
| **PySpark / Scala notebooks** | `df.write.parquet("abfss://...")` | LIKELY_EXFILTRATION |
| Unsalted hash | `sha2(phone,256)` | **SUSPICIOUS** — weak one-way, low entropy |
| Quasi-identifiers | `dob + city + segment` | **SUSPICIOUS** — re-identification by combination |
| Salted hash (secret salt) | `sha2(concat(phone, secret),256)` | **BENIGN** |

The last three matter as much as the first eight. A detector that scores everything maximum gets
muted within a week.

## Coverage

- **SQL warehouse queries** — full coverage, including statement text.
- **Spark DataFrame API in Python, Scala, R** — lineage is captured from the query plan, so
  language is irrelevant. See [docs/05](docs/05-spark-notebook-coverage.md).
- **Writes to ADLS / cloud storage paths** — recorded with `target_type = 'PATH'`. These sit
  **outside** Unity Catalog's control plane, so table grants, row filters and column masks do not
  apply to the copy.
- **Multi-hop laundering** — a transitive lineage closure follows PII through untagged
  intermediate tables. See [docs/04](docs/04-multihop-lineage.md).

---

## Quick start

**Prerequisites:** Azure Databricks Premium with Unity Catalog, account + metastore admin rights,
system schemas enabled, and an Azure AI Foundry reasoning-model deployment.
Full list: [docs/01-prerequisites.md](docs/01-prerequisites.md).

```
1. sql/01_setup_demo_data.sql          Create and TAG the demo PII table
2. sql/03_detection.sql                Stage 1 detection views
3. sql/05_multihop_lineage.sql         Multi-hop closure (recommended)
4. sql/06_notebook_spark_detection.sql Notebook + storage-path coverage (recommended)
5. sql/02_attacker_playbook.sql        Fire the attacks
6. notebooks/scorer_03_spark.py        Stage 2 — score with the model
```

Then pick a runbook from [runbooks/](runbooks/README.md) and present it.

### Which guide do I need?

| Starting from | Guide | Time |
|---|---|---|
| **Nothing — empty subscription** | **[SETUP.md](SETUP.md)** — 21 numbered steps, every click and command, with a verification gate after each | 2-3 hrs |
| Prerequisites already met | [QUICKSTART.md](QUICKSTART.md) | 45 min |
| Something is broken | [docs/07-troubleshooting.md](docs/07-troubleshooting.md) | - |

Deep-dive references: [Databricks setup](docs/02-databricks-setup.md) ·
[Azure AI Foundry](docs/03-foundry-setup.md) · [all docs](docs/README.md)

---

## Repository layout

```
SETUP.md       Complete setup from an empty subscription - start here
QUICKSTART.md  45-minute path when prerequisites are already met
docs/          Setup, architecture, detection internals, troubleshooting
sql/           Stage 1 — demo data, detection views, preventive controls
notebooks/     Stage 2 scorers (3 variants) + the PySpark attacker notebook
runbooks/      11 presenter-ready demo scripts with talk-track
reference/     The LLM prompt and verdict schema
deployment/    Optional Event Hub + Function App path for SOC ownership
```

### Which scorer?

| Notebook | Scores | Use when |
|---|---|---|
| `scorer_01_sql.py` | `v_pii_candidates` | SQL warehouse statements only |
| `scorer_02_multihop.py` | `v_pii_candidates_mh` | + laundering through derived tables |
| **`scorer_03_spark.py`** | `v_pii_candidates_all` | **+ notebooks and storage paths — recommended** |

Each requires its corresponding SQL file to have been run first.

---

## Privacy and data handling

**No PII values leave Databricks at any point.** The model receives metadata only:

| Sent to the model | Never sent |
|---|---|
| SQL text (where it exists) | Any row of data |
| Column and table **names** | Any column **value** |
| The column-to-column lineage map | File contents |
| Row counts, rule signals, target type | Credentials |

A reassembled phone number is detected **without the detector ever reading one**. Full detail in
[docs/08-privacy.md](docs/08-privacy.md).

> **Note on system tables.** Databricks advises care when moving system-table data off-platform,
> as it can expose sensitive operational information. This solution keeps Stage 1 entirely inside
> Databricks and sends only the metadata envelope above to Foundry.

---

## Detection is the net, not the fence

The strongest control here is not detection. It is **column masking**
([sql/04_preventive_controls.sql](sql/04_preventive_controls.sql)): with a mask in place, a
temporary-access user never sees raw values, so every obfuscation technique operates on
already-masked data. For storage writes, **external locations and storage credentials** control
whether a path can be written at all.

Run detection for the residual — legitimate volumes, permitted external locations, and the gap
between a grant being issued and being revoked.

---

## Known limitations

Stated plainly, because they will come up:

- **UC-governed compute only.** No lineage from non-UC clusters or writes made outside Databricks.
- **No source code for notebook events.** Databricks records no statement text for the DataFrame
  API, so regex rules cannot fire there — detection becomes structural, reasoning about the column
  map. (Verbose audit logging can recover command text; it is off by default and is a log-volume
  decision.)
- **Retention.** Lineage ~1 year; query history ~90 days.
- **Capture lag.** Documented as up to ~1 hour; typically minutes in practice.
- **Hop depth is fixed at 3** in the multi-hop closure. Extend it for deeper pipelines —
  [docs/04](docs/04-multihop-lineage.md) explains how.

---

## License

MIT — see [LICENSE](LICENSE). Provided as a reference implementation and demonstration kit, not as
a supported Microsoft product. Validate against your own environment and security requirements
before any production use.

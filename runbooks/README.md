# Demo runbooks

Eleven presenter-ready scripts. **Pick one per session** — they are alternatives, not a sequence.

Every runbook follows the same shape, so you can pick any one up cold:

```
Pre-flight → Fire the attack → Narrative (fills the lineage lag) →
Unity Catalog UI walkthrough → Lineage poll → Live detection →
Closer (prevention) → Privacy → Safety nets → Timing table
```

**Attack table names are unique across all eleven**, so any combination can be run back to back
with no collisions.

---

## `sql-queries/` — the insider writes SQL

Six variants, three attack categories each. Requires `sql/03_detection.sql`.

| Runbook | Category 1 | Category 2 | Category 3 |
|---|---|---|---|
| `runbook-0-baseline.md` | cipher + reversal | arithmetic offset | JSON packing |
| `runbook-1.md` | hex encode + split | base conversion | per-char explosion |
| `runbook-2.md` | rearrange + rename | array packing | quasi-identifier |
| `runbook-3.md` | base64 | lpad/rpad padding | concat filler |
| `runbook-4.md` | map packing | a VIEW target | bulk `SELECT *` |
| `runbook-5.md` | **unsalted hash** | regex spacing | ASCII codepoints |

**Start with `runbook-0-baseline.md`** if this is your first run.
**`runbook-5.md`** is the strongest for a sceptical audience — the unsalted hash scores
`SUSPICIOUS`, not maximum, which proves the model reasons about entropy rather than pattern-matching
the word `sha2`.

## `derived-tables/` — the insider launders through untagged tables

Four variants. Requires `sql/05_multihop_lineage.sql`.

| Runbook | Theme | Max depth |
|---|---|---|
| `runbook-1.md` | The patient insider: staging table, then the disguise | hop 2 |
| `runbook-2.md` | Views, joins and **reassembly** | hop 1 |
| `runbook-3.md` | **The deep chain** — four levels, fan-in branches | **hop 3** |
| `runbook-4.md` | **Pipeline mimicry** — a fake bronze/silver/gold chain | hop 2 |

**`runbook-2.md`** has the single strongest moment in the kit: split a phone three ways, then
`concat` it back days later in a statement that mentions no PII column and no PII table.

**`runbook-3.md`** is the one to run if you need to *show* `source_hop = 2` and `3` on screen.

**`runbook-4.md`** suits a data-governance audience — it argues for the allowlist as the real
control, rather than for pattern matching.

## `spark-notebooks/` — the insider uses Python or Scala

Requires `sql/06_notebook_spark_detection.sql`.

| Runbook | Covers |
|---|---|
| `runbook-1.md` | PySpark + Scala writing Parquet/CSV/JSON to ADLS, plus DataFrame table writes |

Run this one when someone says *"but we use notebooks, not SQL."* It opens by proving the SQL-only
detector returns **zero**, then shows all six events caught.

---

## Choosing for your audience

| Audience | Runbook | Why |
|---|---|---|
| First demo, any audience | `sql-queries/runbook-0-baseline.md` | Simplest complete story |
| Security / SOC | `sql-queries/runbook-5.md` | Entropy reasoning, nuanced verdicts |
| Data governance / platform | `derived-tables/runbook-4.md` | Argues for declared pipelines |
| Sceptical engineers | `derived-tables/runbook-2.md` | Reassembly is hard to dismiss |
| "We use Python" | `spark-notebooks/runbook-1.md` | Answers it head-on |

## Running two back to back

Safe — table names do not collide. Sequence that builds well:

1. `sql-queries/runbook-0-baseline.md` — establish the mechanism
2. `derived-tables/runbook-3.md` — show it survives laundering, with visible `hop 3`
3. `spark-notebooks/runbook-1.md` — show it is not only SQL

Budget ~25 minutes each including the lineage wait.

## A note on timing

Every runbook puts the slide narrative **between** firing the attack and querying detection. That
is deliberate — it fills the lineage capture lag with content rather than silence. Do not skip
ahead; you will be waiting on screen.

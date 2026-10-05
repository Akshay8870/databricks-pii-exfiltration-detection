# Detection internals

## Stage 1: the view chain

```
v_pii_columns          which columns are PII          ← driven by TAGS, never hard-coded names
       ↓
v_pii_write_events     lineage ∩ tagged columns       ← the ground truth join
       ↓
v_pii_candidates       + statement text + rules       ← what Stage 2 scores
```

### The join that does the work

```sql
FROM system.access.column_lineage cl
JOIN security.v_pii_columns p
  ON  p.table_full_name = cl.source_table_full_name
  AND p.column_name     = cl.source_column_name
WHERE cl.target_table_full_name IS NOT NULL
```

In English: *every statement where a column tagged as PII was used to write something new.*
Deterministic — no LLM, so no false negative from a clever disguise.

### Tag-driven by design

`v_pii_columns` reads `system.information_schema.column_tags` and keys on
`data_sensitivity IN ('pii_direct','pii_quasi')`. Onboarding a new table is a **tagging exercise,
not a code change**.

```sql
ALTER TABLE gold.customer_master ALTER COLUMN phone_number
  SET TAGS ('data_sensitivity'='pii_direct','pii_type'='phone');
```

> Unity Catalog does **not** require pre-creating tag keys. `SET TAGS` creates them implicitly.
> The `CREATE TAG` DDL belongs to the separate governed-tags feature and raises
> `PARSE_SYNTAX_ERROR` on many workspaces.

## The rule set

Each rule contributes 10 points and a human-readable reason. `rule_score` is the **floor** the
model may raise but never lower.

| Rule | Signal |
|---|---|
| `column_fanout` | One PII column → several target columns |
| `string_slicing` | `substr`, `split_part`, `reverse`, `lpad`, `rpad` … |
| `encoding` | `base64`, `hex`, `unhex`, `aes_encrypt` … |
| `concatenation` | `concat`, `concat_ws`, `\|\|` |
| `packing` | `named_struct`, `to_json`, `map`, `collect_list` … |
| `explosion` | `posexplode`, `explode` |
| `no_hashing` | No one-way function anywhere in the statement |
| `bulk_extract` | Near-full-table volume, no meaningful filter |
| `view_target` | Persisted as a view |
| `derived_source` | Multi-hop layer — reached via untagged tables |
| `laundering_chain` | Multi-hop layer — two or more intermediate tables |
| `column_rename` · `path_target` · `bulk_path_export` · `notebook_source` | Notebook layer |

## Stage 2: the evidence envelope

**Only metadata is sent.** No row of data, ever.

| Field | Notes |
|---|---|
| `sql` | NULL for notebook events |
| `column_map` | `source_col -> target_col` pairs — primary evidence when there is no SQL |
| `actor`, `source_tables`, `pii_source_columns`, `pii_types` | names only |
| `target_object`, `target_type`, `target_columns` | |
| `target_is_storage_path` | PATH targets escape UC controls |
| `source_hop`, `pii_origin_columns` | multi-hop layer |
| `rows_read`, `rows_written`, `filter_present` | |
| `deterministic_signals` | the rule reasons above |

## The verdict schema

| Field | Meaning |
|---|---|
| `verdict` | `LIKELY_EXFILTRATION` · `SUSPICIOUS` · `BENIGN` |
| `risk_score` | 0–100 |
| `confidence` | 0–1 |
| `recoverable` | Can the original value be reconstructed? |
| `reversibility_class` | see below |
| `technique[]` | What was done |
| `pii_types[]` | What kind of PII |
| `reidentification_by_combination` | Quasi-identifiers that together identify a person |
| `evidence_expression` | The specific expression the verdict rests on |
| `rationale` | Why — in plain language |
| `recommended_action` | What the admin should do |

### Reversibility classes

| Class | Meaning | Example |
|---|---|---|
| `trivially_invertible` | Reverse with no secret | split then `concat` |
| `public_encoding` | A public transform | `base64`, `hex` |
| `exposed_secret` | Key visible in the statement | `aes_encrypt(col,'literal')` |
| `lookup_reversible` | Needs a mapping table that exists | surrogate key + map |
| `weak_oneway_low_entropy` | One-way, but small input space | unsalted phone hash |
| `strong_oneway` | Secret-salted, large space | `sha2(concat(col, secret))` |
| `aggregate_only` | No individual recoverable | `count(*) GROUP BY city` |

`weak_oneway_low_entropy` is the class that earns the approach. A 10-digit phone has ~10¹⁰
possibilities — trivially brute-forced against an unsalted hash. The model flags it **SUSPICIOUS**
where a rule engine would see "a hash" and pass it.

## Nuanced verdicts worth demonstrating

| Case | Verdict | Why it matters |
|---|---|---|
| Unsalted hash | SUSPICIOUS ~68–83 | Looks like de-identification, is not |
| Quasi-identifier cohort | SUSPICIOUS, `reidentification_by_combination = true` | A different class from extraction |
| Secret-salted hash | **BENIGN** ~12 | Proves it does not scream at everything |

A detector that scores everything maximum gets muted. Show at least one BENIGN.

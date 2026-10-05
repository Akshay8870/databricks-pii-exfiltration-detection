# SQL

Run in numeric order. Each file is **additive** and safe to re-run — every object is
`CREATE OR REPLACE`.

| File | Creates | Required? |
|---|---|---|
| `sql/01_setup_demo_data.sql` | Demo PII table + **column tags** | Yes — the tags drive everything |
| `sql/02_attacker_playbook.sql` | The attack statements | Demo only |
| `sql/03_detection.sql` | Stage 1 views: `v_pii_columns` → `v_pii_write_events` → `v_pii_candidates` | **Yes** |
| `sql/04_preventive_controls.sql` | Column masks, row filters | Recommended — this is the real control |
| `05_multihop_lineage.sql` | `v_pii_candidates_mh` — laundering through derived tables | Recommended |
| `06_notebook_spark_detection.sql` | `v_pii_candidates_all` — notebooks + storage paths | Recommended |
| `07_live_detection_test.sql` | Verification queries | Optional |
| `08_more_sample_queries.sql` | Extra attack variants | Optional |

## Before you run anything

These files use `pii_demo` as the catalog. **Change it to match your environment** — it appears in
`USE CATALOG` at the top of each file and in fully-qualified references.

```bash
# from the repo root
grep -rl 'pii_demo' sql/ notebooks/ | xargs sed -i 's/pii_demo/<your_catalog>/g'
```

## Which candidate view should I use?

| View | Covers |
|---|---|
| `v_pii_candidates` | SQL warehouse statements, tagged sources only |
| `v_pii_candidates_mh` | + laundering through untagged derived tables |
| **`v_pii_candidates_all`** | **+ notebooks, jobs, and cloud-storage path targets** |

Use `v_pii_candidates_all` in production. The narrower two are kept because showing the base
detector *miss* something is an effective demo beat.

## Production note

The shipped views carry **no time window** — they scan all available history, which is correct for
a demo but expensive on a busy tenant. Add a bound to the `q` CTE and the lineage filter:

```sql
AND start_time >= current_timestamp() - INTERVAL 30 DAYS
AND event_date >= current_date()      - INTERVAL 30 DAYS
```

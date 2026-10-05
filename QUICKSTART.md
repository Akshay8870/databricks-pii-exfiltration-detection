# Quickstart

A working demo in about 45 minutes, assuming the prerequisites are met.

**Not met yet?** Use **[SETUP.md](SETUP.md)** instead — the full 21-step build from an empty
subscription, with a verification gate after every step. Check what you need against
[docs/01-prerequisites.md](docs/01-prerequisites.md).

---

## 1 · Set your catalog name (2 min)

The repo ships with `pii_demo` as the catalog. Change it everywhere:

```bash
grep -rl 'pii_demo' sql/ notebooks/ | xargs sed -i 's/pii_demo/<your_catalog>/g'
```

On macOS use `sed -i ''` instead of `sed -i`.

## 2 · Create the demo data and tags (5 min)

Run `sql/01_setup_demo_data.sql` in a SQL warehouse.

Verify the tags landed — **nothing works without them**:
```sql
SELECT column_name, tag_name, tag_value
FROM   system.information_schema.column_tags
WHERE  catalog_name = '<your_catalog>';
```
Expect **7 tagged columns**.

## 3 · Build the detection views (5 min)

Run in order:
```
sql/03_detection.sql                 Stage 1
sql/05_multihop_lineage.sql          + derived-table laundering
sql/06_notebook_spark_detection.sql  + notebooks and storage paths
```

Verify:
```sql
SELECT count(*) FROM <your_catalog>.security.v_pii_candidates_all;   -- must not error
```
Zero rows is correct at this point — nothing has been attacked yet.

## 4 · Configure the scorer (10 min)

Import `notebooks/scorer_03_spark.py` as a notebook. Fill in the config block, then run **only the
auth cell** and confirm the smoke test returns **200**.

> **Do not proceed past a non-200.** Every later failure becomes harder to diagnose.
> [docs/03-foundry-setup.md](docs/03-foundry-setup.md) has the response-code table.

## 5 · Fire the attacks (2 min)

Run `sql/02_attacker_playbook.sql`.

For the notebook variant, import and run `notebooks/attacker_pyspark.py` on a **UC-governed
cluster** (access mode Shared or Single User — on a non-UC cluster no lineage is produced at all).

## 6 · Wait for lineage (5–15 min)

Documented as up to an hour; usually minutes.

```sql
SELECT count(*) FROM system.access.column_lineage
WHERE event_date = current_date();
```

This wait is why every runbook puts the slide narrative here.

## 7 · See Stage 1 working

```sql
SELECT target_object, target_type, entity_type, rule_score, rule_reasons
FROM   <your_catalog>.security.v_pii_candidates_all
ORDER BY rule_score DESC;
```

## 8 · Run Stage 2 (5 min)

Run `notebooks/scorer_03_spark.py` in full. Keep `ONLY_TODAY = True`.

Expected shape of the output:

| Target | Verdict | Why |
|---|---|---|
| split / padded / encoded tables | LIKELY_EXFILTRATION 90+ | Trivially reversible |
| unsalted hash | **SUSPICIOUS ~70–85** | Weak one-way, low entropy |
| quasi-identifier cohort | **SUSPICIOUS** | Re-identification by combination |
| secret-salted hash | **BENIGN ~12** | Genuinely strong one-way |

**If everything scores 95+, something is wrong** — check the salted-hash example is using a real
secret from the `pii_demo` scope. The nuanced verdicts are the point.

---

## Next

- Pick a presenter script: [runbooks/README.md](runbooks/README.md)
- Show the preventive control: `sql/04_preventive_controls.sql` — masking removes the attack class
  entirely, and is a stronger story than detection
- Something broken: [docs/07-troubleshooting.md](docs/07-troubleshooting.md)

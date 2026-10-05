# Troubleshooting

Every entry here was hit in a real deployment. Start with the symptom.

---

## Setup

### "Manage account" does not appear in the workspace

Not a Databricks setting — an **Entra ID** elevation. See
[02-databricks-setup.md](02-databricks-setup.md#getting-account-admin). Remember to turn the
root-scope toggle back off afterwards.

### `CREATE TAG` fails with `PARSE_SYNTAX_ERROR`

Expected on most workspaces. Unity Catalog does not require pre-creating tag keys — `ALTER TABLE …
SET TAGS` creates them implicitly. The `CREATE TAG` DDL belongs to the separate governed-tags
feature. Remove it.

### 403 enabling a system schema

If the schema already reports `MANAGED`, it is already enabled and the 403 is harmless. Confirm
with:
```bash
databricks api get /api/2.1/unity-catalog/metastores/<metastore-id>/systemschemas
```

### `statement_text` returns `<REDACTED>`

The reading identity is not an account admin and is not in a group granted access. See
[01-prerequisites.md](01-prerequisites.md#4-unredacted-statement-text).

---

## Foundry / model calls

### `403 AuthenticationTypeDisabled`

Key auth is disabled on the resource by policy. Switch to the Entra ID service-principal path —
[03-foundry-setup.md](03-foundry-setup.md).

### `403 PermissionDenied` on the model call

Two causes, both common:
1. **Only one role assigned.** You need **both** `Cognitive Services OpenAI User` **and**
   `Cognitive Services User` on the Foundry resource.
2. **RBAC has not propagated.** Wait 5–15 minutes.

### `400` mentioning `temperature` or `max_tokens`

You are calling a **reasoning model** with chat-model parameters. Use `max_completion_tokens`, add
`reasoning_effort`, and **do not send** `temperature` or `top_p`.

### `JSONDecodeError: Expecting value`

The server returned HTML or an empty body, not JSON. Almost always an **unfilled `<placeholder>`**
in the config block making the URL malformed. Check `TENANT_ID`, `CLIENT_ID`, `FOUNDRY_HOST`,
`DEPLOYMENT`. Also run cells in order — a stale `CHAT_URL` from a previous session does this too.

The shipped notebooks raise a readable error instead of this. If you see the raw exception, you are
on an older copy.

### A single `500` on one candidate while others succeed

A transient Foundry blip. The shipped scorers retry `429/5xx` three times with backoff, and fail
fast on `400/401/403` (which are your fault, not the service's). The run summary names anything
still unscored — re-running is safe.

---

## Lineage

### Nothing in lineage at all

**The cluster is almost certainly not UC-governed.** Check the access mode is **Shared** or
**Single User**, not No-isolation. Everything runs fine on a non-UC cluster and produces no lineage
whatsoever.

### Lineage is late

Documented as up to ~1 hour; typically minutes. Deep chains land **progressively** — hop 1 must
exist before hop 2 resolves. The views are live, so just re-query; never re-run the SQL files.

### Path poll returns 0 but lineage clearly works

> **This one catches everyone once.**

Databricks records a Volume path as **`dbfs:/Volumes/...`**, not `/Volumes/...`. A real ADLS target
may be recorded as the resolved storage URL rather than the string you passed to `.write()`. A
`LIKE '/Volumes/...%'` pattern anchored at the start cannot match.

**Always lead with `%`:**
```sql
SELECT count(DISTINCT target_path) FROM system.access.column_lineage
WHERE target_path LIKE '%exfil_vol%' AND event_date = current_date();
```

Or inspect what actually landed:
```sql
SELECT DISTINCT target_path, target_type, entity_type
FROM   system.access.column_lineage
WHERE  event_date = current_date() AND target_path IS NOT NULL;
```

**This only ever affects manual queries.** The detection views key on
`coalesce(target_table_full_name, target_path)` and never filter on path text.

### A table-name filter finds nothing for a file write

Path targets have a **NULL `target_table_full_name`**. Filter on `target_path`.

### Only `hop 0` rows in the multi-hop view

Either hop-1 lineage has not landed yet (wait, re-query), or the chain genuinely is only one level
deep. `source_hop = 2` requires a table reading from a table that reads from a table that reads
from the tagged source.

Note `source_hop` reports the **shortest** path — a column reachable both 1 and 3 hops back reports
`1`. Deliberate.

---

## Detection results

### `rule_score` is NULL

An old build using `array_remove(array(...), NULL)`. Use
`filter(array(...), x -> x IS NOT NULL)` — `array_remove` does not strip NULLs the way it appears
to. Fixed in the shipped SQL.

### The same table appears several times

Add the dedup the shipped views use:
```sql
QUALIFY row_number() OVER (PARTITION BY target_table
                           ORDER BY size(rule_reasons) DESC, start_time DESC) = 1
```

### The candidate list keeps growing between runs

The detection views carry **no time window**, so every attack table ever created stays in scope.
For a demo set `ONLY_TODAY = True` in the scorer. For production, add a window to the `q` CTE.

### The scorer re-scores everything each run

By design — re-running is always safe, and a prompt change re-scores cleanly. The display query
keeps only the newest verdict per statement. For true incremental, filter on:
```sql
statement_id NOT IN (SELECT statement_id FROM <catalog>.security.pii_query_verdicts)
```
Turn that off whenever you change the prompt or rules, or old verdicts never refresh.

### A verdict seems too low

Check whether it is actually correct. An unsalted hash **should** be `SUSPICIOUS`, not
`LIKELY_EXFILTRATION`. A quasi-identifier cohort **should** carry
`reidentification_by_combination`. A secret-salted hash **should** be `BENIGN`. Nuance is the
feature.

If a genuinely recoverable case scores low and the source came through derived tables, confirm the
scorer is sending `pii_origin_columns` — without it the model reasons about the innocuous
intermediate name.

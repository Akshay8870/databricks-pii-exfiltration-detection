# Privacy and data handling

## The guarantee

**No PII values leave Databricks at any point in this solution.**

Stage 1 runs entirely inside Databricks against system tables. Stage 2 sends a **metadata
envelope** to Azure AI Foundry.

| Sent to the model | Never sent |
|---|---|
| SQL statement text (where it exists) | Any row of data |
| Column **names** | Any column **value** |
| Table and path **names** | File contents |
| The column-to-column lineage map | Credentials or secrets |
| Row counts (`read_rows`, `written_rows`) | Sample or preview rows |
| Rule signal strings | |
| `source_hop`, `pii_origin_columns` (names) | |
| `target_type`, notebook/job identifiers | |

A reassembled phone number is detected **without the detector reading one**. The verdict rests
entirely on the structure of the statement and the shape of the lineage graph.

### Where to verify this yourself

The envelope is constructed in exactly two places — read them, do not take this on trust:

- `sql/03_detection.sql` — the `v_pii_llm_input` view
- `notebooks/scorer_*.py` — the `ev = {...}` dict inside `score()`

If a field is not in those two places, it is not sent.

## One caveat to state honestly

**SQL statement text can itself contain data.** A statement like:

```sql
SELECT * FROM customer_master WHERE phone_number = '9764445335'
```

embeds a PII value as a literal, and that text *is* part of the envelope for warehouse statements.

Options if this matters in your environment:
- Redact literals from `statement_text` before building the envelope (regex on quoted strings and
  long digit runs)
- Omit `sql` entirely and rely on `column_map` plus the rule signals — this is exactly how notebook
  events are already scored, so it is a proven path

Notebook events have no statement text at all, so they are unaffected.

## System table handling

Databricks advises care when moving system-table data off-platform, since it can expose sensitive
operational information. This solution:

- Keeps Stage 1 **entirely inside** Databricks
- Sends only the metadata envelope above to Foundry
- Writes verdicts back to a Delta table **inside** Unity Catalog

No system-table bulk export is required at any point.

## Data residency

Choose a Foundry region consistent with your data-residency obligations. The envelope crosses from
Databricks to Foundry over HTTPS; model calls are subject to the Azure OpenAI data-handling terms
for your resource. For regulated workloads, confirm the regional pairing with your compliance team
before enabling.

## Access control

- **Secrets** live in Databricks secret scopes, never in a notebook
- The **verdicts table** contains statement text and column names — grant it like a security
  artefact, not a general analytics table
- The detector identity needs unredacted `statement_text`, which is a privileged read: use a
  dedicated service principal in a named group rather than a personal account admin

## Retention

| Store | Retention |
|---|---|
| `system.access.column_lineage` / `table_lineage` | ~1 year (rolling) |
| `system.query.history` | ~90 days |
| `security.pii_query_verdicts` | yours — set a retention policy to match your IR requirements |

Note that **dropping a table does not erase its lineage**. An insider who deletes their tracks
leaves the lineage record intact — a genuinely useful property worth pointing out.

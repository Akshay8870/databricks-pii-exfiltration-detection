# Multi-hop lineage: catching laundering through derived tables

**File:** `sql/05_multihop_lineage.sql`

## The gap this closes

Unity Catalog does **not propagate tags to derived tables**. `v_pii_columns` reads
`system.information_schema.column_tags`, which contains only columns someone explicitly tagged.
Stage 1's join therefore only matches when the **source** column is tagged:

```
gold.customer_master  →  sandbox.stg_x     CAUGHT   (source is tagged)
sandbox.stg_x         →  sandbox.final_x   MISSED   (source carries no tag)
```

A patient insider exploits exactly this: create one boring-looking staging table today, wait, then
do the real disguise *from that table* where no column carries a tag.

**This is not a flaw in these rules.** It is what happens to every tag-driven control the moment
data moves one table sideways — worth saying plainly to a governance audience.

## The fix

A **transitive closure** over `column_lineage`, three hops deep, implemented as bounded self-joins
(`h0 → h1 → h2 → h3`) rather than `WITH RECURSIVE` so it runs on every DBR and warehouse version.

| Step | Computes |
|---|---|
| `h0` | The explicitly tagged columns — the seed set |
| `h1` | Every column written *from* an `h0` column |
| `h2` | Every column written from an `h1` column |
| `h3` | One level deeper again |

The union keeps the **shortest** path to each column:

```sql
QUALIFY row_number() OVER (PARTITION BY table_full_name, column_name
                           ORDER BY hop ASC) = 1
```

So a column reachable both 1 and 3 hops back reports `hop 1`. Deliberate and conservative — it
never overstates distance.

## The two fields it produces

| Field | Meaning |
|---|---|
| `source_hop` | Distance from the tag. `0` = read the tagged table directly. `≥1` = the immediate source carries no tag. |
| `pii_origin_columns` | The **original tagged column**, however many hops back. |

**The second is the load-bearing one.** The scorer's prompt tells the model to judge recoverability
against `pii_origin_columns`, **not** the immediate source column name. Without that, the model
sees a source column called `contact_ref` or `seg_a` — deliberately innocuous — and softens its
verdict. With it, the model knows it is reasoning about `phone_number` whatever the intermediate
chose to call it.

> The closure restores the classification the tag lost; the origin field restores the context the
> rename destroyed.

## New rule signals

| Signal | Fires when |
|---|---|
| `derived_source` | `source_hop >= 1` — PII reached this table indirectly |
| `laundering_chain` | `source_hop >= 2` — two or more intermediate tables |

Depth becomes **evidence**, not a mitigating factor: real pipelines are documented and declared,
laundering chains are not.

## Views created

```
v_pii_columns_transitive   tagged columns + every descendant, with hop + origin
v_pii_write_events_mh      lineage joined to the closure instead of raw tags
v_pii_candidates_mh        + query text + rules + the two new signals
```

Run after `sql/03_detection.sql`. Purely additive — creates views, changes nothing existing, safe
to re-run.

## Changing the depth

Copy the `h3` block to an `h4` and add it to the `allhops` UNION. A six-level pipeline needs a
six-level closure — say so plainly rather than implying the default covers everything.

## Production note

The shipped version has **no time window**, so it scans all of `query.history`. Fine for a demo;
on a busy tenant add a bound to the `q` CTE and the `edges` CTE:

```sql
AND start_time >= current_timestamp() - INTERVAL 30 DAYS   -- q CTE
AND event_date >= current_date()      - INTERVAL 30 DAYS   -- edges CTE
```

## Finding reassembly

Targets where several source columns descend from **one** origin column — i.e. something was put
back together:

```sql
SELECT cl.target_table_full_name AS target_table,
       cl.target_column_name     AS target_column,
       count(DISTINCT cl.source_column_name) AS parts_combined,
       collect_set(p.origin_column)          AS origin
FROM   system.access.column_lineage cl
JOIN   <catalog>.security.v_pii_columns_transitive p
  ON   p.table_full_name = cl.source_table_full_name
  AND  p.column_name     = cl.source_column_name
WHERE  cl.target_table_full_name IS NOT NULL
GROUP BY 1,2
HAVING count(DISTINCT cl.source_column_name) > 1
   AND size(collect_set(p.origin_column)) = 1
ORDER BY parts_combined DESC;
```

A row returning `parts_combined = 3` against origin `phone_number` is a **reconstructed phone
number** — found without reading a single data value.

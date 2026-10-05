-- =====================================================================
-- sql/05_multihop_lineage.sql
-- WHY THIS FILE EXISTS
-- --------------------
-- Stage 1 (sql/03_detection.sql) joins column_lineage to v_pii_columns, which
-- reads system.information_schema.column_tags. That only contains columns
-- someone EXPLICITLY tagged -- i.e. the columns of gold.customer_master.
--
-- Unity Catalog does NOT propagate tags to derived tables. So:
--
--   hop 1  gold.customer_master  ->  sandbox.stg_x     CAUGHT   (source is tagged)
--   hop 2  sandbox.stg_x         ->  sandbox.final_x   MISSED   (source is NOT tagged)
--
-- A patient insider exploits exactly this: make one boring-looking derived
-- table, wait, then do the real disguise from THAT table. This file closes
-- the hole by walking column_lineage transitively, so every descendant of a
-- tagged PII column is itself treated as PII for detection purposes.
--
-- Run this AFTER sql/03_detection.sql. It adds views, changes nothing existing.
-- =====================================================================
USE CATALOG pii_demo;

-- ---------------------------------------------------------------------
-- A. Transitive PII closure: tagged columns + everything descended from
--    them, up to 3 hops. Bounded self-joins (no WITH RECURSIVE) so this
--    runs on every DBR / SQL warehouse version.
--    Raise to 4-5 hops if the customer's real pipelines are deeper.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_pii_columns_transitive AS
WITH edges AS (
  SELECT DISTINCT
    source_table_full_name AS src_tbl, source_column_name AS src_col,
    target_table_full_name AS tgt_tbl, target_column_name AS tgt_col
  FROM system.access.column_lineage
  WHERE source_table_full_name IS NOT NULL
    AND target_table_full_name IS NOT NULL
    AND source_column_name    IS NOT NULL
    AND target_column_name    IS NOT NULL
    AND source_table_full_name <> target_table_full_name   -- ignore self-writes
),
h0 AS (   -- hop 0 = the columns an admin actually tagged
  SELECT table_full_name, column_name, pii_type, 0 AS hop,
         table_full_name AS origin_table, column_name AS origin_column
  FROM security.v_pii_columns
),
h1 AS (
  SELECT e.tgt_tbl, e.tgt_col, h0.pii_type, 1 AS hop, h0.origin_table, h0.origin_column
  FROM h0 JOIN edges e ON e.src_tbl = h0.table_full_name AND e.src_col = h0.column_name
),
h2 AS (
  SELECT e.tgt_tbl, e.tgt_col, h1.pii_type, 2 AS hop, h1.origin_table, h1.origin_column
  FROM h1 JOIN edges e ON e.src_tbl = h1.tgt_tbl AND e.src_col = h1.tgt_col
),
h3 AS (
  SELECT e.tgt_tbl, e.tgt_col, h2.pii_type, 3 AS hop, h2.origin_table, h2.origin_column
  FROM h2 JOIN edges e ON e.src_tbl = h2.tgt_tbl AND e.src_col = h2.tgt_col
),
allhops AS (
  SELECT table_full_name, column_name, pii_type, hop, origin_table, origin_column FROM h0
  UNION ALL SELECT tgt_tbl, tgt_col, pii_type, hop, origin_table, origin_column FROM h1
  UNION ALL SELECT tgt_tbl, tgt_col, pii_type, hop, origin_table, origin_column FROM h2
  UNION ALL SELECT tgt_tbl, tgt_col, pii_type, hop, origin_table, origin_column FROM h3
)
SELECT table_full_name, column_name, pii_type, hop, origin_table, origin_column
FROM allhops
-- keep the SHORTEST path to each column (a column reachable 1 and 3 hops away is hop 1)
QUALIFY row_number() OVER (PARTITION BY table_full_name, column_name
                           ORDER BY hop ASC) = 1;

-- Sanity check: what did the closure discover beyond the tagged columns?
-- SELECT * FROM security.v_pii_columns_transitive WHERE hop > 0 ORDER BY hop, table_full_name;


-- ---------------------------------------------------------------------
-- B. Write events, multi-hop aware. Same shape as v_pii_write_events so
--    everything downstream keeps working -- only the join source changed,
--    plus two new columns: source_hop and pii_origin_columns.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_pii_write_events_mh AS
SELECT
  cl.statement_id,
  cl.created_by                                        AS actor,
  min(cl.event_time)                                   AS event_time,
  max(cl.target_table_full_name)                       AS target_table,
  max(cl.target_type)                                  AS target_type,
  collect_set(cl.source_table_full_name)               AS source_tables,
  collect_set(concat(cl.source_table_full_name,'.',cl.source_column_name)) AS pii_source_columns,
  -- NEW: where the data ORIGINALLY came from, however many hops back
  collect_set(concat(p.origin_table,'.',p.origin_column)) AS pii_origin_columns,
  collect_set(p.pii_type)                              AS pii_types,
  collect_set(cl.target_column_name)                   AS target_columns,
  count(DISTINCT cl.target_column_name)                AS target_col_count,
  count(DISTINCT cl.source_column_name)                AS pii_col_count,
  -- NEW: 0 = read straight from the tagged table, >=1 = laundered via derived tables
  max(p.hop)                                           AS source_hop
FROM system.access.column_lineage cl
JOIN security.v_pii_columns_transitive p
  ON  p.table_full_name = cl.source_table_full_name
  AND p.column_name     = cl.source_column_name
WHERE cl.target_table_full_name IS NOT NULL
  AND cl.target_table_full_name <> cl.source_table_full_name
GROUP BY cl.statement_id, cl.created_by;


-- ---------------------------------------------------------------------
-- C. Candidates, multi-hop aware. Identical rule set to v_pii_candidates
--    plus TWO new signals that only exist in the multi-hop world.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_pii_candidates_mh AS
WITH q AS (
  SELECT statement_id, workspace_id, executed_by, statement_type, statement_text,
         start_time, read_rows, produced_rows, written_rows, client_application
  FROM   system.query.history
  WHERE  execution_status = 'FINISHED'
),
j AS (
  SELECT e.*, q.workspace_id, q.executed_by, q.statement_type, q.statement_text,
         q.start_time, q.read_rows, q.produced_rows, q.written_rows, q.client_application
  FROM   security.v_pii_write_events_mh e
  LEFT JOIN q ON q.statement_id = e.statement_id
),
scored AS (
  SELECT j.*,
    filter(array(
      CASE WHEN target_col_count > pii_col_count
           THEN 'column_fanout: one PII column expanded into multiple target columns' END,
      CASE WHEN lower(statement_text) RLIKE '(substr|substring|left\\(|right\\(|split_part|regexp_extract|translate|reverse|lpad|rpad)'
           THEN 'string_slicing: substring/split/reverse style manipulation of a PII column' END,
      CASE WHEN lower(statement_text) RLIKE '(base64|unbase64|hex\\(|unhex|encode\\(|decode\\(|aes_encrypt)'
           THEN 'encoding: reversible encoding used instead of hashing' END,
      CASE WHEN lower(statement_text) RLIKE '(concat|concat_ws|\\|\\|)'
           THEN 'concatenation: PII glued to padding characters or to other columns' END,
      CASE WHEN lower(statement_text) RLIKE '(named_struct|to_json|map\\(|array\\(|collect_list|collect_set)'
           THEN 'packing: PII nested inside a struct/map/json column' END,
      CASE WHEN lower(statement_text) RLIKE '(posexplode|explode\\()'
           THEN 'explosion: PII broken into one row per character/element' END,
      CASE WHEN NOT lower(statement_text) RLIKE '(sha1|sha2|md5|crc32|xxhash64|mask\\()'
           THEN 'no_hashing: PII moved without any one-way function' END,
      CASE WHEN produced_rows >= 0.9 * greatest(read_rows,1) AND read_rows > 1000
           THEN 'bulk_extract: near-full-table volume, no meaningful filter' END,
      CASE WHEN target_type = 'VIEW'
           THEN 'view_target: result persisted as a view rather than a table' END,
      -- ===== NEW multi-hop signals =====
      CASE WHEN source_hop >= 1
           THEN concat('derived_source: PII reached this table indirectly, ', cast(source_hop AS STRING),
                       ' hop(s) from the tagged column - the source table itself carries no tag') END,
      CASE WHEN source_hop >= 2
           THEN 'laundering_chain: two or more intermediate tables between the tagged column and this write' END
    ), x -> x IS NOT NULL) AS rule_reasons
  FROM j
)
SELECT
  statement_id, workspace_id, actor AS executed_by, statement_type, statement_text,
  coalesce(start_time, event_time) AS start_time,
  read_rows, produced_rows, written_rows,
  source_tables, target_table, target_type,
  pii_source_columns, pii_origin_columns, pii_types, target_columns,
  pii_col_count, target_col_count, source_hop,
  size(rule_reasons) * 10 AS rule_score,
  rule_reasons
FROM scored
WHERE target_table NOT IN (SELECT target_table_full_name FROM security.pii_transform_allowlist)
QUALIFY row_number() OVER (PARTITION BY target_table
                           ORDER BY size(rule_reasons) DESC, start_time DESC) = 1;


-- ---------------------------------------------------------------------
-- D. The chain, rendered for a human. Run this on stage -- it is the
--    single most convincing output in the multi-hop demo.
-- ---------------------------------------------------------------------
SELECT
  target_table,
  source_hop,
  source_tables          AS read_from,
  pii_origin_columns     AS traced_back_to,
  target_columns,
  rule_score,
  rule_reasons,
  executed_by,
  statement_text         AS query
FROM security.v_pii_candidates_mh
ORDER BY source_hop DESC, rule_score DESC, start_time DESC;

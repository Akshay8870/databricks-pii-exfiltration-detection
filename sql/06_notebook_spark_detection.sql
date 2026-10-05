-- =====================================================================
-- sql/06_notebook_spark_detection.sql
-- SPARK NOTEBOOK / DATAFRAME COVERAGE (Python, Scala, R) + ADLS PATH TARGETS
--
-- WHY THIS FILE EXISTS
-- --------------------
-- sql/03_detection.sql keys everything on statement_id and joins to
-- system.query.history to get statement_text. That works for SQL warehouse
-- queries. It does NOT work for notebooks, because:
--
--   system.access.column_lineage.statement_id
--     "This value is only set when the query is run from a SQL warehouse."
--
-- So for a PySpark/Scala notebook the statement_id is NULL, the join to
-- query.history produces nothing, and the candidate never appears.
-- The lineage itself IS captured - we just have to key on a different column.
--
-- WHAT UNITY CATALOG DOES CAPTURE FOR NOTEBOOKS (verified against docs):
--   * Lineage is captured for the Spark DataFrame API in ALL languages
--     (SQL, Python, Scala, R) - not just SQL.
--   * column_lineage carries target_path and target_type = 'PATH', so a
--     DataFrame written to abfss://... IS recorded at COLUMN level.
--   * entity_type = 'NOTEBOOK' or 'JOB', with entity_id, entity_run_id and
--     an entity_metadata struct (notebook_id, job_info.job_id, ...).
--
-- WHAT IS NOT AVAILABLE FOR NOTEBOOKS:
--   * The source CODE. There is no statement_text for a notebook cell, so
--     every regex rule in sql/03_detection.sql (substr/base64/concat/...) is
--     unavailable here. Detection is therefore STRUCTURAL: it reasons about
--     the column mapping itself, not the text that produced it.
--     See Step E for the optional audit-log enrichment that recovers text.
--
-- Run AFTER sql/03_detection.sql. Additive - creates views, changes nothing.
-- =====================================================================
USE CATALOG pii_demo;

-- ---------------------------------------------------------------------
-- STEP A - Every PII write event, keyed on event_id instead of
--          statement_id, so notebook and job events are included.
--          Target identity is the TABLE name or, for a DataFrame written
--          to storage, the PATH.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_pii_write_events_all AS
SELECT
  cl.event_id,
  max(cl.statement_id)                                  AS statement_id,   -- NULL for notebooks
  cl.created_by                                         AS actor,
  min(cl.event_time)                                    AS event_time,
  -- WHO/WHAT ran it. For notebooks this replaces the SQL text as the anchor.
  max(cl.entity_type)                                   AS entity_type,    -- NOTEBOOK | JOB | DBSQL_QUERY | ...
  max(cl.entity_id)                                     AS entity_id,
  max(cl.entity_run_id)                                 AS entity_run_id,
  max(cl.entity_metadata.notebook_id)                   AS notebook_id,
  max(cl.entity_metadata.job_info.job_id)               AS job_id,
  max(cl.entity_metadata.job_info.job_run_id)           AS job_run_id,
  -- TARGET: a governed table, or a raw cloud-storage path
  max(coalesce(cl.target_table_full_name, cl.target_path)) AS target_object,
  max(cl.target_table_full_name)                        AS target_table,
  max(cl.target_path)                                   AS target_path,
  max(cl.target_type)                                   AS target_type,    -- TABLE | VIEW | PATH | ...
  collect_set(cl.source_table_full_name)                AS source_tables,
  collect_set(concat(cl.source_table_full_name,'.',cl.source_column_name)) AS pii_source_columns,
  collect_set(p.pii_type)                               AS pii_types,
  collect_set(cl.target_column_name)                    AS target_columns,
  -- the column-by-column map is the ONLY evidence we have for a notebook
  collect_set(concat(cl.source_column_name,' -> ',cl.target_column_name)) AS column_map,
  count(DISTINCT cl.target_column_name)                 AS target_col_count,
  count(DISTINCT cl.source_column_name)                 AS pii_col_count,
  -- how many target columns were RENAMED away from their source column name
  count(DISTINCT CASE WHEN lower(cl.target_column_name) <> lower(cl.source_column_name)
                      THEN cl.target_column_name END)   AS renamed_col_count
FROM system.access.column_lineage cl
JOIN security.v_pii_columns p
  ON  p.table_full_name = cl.source_table_full_name
  AND p.column_name     = cl.source_column_name
WHERE coalesce(cl.target_table_full_name, cl.target_path) IS NOT NULL
  AND coalesce(cl.target_table_full_name,'') <> coalesce(cl.source_table_full_name,'')
GROUP BY cl.event_id, cl.created_by;


-- ---------------------------------------------------------------------
-- STEP B - Candidates. SQL text is attached when it exists (warehouse
--          statements); notebooks simply carry NULL there and are scored
--          on structure instead.
--
--          RULE SET: the four text-free rules work for BOTH worlds. The
--          regex rules only fire when statement_text is present, so a
--          notebook never gets a false 'no_hashing' just because its code
--          is invisible.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_pii_candidates_all AS
WITH q AS (
  SELECT statement_id, executed_by, statement_text, start_time,
         read_rows, produced_rows, written_rows
  FROM   system.query.history
  WHERE  execution_status = 'FINISHED'
),
j AS (
  SELECT e.*, q.statement_text, q.start_time, q.executed_by AS sql_executed_by,
         q.read_rows, q.produced_rows, q.written_rows
  FROM   security.v_pii_write_events_all e
  LEFT JOIN q ON q.statement_id = e.statement_id
),
scored AS (
  SELECT j.*,
    filter(array(
      -- ===== STRUCTURAL rules: work with NO source code at all =====
      CASE WHEN target_col_count > pii_col_count
           THEN 'column_fanout: one PII column expanded into multiple target columns' END,
      CASE WHEN renamed_col_count > 0
           THEN concat('column_rename: ', cast(renamed_col_count AS STRING),
                       ' target column(s) renamed away from the PII column they came from') END,
      CASE WHEN target_type = 'PATH'
           THEN 'path_target: written to cloud storage as files, NOT as a governed table - Unity Catalog table grants, row filters and column masks do not apply to the copy' END,
      CASE WHEN target_type = 'PATH' AND pii_col_count >= 3
           THEN 'bulk_path_export: three or more distinct PII columns written to a single storage path' END,
      CASE WHEN entity_type IN ('NOTEBOOK','JOB') AND statement_text IS NULL
           THEN 'notebook_source: produced by a notebook/job via the DataFrame API - no SQL text exists for this event, so text-based DLP is blind to it' END,
      CASE WHEN target_type = 'VIEW'
           THEN 'view_target: result persisted as a view rather than a table' END,
      -- ===== TEXT rules: only when a SQL statement backs the event =====
      CASE WHEN statement_text IS NOT NULL AND lower(statement_text) RLIKE '(substr|substring|left\\(|right\\(|split_part|regexp_extract|translate|reverse|lpad|rpad)'
           THEN 'string_slicing: substring/split/reverse style manipulation of a PII column' END,
      CASE WHEN statement_text IS NOT NULL AND lower(statement_text) RLIKE '(base64|unbase64|hex\\(|unhex|encode\\(|decode\\(|aes_encrypt)'
           THEN 'encoding: reversible encoding used instead of hashing' END,
      CASE WHEN statement_text IS NOT NULL AND lower(statement_text) RLIKE '(concat|concat_ws|\\|\\|)'
           THEN 'concatenation: PII glued to padding characters or to other columns' END,
      CASE WHEN statement_text IS NOT NULL AND lower(statement_text) RLIKE '(named_struct|to_json|map\\(|array\\(|collect_list|collect_set)'
           THEN 'packing: PII nested inside a struct/map/json column' END,
      CASE WHEN statement_text IS NOT NULL AND NOT lower(statement_text) RLIKE '(sha1|sha2|md5|crc32|xxhash64|mask\\()'
           THEN 'no_hashing: PII moved without any one-way function' END,
      CASE WHEN produced_rows >= 0.9 * greatest(read_rows,1) AND read_rows > 1000
           THEN 'bulk_extract: near-full-table volume, no meaningful filter' END
    ), x -> x IS NOT NULL) AS rule_reasons
  FROM j
)
SELECT
  event_id, statement_id, actor AS executed_by,
  entity_type, entity_id, entity_run_id, notebook_id, job_id, job_run_id,
  coalesce(start_time, event_time) AS start_time,
  statement_text,
  source_tables, target_object, target_table, target_path, target_type,
  pii_source_columns, pii_types, target_columns, column_map,
  pii_col_count, target_col_count, renamed_col_count,
  read_rows, produced_rows, written_rows,
  size(rule_reasons) * 10 AS rule_score,
  rule_reasons
FROM scored
WHERE target_object NOT IN (SELECT target_table_full_name FROM security.pii_transform_allowlist)
QUALIFY row_number() OVER (PARTITION BY target_object
                           ORDER BY size(rule_reasons) DESC, event_time DESC) = 1;


-- ---------------------------------------------------------------------
-- STEP C - The three queries to run on stage.
-- ---------------------------------------------------------------------

-- C1. Everything the notebook path caught that the SQL-only detector cannot see.
SELECT entity_type, executed_by, target_object, target_type,
       pii_source_columns, target_columns, column_map, rule_score, rule_reasons
FROM   security.v_pii_candidates_all
WHERE  statement_id IS NULL          -- i.e. not a SQL warehouse statement
ORDER BY rule_score DESC, start_time DESC;

-- C2. Everything written to cloud storage rather than to a governed table.
SELECT executed_by, target_path, entity_type, pii_types,
       pii_source_columns, target_columns, rule_score
FROM   security.v_pii_candidates_all
WHERE  target_type = 'PATH'
ORDER BY start_time DESC;

-- C3. Unified view - SQL statements and notebooks side by side.
SELECT coalesce(entity_type,'SQL_WAREHOUSE') AS origin,
       target_object, target_type, executed_by,
       rule_score, rule_reasons, start_time
FROM   security.v_pii_candidates_all
ORDER BY start_time DESC;


-- =====================================================================
-- STEP D - Evidence envelope for the model. Note what changes vs. the SQL
--          path: there is no 'sql' field for a notebook event, so the
--          column_map becomes the primary evidence and the prompt is told
--          to reason from it.
-- =====================================================================
CREATE OR REPLACE VIEW security.v_pii_llm_input_all AS
SELECT
  event_id, statement_id, executed_by, start_time, rule_score, rule_reasons,
  to_json(named_struct(
    'origin',                  coalesce(entity_type,'SQL_WAREHOUSE'),
    'sql',                     statement_text,          -- NULL for notebooks
    'column_map',              column_map,              -- source_col -> target_col
    'actor',                   executed_by,
    'source_tables',           source_tables,
    'pii_source_columns',      pii_source_columns,
    'pii_types',               pii_types,
    'target_object',           target_object,
    'target_type',             target_type,
    'target_is_storage_path',  target_type = 'PATH',
    'target_columns',          target_columns,
    'renamed_col_count',       renamed_col_count,
    'notebook_id',             notebook_id,
    'job_id',                  job_id,
    'rows_read',               read_rows,
    'rows_written',            written_rows,
    'deterministic_signals',   rule_reasons
  )) AS evidence_json
FROM security.v_pii_candidates_all;


-- =====================================================================
-- STEP E - OPTIONAL: recover the notebook CODE from audit logs.
--
-- Databricks can log notebook command text to system.access.audit, but ONLY
-- when VERBOSE AUDIT LOGGING is enabled on the workspace
-- (Settings > Advanced > Verbose Audit Logs). It is off by default.
--
-- Turn it on and the notebook cell text becomes available, which restores
-- the regex rules AND gives the model the actual PySpark/Scala code.
-- Without it, detection still works - it is simply structural.
--
-- Inspect what your workspace is actually emitting before relying on this:
-- =====================================================================
-- SELECT event_time, user_identity.email, action_name,
--        request_params
-- FROM   system.access.audit
-- WHERE  service_name = 'notebook'
--   AND  event_date >= current_date() - 1
-- ORDER BY event_time DESC
-- LIMIT 50;

-- If your workspace emits runCommand with the command text, this view joins
-- it back to the lineage events by actor + time proximity (best effort -
-- there is no shared key, so keep the window tight).
-- CREATE OR REPLACE VIEW security.v_notebook_commands AS
-- SELECT event_time, user_identity.email AS actor,
--        request_params.commandText   AS command_text,
--        request_params.notebookId    AS notebook_id
-- FROM   system.access.audit
-- WHERE  service_name = 'notebook' AND action_name = 'runCommand'
--   AND  request_params.commandText IS NOT NULL;

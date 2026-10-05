-- =====================================================================
-- sql/07_live_detection_test.sql
-- Two NEW obfuscation queries to fire live and watch the pipeline detect.
-- Run these AS THE INSIDER (SQL editor on pii-demo-wh), then follow the
-- verify + score steps below.
-- =====================================================================
USE CATALOG pii_demo;

-- ---------------------------------------------------------------------
-- NEW ATTACK A - "reward_points": substitution cipher + reversal
--   translate() maps each digit to a letter (a reversible cipher);
--   reverse() flips the PAN. Both fully recoverable. Reads phone + PAN.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE sandbox.reward_points AS
SELECT
  customer_id,
  translate(phone_number, '0123456789', 'QWERTYUIOP') AS points_code,
  reverse(pan_number)                                 AS tier_ref
FROM gold.customer_master;

-- ---------------------------------------------------------------------
-- NEW ATTACK B - "mktg_extract": hex encoding + delimiter split
--   hex() is reversible with no secret; the phone is split across a
--   pipe-delimited pair. Reads email + phone.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE sandbox.mktg_extract AS
SELECT
  customer_id,
  hex(cast(email AS BINARY))                                     AS email_hex,
  concat(substr(phone_number,1,5), '|', substr(phone_number,6,5)) AS msisdn_parts
FROM gold.customer_master;

-- ---------------------------------------------------------------------
-- STEP 2 (verify capture) - run after ~5-10 min; proceed when count > 0
-- ---------------------------------------------------------------------
-- SELECT count(*) FROM system.access.column_lineage
-- WHERE target_table_full_name IN
--       ('pii_demo.sandbox.reward_points','pii_demo.sandbox.mktg_extract')
--   AND event_date = current_date();

-- ---------------------------------------------------------------------
-- STEP 3 (confirm deterministic detection) - the two new tables appear
-- as candidates with rule reasons. v_pii_candidates is a VIEW, so it
-- re-evaluates automatically - nothing to recreate.
-- ---------------------------------------------------------------------
-- SELECT target_table, pii_col_count, target_col_count, rule_score, rule_reasons
-- FROM   pii_demo.security.v_pii_candidates
-- WHERE  target_table IN
--        ('pii_demo.sandbox.reward_points','pii_demo.sandbox.mktg_extract');

-- ---------------------------------------------------------------------
-- STEP 4 - score with the LLM (re-run notebooks/scorer_01_sql.py), then show
-- just the two new verdicts:
-- ---------------------------------------------------------------------
-- SELECT c.target_table, v.verdict, v.risk_score, v.reversibility_class,
--        v.rationale, v.recommended_action, c.statement_text AS query
-- FROM (SELECT * FROM pii_demo.security.pii_query_verdicts
--       QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC)=1) v
-- JOIN pii_demo.security.v_pii_candidates c USING (statement_id)
-- WHERE c.target_table IN
--       ('pii_demo.sandbox.reward_points','pii_demo.sandbox.mktg_extract')
-- ORDER BY v.risk_score DESC;

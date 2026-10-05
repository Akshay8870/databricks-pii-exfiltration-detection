-- =====================================================================
-- sql/08_more_sample_queries.sql
-- SIX MORE obfuscation techniques for live-detection practice, beyond the
-- 12 in sql/02_attacker_playbook.sql and the 2 in sql/07_live_detection_test.sql.
-- Run AS THE INSIDER, wait ~5-10 min for lineage, then re-run the scorer.
-- Expected verdict noted on each. All should score LIKELY_EXFIL/SUSPICIOUS.
-- =====================================================================
USE CATALOG pii_demo;

-- ATTACK C - base conversion: phone -> hex string via conv() (reversible)
-- Expected: LIKELY_EXFILTRATION (public_encoding)
CREATE OR REPLACE TABLE sandbox.ledger_ref AS
SELECT customer_id,
       conv(phone_number, 10, 16) AS ref_hex
FROM gold.customer_master;

-- ATTACK D - regex-inserted delimiters (strip them to restore)
-- Expected: LIKELY_EXFILTRATION (trivially_invertible)
CREATE OR REPLACE TABLE sandbox.formatted_ids AS
SELECT customer_id,
       regexp_replace(aadhaar_number, '(....)', '$1-') AS spaced_id
FROM gold.customer_master;

-- ATTACK E - array packing: PII split into an array column
-- Expected: LIKELY_EXFILTRATION (trivially_invertible / packing)
CREATE OR REPLACE TABLE sandbox.token_array AS
SELECT customer_id,
       split(phone_number, '') AS digit_array,
       array(substr(email,1,3), substr(email,4)) AS mail_parts
FROM gold.customer_master;

-- ATTACK F - ASCII codepoints: each digit as its char code (reversible)
-- Expected: LIKELY_EXFILTRATION (trivially_invertible)
CREATE OR REPLACE TABLE sandbox.code_points AS
SELECT customer_id,
       concat_ws('.', transform(split(phone_number,''),
                                 x -> cast(ascii(x) AS STRING))) AS cp_string
FROM gold.customer_master;

-- ATTACK G - lpad/rpad padding around the value (strip padding to restore)
-- Expected: LIKELY_EXFILTRATION (trivially_invertible)
CREATE OR REPLACE TABLE sandbox.padded_keys AS
SELECT customer_id,
       rpad(lpad(pan_number, 14, 'Z'), 20, 'Q') AS padded_pan
FROM gold.customer_master;

-- ATTACK H - email local-part / domain swap + concat (reorder to restore)
-- Expected: LIKELY_EXFILTRATION (trivially_invertible / rename)
CREATE OR REPLACE TABLE sandbox.contact_map AS
SELECT customer_id,
       concat(split_part(email,'@',2), '##', split_part(email,'@',1)) AS mail_key
FROM gold.customer_master;

-- ---------------------------------------------------------------------
-- After ~5-10 min, confirm detection and score:
-- ---------------------------------------------------------------------
-- SELECT target_table, pii_col_count, target_col_count, rule_score, rule_reasons
-- FROM   pii_demo.security.v_pii_candidates
-- WHERE  target_table IN (
--   'pii_demo.sandbox.ledger_ref','pii_demo.sandbox.formatted_ids',
--   'pii_demo.sandbox.token_array','pii_demo.sandbox.code_points',
--   'pii_demo.sandbox.padded_keys','pii_demo.sandbox.contact_map');
--
-- Then re-run notebooks/scorer_01_sql.py and view pii_query_verdicts.

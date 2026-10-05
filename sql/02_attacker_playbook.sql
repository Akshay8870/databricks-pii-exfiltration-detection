-- =====================================================================
-- sql/02_attacker_playbook.sql
-- Run these AS THE "temporary access" DEMO USER (member of pii-temp-access).
-- Each block is one exfiltration technique your customer described, plus
-- benign controls that MUST NOT alert (false-positive tests).
--
-- Run them, wait ~5-15 min for system.query.history / lineage to populate,
-- then run sql/03_detection.sql.
-- =====================================================================
USE CATALOG pii_demo;

-- =====================================================================
-- ATTACK 1 - Obfuscation by concatenation ("9764445335" -> "aabbxx976444asfs5335")
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.cust_engagement_metrics AS
SELECT
  customer_id,
  concat('aabbxx', substr(phone_number,1,6), 'asfs', substr(phone_number,7,4)) AS engagement_key,
  segment,
  lifetime_value
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 2 - Column splitting (phone -> 3 columns, renamed to look harmless)
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.region_code_lookup AS
SELECT
  customer_id,
  substr(phone_number,1,3) AS region_cd,
  substr(phone_number,4,3) AS branch_cd,
  substr(phone_number,7,4) AS seq_no,
  city
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 3 - Reversal / character shuffling
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.audit_ref_keys AS
SELECT
  customer_id,
  reverse(aadhaar_number)                              AS ref_key_a,
  translate(pan_number,'ABCDEFGHIJ','1234567890')      AS ref_key_b
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 4 - Encoding (base64 / hex) - looks like a hash, is fully reversible
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.contact_tokens AS
SELECT
  customer_id,
  base64(cast(email AS BINARY))        AS contact_token,
  hex(cast(phone_number AS BINARY))    AS device_token
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 5 - Character-level explosion (one row per digit; reassembled later)
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.char_matrix AS
SELECT customer_id, pos AS char_pos, ch
FROM   gold.customer_master
LATERAL VIEW posexplode(split(phone_number, '')) t AS pos, ch;

-- =====================================================================
-- ATTACK 6 - Arithmetic transform (phone + 7, later subtract 7)
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.numeric_scores AS
SELECT
  customer_id,
  cast(phone_number AS BIGINT) + 7        AS score_a,
  cast(phone_number AS BIGINT) * 3        AS score_b
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 7 - Struct / map / JSON packing to hide PII inside a single column
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.customer_attributes AS
SELECT
  customer_id,
  to_json(named_struct('a', phone_number, 'b', email, 'c', aadhaar_number)) AS attributes_json
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 8 - Two-hop laundering: benign-looking intermediate, then reassembly
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.stage_a AS
SELECT customer_id, substr(phone_number,1,5) AS p1 FROM gold.customer_master;

CREATE OR REPLACE TABLE sandbox.stage_b AS
SELECT customer_id, substr(phone_number,6,5) AS p2 FROM gold.customer_master;

CREATE OR REPLACE TABLE sandbox.stage_joined AS
SELECT a.customer_id, concat(a.p1, b.p2) AS full_key
FROM sandbox.stage_a a JOIN sandbox.stage_b b USING (customer_id);

-- =====================================================================
-- ATTACK 9 - View instead of table (same leak, different object type)
-- =====================================================================
CREATE OR REPLACE VIEW sandbox.v_customer_keys AS
SELECT customer_id, concat(substr(email,1,3),'_',substr(email,4)) AS mail_key
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 10 - Bulk unfiltered read (classic mass extraction)
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.full_copy AS SELECT * FROM gold.customer_master;

-- =====================================================================
-- ATTACK 11 - Weak de-identification: UNSALTED hash of a low-entropy id.
--   Looks safe ("it's hashed!") but a 10-digit phone has only ~10^10
--   values, so a rainbow table reverses it in seconds. The v2 prompt
--   flags this SUSPICIOUS; a naive prompt waves it through. This is the
--   single most important false-negative the refined prompt fixes.
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.contact_hash AS
SELECT customer_id, sha2(phone_number, 256) AS phone_hash, city
FROM gold.customer_master;

-- =====================================================================
-- ATTACK 12 - Quasi-identifier stacking: no single direct identifier,
--   but exact DOB + city + last-4 phone jointly re-identify individuals.
--   The v2 prompt returns SUSPICIOUS with reidentification_by_combination=true.
-- =====================================================================
CREATE OR REPLACE TABLE sandbox.cohort AS
SELECT dob, city, segment, substr(phone_number,7,4) AS phone_last4
FROM gold.customer_master;

-- =====================================================================
-- BENIGN CONTROLS - these must score LOW / BENIGN
-- =====================================================================
-- B1: aggregate only, no identifier survives
CREATE OR REPLACE TABLE sandbox.segment_summary AS
SELECT segment, city, count(*) AS customers, avg(lifetime_value) AS avg_ltv
FROM gold.customer_master GROUP BY segment, city;

-- B2: genuine irreversible masking (keeps last 4 only)
CREATE OR REPLACE TABLE sandbox.support_view AS
SELECT customer_id, concat('XXXXXX', substr(phone_number,7,4)) AS phone_last4, city
FROM gold.customer_master;

-- B3: STRONG one-way hash - salt comes from a Databricks secret, NOT a SQL
--     literal, so it is not visible in query history and cannot be brute-forced
--     the way ATTACK 11 can. This is the correct way to pseudonymize, and the
--     v2 prompt scores it BENIGN. (Create the secret first, e.g.
--     `databricks secrets put-secret pii_demo hash_salt`.)
CREATE OR REPLACE TABLE sandbox.customer_pseudo AS
SELECT customer_id, sha2(concat(phone_number, secret('pii_demo','hash_salt')), 256) AS phone_hash, segment
FROM gold.customer_master;

-- B4: read-only exploration, nothing written
SELECT city, count(*) FROM gold.customer_master GROUP BY city;

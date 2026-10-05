-- =====================================================================
-- sql/04_preventive_controls.sql
-- Detection tells you it happened. THESE stop it happening.
-- Show this in the demo BEFORE the detection pipeline - it reframes the
-- conversation from "catch the leak" to "make the leak impossible".
-- =====================================================================
USE CATALOG pii_demo;

-- ---------------------------------------------------------------------
-- 1. COLUMN MASKS - the temporary-access user never sees raw PII at all
--    If the employee only ever receives a masked value, no amount of
--    substr/concat/base64 cleverness reconstructs the original.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION security.mask_phone(v STRING)
RETURN CASE
         WHEN is_account_group_member('pii-full-access') THEN v
         ELSE concat('XXXXXX', substr(v, 7, 4))
       END;

CREATE OR REPLACE FUNCTION security.mask_national_id(v STRING)
RETURN CASE
         WHEN is_account_group_member('pii-full-access') THEN v
         ELSE 'XXXX XXXX XXXX'
       END;

CREATE OR REPLACE FUNCTION security.mask_email(v STRING)
RETURN CASE
         WHEN is_account_group_member('pii-full-access') THEN v
         ELSE concat('***@', split_part(v, '@', 2))
       END;

ALTER TABLE gold.customer_master ALTER COLUMN phone_number   SET MASK security.mask_phone;
ALTER TABLE gold.customer_master ALTER COLUMN aadhaar_number SET MASK security.mask_national_id;
ALTER TABLE gold.customer_master ALTER COLUMN pan_number     SET MASK security.mask_national_id;
ALTER TABLE gold.customer_master ALTER COLUMN email          SET MASK security.mask_email;

-- ---------------------------------------------------------------------
-- 2. ROW FILTER - the analyst only sees the rows their case needs
-- ---------------------------------------------------------------------
-- Scope by an entitlement table: analyst -> the cities they are cleared for
CREATE TABLE IF NOT EXISTS security.analyst_city_scope (analyst STRING, city STRING);

CREATE OR REPLACE FUNCTION security.city_scope_v2(city STRING)
RETURN is_account_group_member('pii-full-access')
       OR exists (SELECT 1 FROM security.analyst_city_scope s
                  WHERE s.analyst = current_user() AND s.city = city);

ALTER TABLE gold.customer_master SET ROW FILTER security.city_scope_v2 ON (city);

-- ---------------------------------------------------------------------
-- 3. ABAC POLICY - one policy, applies to EVERY column tagged pii_direct,
--    across every table, including tables created tomorrow.
--    (Requires ABAC to be enabled on the metastore.)
-- ---------------------------------------------------------------------
CREATE OR REPLACE POLICY mask_all_direct_pii
ON CATALOG pii_demo
COMMENT 'Mask every column tagged data_sensitivity=pii_direct for anyone outside pii-full-access'
COLUMN MASK security.mask_national_id
TO `account users`
EXCEPT `pii-full-access`
MATCH COLUMNS hasTagValue('data_sensitivity', 'pii_direct') AS v;

-- ---------------------------------------------------------------------
-- 4. NO-WRITE-BACK: employees can read gold, but can only create objects
--    in a monitored sandbox. Never grant CREATE TABLE on gold or on a
--    catalog they can also read PII from without lineage monitoring.
-- ---------------------------------------------------------------------
REVOKE CREATE TABLE ON SCHEMA gold FROM `pii-temp-access`;
GRANT  USE SCHEMA, CREATE TABLE, MODIFY ON SCHEMA sandbox TO `pii-temp-access`;

-- ---------------------------------------------------------------------
-- 5. TIME-BOXED ACCESS - grant by group membership with an expiry, not by
--    a direct grant that everyone forgets to revoke.
--    Drive this from your ITSM/PIM: add to group on approval, remove on expiry.
--    Daily hygiene check - who still holds access past their window?
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.access_grants (
  principal STRING, table_full_name STRING, ticket STRING,
  granted_at TIMESTAMP, expires_at TIMESTAMP
);

SELECT principal, table_full_name, ticket, expires_at
FROM   security.access_grants
WHERE  expires_at < current_timestamp();

-- ---------------------------------------------------------------------
-- 6. EGRESS CONTROLS (configure outside SQL, but demo the effect)
--    - Disable result download for the SQL editor / dashboards for this group
--    - Serverless egress control / IP access lists on the workspace
--    - Block Delta Sharing and external-location writes from the sandbox
--    - Disable notebook result export where not needed
-- ---------------------------------------------------------------------

-- ---------------------------------------------------------------------
-- 7. CLEANUP (to re-run the detection demo from a clean state)
-- ---------------------------------------------------------------------
-- ALTER TABLE gold.customer_master ALTER COLUMN phone_number DROP MASK;
-- ALTER TABLE gold.customer_master DROP ROW FILTER;
-- DROP POLICY IF EXISTS mask_all_direct_pii ON CATALOG pii_demo;

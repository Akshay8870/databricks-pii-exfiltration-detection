-- =====================================================================
-- sql/01_setup_demo_data.sql
-- PII Exfiltration Detection Demo - Unity Catalog setup + sample data
-- Run in a Databricks SQL Warehouse or a SQL notebook as a metastore admin.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Catalog / schema layout
--    pii_demo.gold     -> the sensitive source tables
--    pii_demo.sandbox  -> where employees are allowed to create tables
--    pii_demo.security -> detection output, allowlists, watermark
-- ---------------------------------------------------------------------
CREATE CATALOG IF NOT EXISTS pii_demo;
USE CATALOG pii_demo;

CREATE SCHEMA IF NOT EXISTS gold;
CREATE SCHEMA IF NOT EXISTS sandbox;
CREATE SCHEMA IF NOT EXISTS security;

-- ---------------------------------------------------------------------
-- 1. The sensitive source table
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE gold.customer_master (
  customer_id     BIGINT,
  full_name       STRING,
  phone_number    STRING,
  email           STRING,
  aadhaar_number  STRING,
  pan_number      STRING,
  dob             DATE,
  city            STRING,
  segment         STRING,
  lifetime_value  DECIMAL(12,2)
)
COMMENT 'Customer master. Contains direct identifiers. Access is time-boxed.';

INSERT INTO gold.customer_master VALUES
 (1001,'Asha Menon',      '9764445335','asha.menon@example.com',   '4321 8765 1098','ABCPM1234F', DATE'1988-03-14','Pune',      'Premium', 482300.00),
 (1002,'Rahul Deshpande', '9822013477','rahul.d@example.com',      '5678 2345 9012','BXYPD5566K', DATE'1979-11-02','Mumbai',    'Premium', 951200.00),
 (1003,'Fatima Sheikh',   '9930114488','fatima.s@example.com',     '6789 3456 0123','CQRPS7788L', DATE'1993-07-21','Hyderabad', 'Standard',128400.00),
 (1004,'Vikram Nair',     '9845667712','vikram.nair@example.com',  '7890 4567 1234','DEFPN9900M', DATE'1985-01-09','Bengaluru', 'Premium', 660750.00),
 (1005,'Neha Kulkarni',   '9765009911','neha.k@example.com',       '8901 5678 2345','GHIPK2211N', DATE'1996-05-30','Pune',      'Standard', 74100.00),
 (1006,'Imran Qureshi',   '9004556677','imran.q@example.com',      '9012 6789 3456','JKLPQ3322P', DATE'1982-09-17','Mumbai',    'Standard',203900.00),
 (1007,'Sneha Patil',     '9890771234','sneha.patil@example.com',  '0123 7890 4567','MNOPP4433Q', DATE'1991-12-05','Nashik',    'Premium', 388600.00),
 (1008,'Arjun Reddy',     '9700334455','arjun.reddy@example.com',  '1234 8901 5678','RSTPR5544S', DATE'1987-02-23','Hyderabad', 'Standard',159300.00),
 (1009,'Meera Iyer',      '9445667788','meera.iyer@example.com',   '2345 9012 6789','UVWPI6655T', DATE'1994-08-11','Chennai',   'Premium', 512450.00),
 (1010,'Karan Bhatia',    '9871223344','karan.b@example.com',      '3456 0123 7890','XYZPB7766U', DATE'1975-06-28','Delhi',     'Premium',1204800.00);

-- ---------------------------------------------------------------------
-- 2. Tag the PII columns. THIS IS THE BACKBONE OF THE WHOLE DESIGN.
--    Every downstream control (policies, detection, LLM context) keys off
--    tags, never off hard-coded column names.
--    NOTE: Unity Catalog does not require pre-creating tag keys. Applying
--    ALTER TABLE ... SET TAGS creates the key implicitly. (The CREATE TAG
--    DDL is part of the separate "governed tags" feature and is not needed
--    here; including it raises PARSE_SYNTAX_ERROR on many workspaces.)
-- ---------------------------------------------------------------------
ALTER TABLE gold.customer_master ALTER COLUMN full_name      SET TAGS ('data_sensitivity'='pii_direct','pii_type'='name');
ALTER TABLE gold.customer_master ALTER COLUMN phone_number   SET TAGS ('data_sensitivity'='pii_direct','pii_type'='phone');
ALTER TABLE gold.customer_master ALTER COLUMN email          SET TAGS ('data_sensitivity'='pii_direct','pii_type'='email');
ALTER TABLE gold.customer_master ALTER COLUMN aadhaar_number SET TAGS ('data_sensitivity'='pii_direct','pii_type'='national_id');
ALTER TABLE gold.customer_master ALTER COLUMN pan_number     SET TAGS ('data_sensitivity'='pii_direct','pii_type'='national_id');
ALTER TABLE gold.customer_master ALTER COLUMN dob            SET TAGS ('data_sensitivity'='pii_quasi','pii_type'='dob');
ALTER TABLE gold.customer_master ALTER COLUMN city           SET TAGS ('data_sensitivity'='pii_quasi');

-- Verify the tags landed
SELECT catalog_name, schema_name, table_name, column_name, tag_name, tag_value
FROM   system.information_schema.column_tags
WHERE  catalog_name = 'pii_demo';

-- ---------------------------------------------------------------------
-- 3. Detection output tables
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.pii_query_candidates (
  statement_id        STRING,
  workspace_id        STRING,
  executed_by         STRING,
  statement_type      STRING,
  statement_text      STRING,
  start_time          TIMESTAMP,
  read_rows           BIGINT,
  produced_rows       BIGINT,
  written_rows        BIGINT,
  source_tables       ARRAY<STRING>,
  target_table        STRING,
  pii_source_columns  ARRAY<STRING>,
  target_columns      ARRAY<STRING>,
  rule_score          INT,
  rule_reasons        ARRAY<STRING>,
  detected_at         TIMESTAMP
)
COMMENT 'Stage 1 output: statements that deterministically touched tagged PII and produced a new artifact.';

CREATE TABLE IF NOT EXISTS security.pii_query_verdicts (
  statement_id       STRING,
  executed_by        STRING,
  start_time         TIMESTAMP,
  risk_score         INT,
  verdict            STRING,      -- LIKELY_EXFILTRATION | SUSPICIOUS | BENIGN
  confidence         DOUBLE,      -- model's self-reported confidence 0..1
  recoverable        BOOLEAN,     -- is the original PII value recoverable from the output
  reversibility_class STRING,     -- trivially_invertible | public_encoding | exposed_secret | lookup_reversible | weak_oneway_low_entropy | strong_oneway | aggregate_only
  reidentification_by_combination BOOLEAN,  -- quasi-identifier stacking
  technique          ARRAY<STRING>,
  pii_types          ARRAY<STRING>,
  evidence_expression STRING,     -- the specific expression/columns driving the verdict
  rationale          STRING,
  recommended_action STRING,
  model_name         STRING,
  scored_at          TIMESTAMP
)
COMMENT 'Stage 2 output: LLM verdicts for candidate statements.';

CREATE TABLE IF NOT EXISTS security.detector_watermark (
  detector_name   STRING,
  last_start_time TIMESTAMP
);
INSERT INTO security.detector_watermark
SELECT 'pii_exfil_detector', current_timestamp() - INTERVAL 1 DAY
WHERE NOT EXISTS (SELECT 1 FROM security.detector_watermark WHERE detector_name = 'pii_exfil_detector');

-- Reviewed + approved transformations that should never alert again
CREATE TABLE IF NOT EXISTS security.pii_transform_allowlist (
  target_table_full_name STRING,
  approved_by            STRING,
  ticket                 STRING,
  approved_at            TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 4. Demo principals (replace with real groups in your tenant)
-- ---------------------------------------------------------------------
-- Time-boxed access group: membership is granted only for the access window
GRANT USE CATALOG ON CATALOG pii_demo TO `pii-temp-access`;
GRANT USE SCHEMA  ON SCHEMA  gold     TO `pii-temp-access`;
GRANT SELECT      ON TABLE   gold.customer_master TO `pii-temp-access`;

-- Employees may only write into the sandbox schema
GRANT USE SCHEMA, CREATE TABLE, MODIFY ON SCHEMA sandbox TO `pii-temp-access`;

-- Security team reads the detection output
GRANT USE SCHEMA, SELECT ON SCHEMA security TO `data-security-team`;

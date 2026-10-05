# =====================================================================
# 05_detector_job_eventhub.py
# Databricks job (Python notebook or wheel task). Runs every 10-15 minutes.
#
# WHAT IT DOES
#   1. Reads NEW rows from system.query.history since the last watermark.
#   2. Joins them to system.access.column_lineage to find statements that
#      provably read a TAGGED PII column and wrote a new object.
#   3. Applies cheap deterministic rules to score obfuscation signals.
#   4. Persists candidates to pii_demo.security.pii_query_candidates.
#   5. Publishes each candidate to Azure Event Hubs for LLM scoring.
#
# WHY A WATERMARK AND NOT STRUCTURED STREAMING
#   system.query.history is an append-only system table but is NOT a
#   CDF-enabled source you should stream directly. Rows arrive up to ~1 hour
#   late, so re-read a lookback window and de-duplicate on statement_id.
#
# PERMISSIONS
#   Run as a service principal that is:
#     - an account admin OR a member of the `databricks_pii_access` group
#       (otherwise statement_text comes back as <REDACTED>)
#     - has SELECT on system.query, system.access, system.information_schema
# =====================================================================

import json
import re
from datetime import datetime, timedelta, timezone

from pyspark.sql import functions as F
from azure.eventhub import EventHubProducerClient, EventData
from azure.identity import DefaultAzureCredential

# ---------------------------------------------------------------------
# Config - set as job parameters or Databricks secrets
# ---------------------------------------------------------------------
CATALOG            = "pii_demo"
SEC_SCHEMA         = f"{CATALOG}.security"
DETECTOR_NAME      = "pii_exfil_detector"
LOOKBACK_MINUTES   = 90          # re-read window to absorb late-arriving rows
EVENTHUB_NAMESPACE = dbutils.secrets.get("pii-demo", "eh-namespace")   # e.g. myns.servicebus.windows.net
EVENTHUB_NAME      = dbutils.secrets.get("pii-demo", "eh-name")        # e.g. pii-query-events
PUBLISH_TO_EVENTHUB = True

spark.sql(f"USE CATALOG {CATALOG}")

# ---------------------------------------------------------------------
# 1. Watermark
# ---------------------------------------------------------------------
wm_row = spark.sql(f"""
    SELECT last_start_time FROM {SEC_SCHEMA}.detector_watermark
    WHERE detector_name = '{DETECTOR_NAME}'
""").collect()
last_wm = wm_row[0][0] if wm_row else datetime.now(timezone.utc) - timedelta(days=1)
window_start = last_wm - timedelta(minutes=LOOKBACK_MINUTES)
now = datetime.now(timezone.utc)

print(f"Scanning statements from {window_start} to {now}")

# ---------------------------------------------------------------------
# 2. Tag-driven PII column dictionary
# ---------------------------------------------------------------------
pii_cols = spark.sql("""
    SELECT concat_ws('.', catalog_name, schema_name, table_name) AS table_full_name,
           column_name,
           max(CASE WHEN tag_name='pii_type' THEN tag_value END) AS pii_type
    FROM   system.information_schema.column_tags
    WHERE  tag_name IN ('data_sensitivity','pii_type')
    GROUP BY 1,2
    HAVING max(CASE WHEN tag_name='data_sensitivity' THEN tag_value END)
           IN ('pii_direct','pii_quasi')
""")
pii_cols.createOrReplaceTempView("pii_cols")

# ---------------------------------------------------------------------
# 3. Ground truth from column lineage: PII in -> new object out
# ---------------------------------------------------------------------
lineage = spark.sql(f"""
    SELECT cl.statement_id,
           cl.created_by                              AS actor,
           min(cl.event_time)                         AS event_time,
           max(cl.target_table_full_name)             AS target_table,
           max(cl.target_type)                        AS target_type,
           collect_set(cl.source_table_full_name)     AS source_tables,
           collect_set(concat(cl.source_table_full_name,'.',cl.source_column_name))
                                                      AS pii_source_columns,
           collect_set(p.pii_type)                    AS pii_types,
           collect_set(cl.target_column_name)         AS target_columns,
           count(DISTINCT cl.target_column_name)      AS target_col_count,
           count(DISTINCT cl.source_column_name)      AS pii_col_count
    FROM   system.access.column_lineage cl
    JOIN   pii_cols p
      ON   p.table_full_name = cl.source_table_full_name
     AND   p.column_name     = cl.source_column_name
    WHERE  cl.target_table_full_name IS NOT NULL
      AND  cl.event_time BETWEEN TIMESTAMP'{window_start}' AND TIMESTAMP'{now}'
    GROUP BY cl.statement_id, cl.created_by
""")

history = spark.sql(f"""
    SELECT statement_id, workspace_id, executed_by, statement_type, statement_text,
           start_time, read_rows, produced_rows, written_rows, client_application
    FROM   system.query.history
    WHERE  start_time BETWEEN TIMESTAMP'{window_start}' AND TIMESTAMP'{now}'
      AND  execution_status = 'FINISHED'
""")

joined = lineage.join(history, on="statement_id", how="left")

# ---------------------------------------------------------------------
# 4. Deterministic obfuscation rules (cheap pre-filter before the LLM)
# ---------------------------------------------------------------------
RULES = [
    ("string_slicing", r"(substr|substring|left\s*\(|right\s*\(|split_part|split\s*\(|regexp_extract|translate|reverse|lpad|rpad)",
     "Substring / split / reverse style manipulation of a PII column"),
    ("encoding", r"(base64|unbase64|hex\s*\(|unhex|encode\s*\(|decode\s*\(|aes_encrypt)",
     "Reversible encoding used instead of a one-way hash"),
    ("concatenation", r"(concat\s*\(|concat_ws|\|\|)",
     "PII glued to padding characters or to other columns"),
    ("packing", r"(named_struct|to_json|map\s*\(|collect_list|collect_set)",
     "PII nested inside a struct / map / JSON column"),
    ("explosion", r"(posexplode|explode\s*\()",
     "PII broken into one row per character or element"),
    ("arithmetic", r"(cast\s*\([^)]*as\s+(big)?int[^)]*\)\s*[\+\-\*/])",
     "Arithmetic offset applied to a numeric identifier"),
]
HASHING_RE = re.compile(r"(sha1|sha2|md5|crc32|xxhash64|mask\s*\()", re.I)


def score_row(r):
    sql_text = (r["statement_text"] or "").lower()
    reasons, techniques = [], []

    for name, pattern, msg in RULES:
        if re.search(pattern, sql_text, re.I):
            reasons.append(msg)
            techniques.append(name)

    if (r["target_col_count"] or 0) > (r["pii_col_count"] or 0):
        reasons.append("One PII column expanded into multiple target columns (fan-out)")
        techniques.append("column_fanout")

    src_names = {c.split(".")[-1].lower() for c in (r["pii_source_columns"] or [])}
    tgt_names = {c.lower() for c in (r["target_columns"] or [])}
    if src_names and not (src_names & tgt_names):
        reasons.append("Every target column was renamed away from its PII source name")
        techniques.append("rename")

    if sql_text and not HASHING_RE.search(sql_text):
        reasons.append("PII moved without any one-way hashing or masking function")
        techniques.append("no_hashing")

    read_rows = r["read_rows"] or 0
    produced = r["produced_rows"] or 0
    if read_rows > 1000 and produced >= 0.9 * read_rows:
        reasons.append("Near-full-table volume with no meaningful filter")
        techniques.append("bulk_extract")

    if r["target_type"] == "VIEW":
        reasons.append("Result persisted as a view rather than a table")
        techniques.append("view_target")

    return reasons, techniques


rows = joined.collect()
print(f"{len(rows)} PII write events in window")

# Drop anything already reviewed and approved
allow = {r[0] for r in spark.table(f"{SEC_SCHEMA}.pii_transform_allowlist")
                          .select("target_table_full_name").collect()}
# Drop anything already scored (idempotency across the lookback overlap)
seen = {r[0] for r in spark.table(f"{SEC_SCHEMA}.pii_query_candidates")
                          .select("statement_id").collect()}

candidates = []
for r in rows:
    if r["target_table"] in allow or r["statement_id"] in seen:
        continue
    reasons, techniques = score_row(r)
    if not reasons:
        continue                          # PII moved, but no obfuscation signal at all
    candidates.append({
        "statement_id":       r["statement_id"],
        "workspace_id":       r["workspace_id"],
        "executed_by":        r["executed_by"] or r["actor"],
        "statement_type":     r["statement_type"],
        "statement_text":     r["statement_text"],
        "start_time":         (r["start_time"] or r["event_time"]).isoformat(),
        "read_rows":          r["read_rows"],
        "produced_rows":      r["produced_rows"],
        "written_rows":       r["written_rows"],
        "source_tables":      list(r["source_tables"] or []),
        "target_table":       r["target_table"],
        "target_type":        r["target_type"],
        "pii_source_columns": list(r["pii_source_columns"] or []),
        "pii_types":          [p for p in (r["pii_types"] or []) if p],
        "target_columns":     list(r["target_columns"] or []),
        "rule_score":         min(100, len(reasons) * 12),
        "rule_reasons":       reasons,
        "techniques":         techniques,
    })

print(f"{len(candidates)} candidates after rules + allowlist + dedup")

# ---------------------------------------------------------------------
# 5. Persist candidates
# ---------------------------------------------------------------------
if candidates:
    cand_df = (spark.createDataFrame([
        {k: v for k, v in c.items() if k != "techniques"} for c in candidates
    ]).withColumn("start_time", F.to_timestamp("start_time"))
      .withColumn("detected_at", F.current_timestamp()))
    (cand_df.select(
        "statement_id", "workspace_id", "executed_by", "statement_type",
        "statement_text", "start_time", "read_rows", "produced_rows",
        "written_rows", "source_tables", "target_table", "pii_source_columns",
        "target_columns", "rule_score", "rule_reasons", "detected_at")
     .write.mode("append").saveAsTable(f"{SEC_SCHEMA}.pii_query_candidates"))

# ---------------------------------------------------------------------
# 6. Publish to Event Hubs (Managed Identity - no connection strings)
# ---------------------------------------------------------------------
if candidates and PUBLISH_TO_EVENTHUB:
    producer = EventHubProducerClient(
        fully_qualified_namespace=EVENTHUB_NAMESPACE,
        eventhub_name=EVENTHUB_NAME,
        credential=DefaultAzureCredential(),
    )
    with producer:
        batch = producer.create_batch()
        for c in candidates:
            payload = EventData(json.dumps(c))
            try:
                batch.add(payload)
            except ValueError:               # batch full
                producer.send_batch(batch)
                batch = producer.create_batch()
                batch.add(payload)
        if len(batch) > 0:
            producer.send_batch(batch)
    print(f"Published {len(candidates)} events to {EVENTHUB_NAME}")

# ---------------------------------------------------------------------
# 7. Advance the watermark
# ---------------------------------------------------------------------
spark.sql(f"""
    UPDATE {SEC_SCHEMA}.detector_watermark
    SET last_start_time = TIMESTAMP'{now}'
    WHERE detector_name = '{DETECTOR_NAME}'
""")
print("Watermark advanced to", now)

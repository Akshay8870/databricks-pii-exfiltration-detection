# =====================================================================
# notebooks/attacker_pyspark.py  -  run as a Databricks NOTEBOOK
#
# THE ATTACK, IN PYTHON. No SQL statement is ever submitted: every read and
# write below goes through the Spark DataFrame API, exactly like a data
# scientist's working notebook. Several of these write FILES to ADLS rather
# than tables, so the result never becomes a governed Unity Catalog object
# at all.
#
# This is the workload the customer asked about. Run it, then run
# sql/06_notebook_spark_detection.sql to see every one of them caught.
#
# PREREQS
#   - sql/01_setup_demo_data.sql has run (gold.customer_master exists and tagged)
#   - sql/06_notebook_spark_detection.sql has run
#   - An external location / storage credential your user can write to,
#     OR just use a UC Volume (works out of the box, same lineage behaviour).
# =====================================================================

from pyspark.sql import functions as F

# ---------------------------------------------------------------------
# CONFIG - point this at somewhere you can write.
#   Option 1 (easiest, no setup): a Unity Catalog Volume.
#   Option 2 (what the customer actually described): a raw ADLS path.
# ---------------------------------------------------------------------
# Option 1 - UC Volume. Create it once:
#   CREATE VOLUME IF NOT EXISTS pii_demo.sandbox.exfil_vol;
BASE = "/Volumes/pii_demo/sandbox/exfil_vol"

# Option 2 - raw ADLS. Uncomment and set your own container/account.
# BASE = "abfss://<container>@<storageaccount>.dfs.core.windows.net/exfil_demo"

SRC = "pii_demo.gold.customer_master"
print(f"reading  {SRC}")
print(f"writing  {BASE}")


# =====================================================================
# ATTACK N1 - Split a phone number three ways, write PARQUET to storage.
#             The customer's original example, done entirely in Python.
# =====================================================================
df = spark.read.table(SRC)

n1 = (df.select(
        F.col("customer_id"),
        F.substring("phone_number", 1, 3).alias("zone_cd"),
        F.substring("phone_number", 4, 3).alias("route_cd"),
        F.substring("phone_number", 7, 4).alias("member_seq"),
        F.col("city").alias("branch_city")))

n1.write.mode("overwrite").parquet(f"{BASE}/nb_phone_parts")
print("N1 written - nb_phone_parts")
# Expect: column_fanout + column_rename + path_target + notebook_source


# =====================================================================
# ATTACK N2 - Pad and concatenate, write CSV. The 'aabbxx976444asfs5335'
#             trick, expressed as DataFrame operations.
# =====================================================================
n2 = (spark.read.table(SRC)
        .select(
            F.col("customer_id"),
            F.concat(F.lit("aabb"), F.col("phone_number"), F.lit("xxzz")).alias("ref_string"),
            F.concat_ws("|", F.col("full_name"), F.col("email")).alias("contact_blob")))

n2.write.mode("overwrite").option("header", True).csv(f"{BASE}/nb_padded_csv")
print("N2 written - nb_padded_csv")
# CSV is the worst case for the customer: plain text, no schema, no governance.


# =====================================================================
# ATTACK N3 - Base64 the national ID, write JSON.
# =====================================================================
n3 = (spark.read.table(SRC)
        .select(
            F.col("customer_id"),
            F.base64(F.col("aadhaar_number").cast("binary")).alias("token_a"),
            F.base64(F.col("pan_number").cast("binary")).alias("token_b")))

n3.write.mode("overwrite").json(f"{BASE}/nb_encoded_json")
print("N3 written - nb_encoded_json")
# Looks like tokenisation. Is reversible with one function call.


# =====================================================================
# ATTACK N4 - A full copy to storage with every column renamed to attr_NN.
#             The 'rename everything so nothing greps' approach.
# =====================================================================
src = spark.read.table(SRC)
renamed = src.select([F.col(c).alias(f"attr_{i:02d}") for i, c in enumerate(src.columns)])
renamed.write.mode("overwrite").parquet(f"{BASE}/nb_full_attr")
print("N4 written - nb_full_attr")
# Every column renamed. Lineage still maps each attr_NN to its origin column.


# =====================================================================
# ATTACK N5 - Two-hop in Python: write an intermediate TABLE, then read it
#             back and write the disguise to storage. This is the
#             derived-table case, in notebook form.
# =====================================================================
(spark.read.table(SRC)
   .select(F.col("customer_id"),
           F.col("phone_number").alias("cref"),
           F.col("dob"))
   .write.mode("overwrite").saveAsTable("pii_demo.sandbox.nb_stage_mid"))
print("N5 hop1 written - nb_stage_mid")

(spark.read.table("pii_demo.sandbox.nb_stage_mid")
   .select(F.col("customer_id"),
           F.reverse(F.col("cref")).alias("rev_ref"),
           F.year(F.col("dob")).alias("birth_yr"))
   .write.mode("overwrite").parquet(f"{BASE}/nb_stage_final"))
print("N5 hop2 written - nb_stage_final")
# Combine with sql/05_multihop_lineage.sql to catch this at source_hop >= 1.


# =====================================================================
# ATTACK N6 - Write to a table using the DataFrame API rather than SQL.
#             Proves the notebook path is not only about file writes.
# =====================================================================
(spark.read.table(SRC)
   .withColumn("mobile_digits", F.regexp_replace("phone_number", "[^0-9]", ""))
   .select("customer_id", "mobile_digits", "segment")
   .write.mode("overwrite").saveAsTable("pii_demo.sandbox.nb_api_table"))
print("N6 written - nb_api_table")


# =====================================================================
# THE SCALA EQUIVALENT - paste into a %scala cell to prove language
# independence. Lineage does not care which language produced the plan.
# =====================================================================
SCALA_CELL = r"""
%scala
import org.apache.spark.sql.functions._

val df = spark.read.table("pii_demo.gold.customer_master")

df.select(
    col("customer_id"),
    substring(col("phone_number"), 1, 5).alias("seg_one"),
    substring(col("phone_number"), 6, 5).alias("seg_two"),
    upper(col("email")).alias("contact_up"))
  .write.mode("overwrite")
  .parquet("/Volumes/pii_demo/sandbox/exfil_vol/nb_scala_parts")

println("Scala attack written - nb_scala_parts")
"""
print("\n--- paste the following into a new cell to run the Scala variant ---")
print(SCALA_CELL)


# =====================================================================
# CLEANUP (run before a repeat demo)
# =====================================================================
CLEANUP = f"""
dbutils.fs.rm("{BASE}/nb_phone_parts", True)
dbutils.fs.rm("{BASE}/nb_padded_csv", True)
dbutils.fs.rm("{BASE}/nb_encoded_json", True)
dbutils.fs.rm("{BASE}/nb_full_attr", True)
dbutils.fs.rm("{BASE}/nb_stage_final", True)
dbutils.fs.rm("{BASE}/nb_scala_parts", True)
spark.sql("DROP TABLE IF EXISTS pii_demo.sandbox.nb_stage_mid")
spark.sql("DROP TABLE IF EXISTS pii_demo.sandbox.nb_api_table")
"""
print("\n--- cleanup cell for a repeat run ---")
print(CLEANUP)


# =====================================================================
# VERIFY - lineage for PATH targets is queried by target_path, NOT by
# target_table_full_name. This is the single most common mistake.
# =====================================================================
print("\n--- run this after a few minutes to confirm capture ---")
# NOTE: lead the LIKE with % - Databricks records a Volume path as
# "dbfs:/Volumes/..." and an ADLS target may be the resolved storage URL,
# so anchoring the pattern at the start of the path returns a false zero.
_leaf = BASE.rstrip("/").split("/")[-1]
print(f"""
SELECT target_path, target_type, entity_type, created_by,
       source_column_name, target_column_name
FROM   system.access.column_lineage
WHERE  target_path LIKE '%{_leaf}%'
  AND  event_date = current_date()
ORDER BY event_time DESC;
""")

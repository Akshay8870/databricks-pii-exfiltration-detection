# Reference

| File | What |
|---|---|
| `llm-prompt-v2.md` | **The current prompt.** Recoverability decision procedure, 7 reversibility classes, entropy awareness, 4 few-shot examples. |
| `llm-prompt-v1-legacy.md` | The first version. Kept for comparison — it shows what was missing. |
| `verdict-schema.md` | Every field the model returns, what it means, and how to use it. |

## Where the prompt actually lives

The prompt is **embedded in the scorer notebooks** (`SYSTEM_PROMPT` plus an addendum per layer),
not loaded from these files. `llm-prompt-v2.md` is the readable canonical copy for review and
discussion.

If you change one, change both.

## The layer addenda

Each scorer appends a small addendum to the base prompt:

| Scorer | Addendum teaches the model |
|---|---|
| `scorer_02_multihop.py` | `source_hop` and `pii_origin_columns` — judge recoverability against the **origin** column, and treat depth as corroborating evidence, never mitigating |
| `scorer_03_spark.py` | `origin`, `column_map`, `target_is_storage_path` — a null `sql` field is **expected** for notebooks and must not lower the score; a PATH target escapes Unity Catalog controls |

These addenda matter more than they look. Without the multi-hop one, the model sees a source column
called `contact_ref` and softens its verdict. Without the Spark one, it treats missing SQL text as
missing evidence and loses confidence.

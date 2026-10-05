# Optional: Event Hub + Function App deployment

**Most users should ignore this directory.** The inline path — a Databricks notebook calling
Foundry directly, in `notebooks/` — is simpler, has no additional infrastructure, and is what the
runbooks demonstrate.

Use this path only when **the SOC owns detection** and wants events flowing into Sentinel or an
existing incident pipeline.

```
Databricks job  →  Event Hub  →  Azure Function  →  Foundry  →  verdicts → SIEM
```

| File | Purpose |
|---|---|
| `eventhub_detector_job.py` | Databricks job: reads Stage 1 candidates, publishes to Event Hub |
| `foundry_scorer_function.py` | Azure Function: consumes events, calls Foundry, emits verdicts |
| `create_serving_endpoint.py` | Helper: register Foundry as a Databricks external model endpoint |
| `sample_event.json` | Envelope shape, for wiring and testing without Databricks |

## Trade-offs

| | Inline (Option A) | Event Hub (Option B) |
|---|---|---|
| Infrastructure | None beyond Foundry | Event Hub + Function App |
| Latency | Batch, on demand | Near real-time |
| Ownership | Data platform team | SOC |
| Egress | One HTTPS call per candidate | Events leave Databricks |
| Setup time | Minutes | Hours |

**Start with Option A.** Add Option B only when the customer explicitly needs the pipeline — it is
an operating-model decision, not a technical upgrade.

# Verdict schema

The structured JSON the model returns for each candidate, enforced via `response_format`.

```json
{
  "verdict":                         "LIKELY_EXFILTRATION | SUSPICIOUS | BENIGN",
  "risk_score":                      0,
  "confidence":                      0.0,
  "recoverable":                     true,
  "reversibility_class":             "trivially_invertible",
  "technique":                       ["column_split", "rename"],
  "pii_types":                       ["phone"],
  "reidentification_by_combination": false,
  "evidence_expression":             "substr(phone_number,1,3) AS zone_cd",
  "rationale":                       "...",
  "recommended_action":              "..."
}
```

## Fields

| Field | Type | Meaning |
|---|---|---|
| `verdict` | enum | The headline call. Three values only. |
| `risk_score` | 0–100 | Severity. The rule score is a **floor** the model may raise but never lower. |
| `confidence` | 0–1 | How sure the model is of its own verdict. Low confidence on a high score is worth a human look. |
| `recoverable` | bool | **The core question.** Can the original PII value be reconstructed from what was written? |
| `reversibility_class` | enum | *How* recoverable — see below. |
| `technique[]` | strings | What was done: splitting, padding, encoding, packing, renaming… |
| `pii_types[]` | strings | What kind of PII: phone, email, national_id, name, dob… |
| `reidentification_by_combination` | bool | No single column is PII, but together they identify a person. |
| `evidence_expression` | string | The specific expression the verdict rests on. **The most useful field for an analyst** — it points straight at the smoking gun. |
| `rationale` | string | Plain-language reasoning. This is what goes in the ticket. |
| `recommended_action` | string | What the admin should actually do. |

## Reversibility classes

Ordered roughly by severity.

| Class | Meaning | Example |
|---|---|---|
| `trivially_invertible` | Reverse with no secret and no effort | split then `concat`; `reverse()` |
| `public_encoding` | A publicly-known transform | `base64`, `hex`, `unhex` |
| `exposed_secret` | Encrypted, but the key is visible in the statement | `aes_encrypt(col,'literalkey')` |
| `lookup_reversible` | Needs a mapping table — which exists and is reachable | surrogate key + its map |
| `weak_oneway_low_entropy` | Genuinely one-way, but the input space is small enough to brute-force | `sha2(phone_number, 256)` unsalted |
| `strong_oneway` | One-way with a secret salt over a large space | `sha2(concat(col, <secret>), 256)` |
| `aggregate_only` | No individual value recoverable | `count(*) … GROUP BY city` |

### Why `weak_oneway_low_entropy` matters

This class is the clearest demonstration of why Stage 2 exists.

A 10-digit Indian mobile number has roughly 10⁹ valid values. An unsalted SHA-256 of it can be
exhaustively reversed on a laptop. A rule engine sees `sha2(...)` and concludes "hashed, therefore
safe." The model recognises the input space is too small for the hash to protect anything, and
returns `SUSPICIOUS` with `recoverable: true`.

Contrast with a secret-salted hash over the same column: `strong_oneway`, `recoverable: false`,
`BENIGN`. **The SQL looks nearly identical. The security outcome is opposite.**

## Score bands

| Range | Meaning |
|---|---|
| 90–100 | Reconstructs exactly, trivially |
| 75–89 | Reconstructs with modest effort or a knowable secret |
| 50–74 | Partial recovery, or re-identification by combination |
| 25–49 | Weak signals, no clear recovery path |
| 0–24 | Benign — aggregate-only or genuinely strong one-way |

## Using it in practice

```sql
-- what an analyst triages first
SELECT target_object, verdict, risk_score, confidence,
       reversibility_class, evidence_expression, recommended_action
FROM   <catalog>.security.pii_query_verdicts
WHERE  risk_score >= 70
QUALIFY row_number() OVER (PARTITION BY statement_id ORDER BY scored_at DESC) = 1
ORDER BY risk_score DESC;
```

**Alert on `risk_score >= 70`** as a starting threshold, then tune. Route
`reidentification_by_combination = true` separately — it is a privacy-review question more than an
incident-response one.

# Contributing

## Before you open a PR

**Never commit environment-specific values.** This repository ships placeholders only. Before
committing, check that none of the following appear in your diff:

- Foundry resource names, endpoints or deployment names
- Entra tenant IDs, client IDs, client secrets
- Databricks metastore IDs, workspace IDs or URLs
- Real catalog, schema or table names from a customer environment
- Any row of real data

Secrets belong in a Databricks secret scope, never in a notebook.

## Adding a demo runbook

Runbooks follow a fixed structure so a presenter can pick any one up cold:

1. Pre-flight (what must already be running)
2. Fire the attack — 3 distinct categories, each a separate statement
3. Narrative for the slide window while lineage lands
4. Unity Catalog UI walkthrough
5. Lineage poll (always lead a path `LIKE` with `%` — see docs/07)
6. Live detection queries
7. Closer — the preventive control
8. Privacy section
9. Safety nets
10. Timing table

**Attack table names must be unique across every runbook in the repository** so that any
combination can be run back to back without collisions. Check existing names first.

## Changing setup steps

If a change affects how the solution is deployed, update **SETUP.md** — it is the authoritative
sequence. The documents in `docs/` are deep-dive references it points into; keep them consistent
but do not duplicate the step order there.

## Adding a detection rule

Rules live in the `scored` CTE of the detection views. A rule must:

- Be deterministic and explainable in one sentence to a non-engineer
- Degrade safely when `statement_text` is NULL (notebook events have no SQL text)
- Add a human-readable reason string, not just a score increment

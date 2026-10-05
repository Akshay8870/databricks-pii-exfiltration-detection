# Documentation

> **Setting up for the first time?** Use **[../SETUP.md](../SETUP.md)** — one linear sequence of 21
> steps with verification gates. The documents below are the deep-dive references it points into.

Read in order for a first setup; jump directly if you know what you need.

| Doc | Read it when |
|---|---|
| [00-architecture.md](00-architecture.md) | You want the design rationale and the two-stage flow |
| [01-prerequisites.md](01-prerequisites.md) | **Before anything else** |
| [02-databricks-setup.md](02-databricks-setup.md) | Workspace, Unity Catalog, admin rights, system schemas |
| [03-foundry-setup.md](03-foundry-setup.md) | Model deployment, auth, reasoning-model parameters |
| [04-multihop-lineage.md](04-multihop-lineage.md) | Laundering through derived tables |
| [05-spark-notebook-coverage.md](05-spark-notebook-coverage.md) | Python/Scala notebooks, ADLS file writes |
| [06-detection-internals.md](06-detection-internals.md) | The rules, the envelope, the verdict schema |
| [07-troubleshooting.md](07-troubleshooting.md) | **Something is not working** |
| [08-privacy.md](08-privacy.md) | What leaves Databricks, and what does not |

## Fastest path to a working demo

Follow **[../SETUP.md](../SETUP.md)** end to end. It sequences everything below into 21 steps and
tells you exactly what to verify at each one.

The two hard gates in that sequence:

- **The Foundry smoke test must return 200** before you go further. Every later failure becomes
  harder to diagnose, and none of them will point back here.
- **Seven tagged columns must exist** after the demo-data step. The tags drive everything; without
  them every downstream view is silently empty.

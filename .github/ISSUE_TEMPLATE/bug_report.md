---
name: Bug report
about: Something does not work as documented
---

**What you ran** (file and step number)

**What you expected**

**What happened**

**Environment**
- Databricks runtime / warehouse type:
- Unity Catalog enabled: yes / no
- Cluster access mode (Shared / Single User / No-isolation):
- Which detection views exist (`SHOW VIEWS IN <catalog>.security`):

**Checked already**
- [ ] Cluster is UC-governed (lineage is not captured otherwise)
- [ ] System schemas `system.query` and `system.access` are enabled
- [ ] Waited for lineage to land (can take minutes)
- [ ] Path filters lead with `%` (see docs/07-troubleshooting.md)

**Please do not paste real data, credentials, tenant IDs or customer table names.**

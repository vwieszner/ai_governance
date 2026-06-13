# Backup & Restore Runbook (Phase-1 item 13)

Each division is a physically-isolated stack; back up and restore **per division**. State
that matters: OpenFGA Postgres (authorization tuples), Qdrant (vectors), the Keycloak realm
(users/clients/groups), and the gitignored identity material (`did.json`, `secrets.json`,
`state.json`).

## Backup

```powershell
.venv\Scripts\python.exe scripts\backup_division.py --division alpha --stamp 20260613-1200
```

Writes `backups/alpha/20260613-1200/` containing `postgres.sql`, `qdrant_snapshot.json`,
`openfga_tuples.json`, `did.json`, `state.json`. **Also copy** the division's
`infra/generated/alpha/secrets.json` and `agt-federated-rag/.env.alpha` to your secure
secret store — they are gitignored key material and are required to restore identity/HMAC.
Schedule this (cron / Task Scheduler / a Temporal cron like the rotation workflow).

## Restore

Order matters: infra up → restore stores → restore identity → restart agents.

1. **Stand up the stack** (without provisioning): `docker compose -p agt-div-alpha ... up -d`
   (or re-run `onboard_division.py` then overwrite the stores below).
2. **Postgres (OpenFGA tuples)** — the authoritative authorization state:
   ```bash
   docker exec -i div-alpha-postgres psql -U openfga openfga < backups/alpha/<stamp>/postgres.sql
   ```
3. **Qdrant** — recover the snapshot taken at backup (snapshots live on the Qdrant volume;
   for cross-host restore, copy the snapshot file and use the Qdrant `recover` API). If the
   document set is reproducible, re-ingest via the connector instead (`FolderConnector`).
4. **Identity** — restore `did.json` + `secrets.json` + `state.json` into
   `infra/generated/alpha/`, and `.env.alpha` into `agt-federated-rag/`. The DID must match
   the one peers trust (the federation trust map), or re-run `federate_divisions.py`.
5. **Keycloak** — if the realm was lost, re-create via `onboard_division.py` (idempotent) or
   import a realm export; users from an external IdP (LDAP/broker) re-sync automatically.
6. **Restart**: `scripts\clusters.ps1 restart alpha` and verify with
   `python scripts\agtctl.py doctor --division alpha` + `python scripts\verify_audit.py`.

## What's logical vs binary

- `openfga_tuples.json` is a **logical** backup (verification / selective re-grant); the
  binary source of truth is `postgres.sql`.
- The **audit chains** (`audit_logs/`) and their anchors are append-only evidence — back
  them up read-only; never restore-overwrite them (that would erase the tamper history).

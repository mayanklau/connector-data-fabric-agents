# Production Operations

## Deployment

Run `alembic upgrade head` as a pre-deployment job, deploy the control plane and workers, then verify `/ready`. Production requires managed PostgreSQL with point-in-time recovery, Redis with persistence or a compatible managed Redis service, and all credentials supplied through the workload secret store.

## Backup And Restore

The included CronJob creates daily PostgreSQL custom-format backups and retains 14 days. Production deployments should copy the backup volume to immutable object storage and enable database PITR. Redis is a delivery mechanism, not the system of record; workflows can be re-published from PostgreSQL after broker loss.

Restore procedure:

1. Scale control-plane and worker deployments to zero.
2. Restore PostgreSQL to a new database with `pg_restore --clean --if-exists`.
3. Run `alembic upgrade head` against the restored database.
4. Point `DATABASE_URL` at the restored database.
5. Start one control-plane replica, validate cases, registrations, routes and audit records.
6. Start workers, replay queued workflows, then restore normal replica counts.

Target recovery objectives are RPO 15 minutes with managed PITR and RTO 60 minutes. Run a restore exercise quarterly and record evidence in the change-management system.

## Secrets And Identity

Use workload identity for cloud APIs. Store API keys and mTLS materials in the platform secret manager and mount them below `/run/secrets`; agent registrations reference them with `file://` or `env://`. Literal credentials are rejected outside local, demo and test environments. Rotate agent callback credentials through `POST /agents/{id}/credentials`.

## Availability

Run at least three API and worker replicas across failure domains. Configure the ingress for TLS, request limits and client certificate verification where required. The PodDisruptionBudget preserves two API replicas during voluntary disruption. Alert on Redis lag, dead-letter growth, agent circuit opening, PostgreSQL saturation and health-probe failures.

# High Availability and Multi-Replica Operation

**Audience:** platform engineers, SREs, security reviewers.
**Scope:** running more than one gateway process with `AEGIS_HA_MODE`, in active-passive or active-active mode, and what each mode does to the evidence record.
**Boundary:** covers what the source implements and what its tests and the container smoke test exercised. Capacity, availability targets and production acceptance are properties of a deployment. None is established here. Claims are governed by `CLM-108` (and `CLM-012` for the chart); the design and its costs are in [`AD-17`](../architecture/DECISIONS.md).

---

## 1. Choose a mode

| Mode | What runs | Evidence shape | External dependencies | Use it when |
| --- | --- | --- | --- | --- |
| `single` (default) | One gateway process per chain | One local WAL | Redis for the rate limiter, as before | One node is acceptable, or you shard by chain yourself |
| `active_passive` | N replicas. One holds the chain's writer lease and serves; the others stand by | **One chain** on one `ReadWriteMany` volume, with every handover recorded in it as a signed node | Redis (lease). PostgreSQL is optional and adds the storage-side epoch fence | You need failover for one chain of record |
| `active_active` | N replicas, all serving | **One chain per replica**, plus **one shared, hash-linked global sequence** that orders every node of every chain | Redis (lease per chain), PostgreSQL (sequence) | You need throughput across replicas **and** one agreed order of all evidence |

`active_active` does **not** make one WAL. Each replica's chain stays its own, signed and `fsync`-ed locally. The global sequence stores references (`chain_id`, local sequence number, node hash) in one total order. It is not a happens-before relation and not a clock.

## 2. Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AEGIS_HA_MODE` | `single` | `single`, `active_passive` or `active_active`. Anything else refuses to start. |
| `AEGIS_HA_CHAIN_ID` | host name | `active_passive`: the one shared chain (**required**). `active_active`: this replica's chain. A StatefulSet pod name is unique and stable. |
| `AEGIS_HA_REDIS_URL` | `AEGIS_REDIS_URL` | Redis holding the writer lease. |
| `AEGIS_HA_LEASE_TTL_SECONDS` | `15` (3–300) | Lease lifetime. Renewed every third. The holder stops admitting once less than `max(0.2·TTL, 0.5 s)` remains, measured from before the last renewal was sent. |
| `AEGIS_HA_STANDBY_POLL_SECONDS` | `2` (0.2–60) | How often a standby retries the lease. |
| `AEGIS_HA_SEQUENCER_URL` | empty | `postgresql://…` for the global sequence. `sqlite:///abs/path` is accepted **only** outside strict mode and only on one host. Required for `active_active`. |
| `AEGIS_HA_MAX_SEQUENCING_LAG_SECONDS` | `30` (1–3600) | Admission returns `503` while the oldest durable, unsequenced node is older than this. |

Startup refuses to run with any of the following. Each would fork evidence:

- `AEGIS_WORKERS` other than `1`
- no Redis
- `active_passive` without a chain ID
- `active_active` without a sequence store
- a sequence URL that is neither PostgreSQL nor an absolute SQLite path
- SQLite under `AEGIS_SECURITY_ENFORCEMENT_MODE=strict`

The Helm chart refuses the same shapes at render time (`ha.*` in `deploy/helm/values.yaml`; the schema limits `ha.mode` to the three values).

### Kubernetes

```yaml
# active_passive: one chain on a ReadWriteMany claim you provision
ha:
  mode: active_passive
  chainId: prod-evidence
  sharedClaim: aegis-wal-rwx
  sequencerUrlSecret: {name: aegis-ha, key: dsn}   # optional; adds the epoch fence

# active_active: one chain per pod, one global sequence
ha:
  mode: active_active
  sequencerUrlSecret: {name: aegis-ha, key: dsn}   # required
```

For `active_passive` the chart renders `podManagementPolicy: Parallel` and `updateStrategy: OnDelete`, because a standby is never Ready and an ordered rollout would wait on it forever. Roll a new version by deleting the **standby** pods first and the holder last. The chart skips `volumeClaimTemplates` and mounts `ha.sharedClaim` instead.

The shared volume must give the lease holder working `fsync` and `flock` semantics. [Storage Requirements](STORAGE_REQUIREMENTS.md) applies in full, and network filesystems are where it most often fails. Accept the volume with the WAL durability tests on the real storage class before relying on it.

## 3. What each endpoint says

| Endpoint | Lease holder or active replica | Standby |
| --- | --- | --- |
| `GET /health` | `200`, with an `ha` block: `mode`, `chain_id`, `lease.{epoch, held, seconds_remaining}`, `sequence.{lag_seconds, backlog, diverged, last_error}` and `admitting` | `200` `{"status": "standby", "chain_id": …}` |
| `GET /ready` | `200` while admitting, otherwise `503 {"status":"not-ready","ha":"<reason>"}` | `503` |
| Governed routes | Served while admitting, otherwise `503` naming the reason | `503` |

Point the load balancer at `/ready`, not `/health`.

## 4. Failure behaviour

| Event | What happens | Evidence consequence | Operator action |
| --- | --- | --- | --- |
| Holder crashes or is killed | The lease expires after at most one TTL. A standby acquires it with a new epoch, opens the WAL, and commits a signed `ha-lease-<chain>-<epoch>` node before serving | The chain stays linked and the handover sits in it | None. Check that `verify` (§5) shows increasing epochs |
| Holder loses the lease (Redis partition, pause past TTL) | It stops admitting at once, logs `chain writer lease LOST`, and shuts down. The orchestrator restarts it as a standby | A holder paused past its TTL can append **one** node to its local WAL before it notices. With a sequence store configured, that node is refused by the epoch fence and reported unsequenced by `verify` | Investigate the pause. The unsequenced node is evidence of the incident; do not delete it |
| Redis unavailable | The holder cannot renew and stops admitting within one TTL. Standbys cannot acquire | No new evidence. Nothing already written is affected | Restore Redis. Service resumes without manual steps |
| Sequence store unavailable | Local commits continue until the lag bound, then admission returns `503` | Nodes wait in the backlog and are appended in order when the store returns | Restore PostgreSQL, then watch `sequence.lag_seconds` fall |
| `diverged: true` | The store refused an append because the chain's previous entry is not this node's predecessor, or the epoch is stale. This is never retried | A second writer or a substituted WAL is in play | **Incident.** Stop the replica, preserve the WAL and the sequence, and run `verify` |
| Two replicas configured with the same chain in `active_active` | The second cannot take the lease and stays a standby | None | Fix `AEGIS_HA_CHAIN_ID` (leave it empty to use the pod name) |

## 5. Verify, as an auditor would

```bash
python -m aegis.core.ha verify \
  --sequencer "postgresql://…" \
  --wal prod-0=/data/aegis.wal.jsonl \
  --wal prod-1=/mnt/prod-1/aegis.wal.jsonl
```

The command is read-only and needs no gateway running. Exit `0` means all of the following held:

- the global sequence re-derives from its own rows, with every entry hash-linked to the previous one and no gaps;
- each named WAL is one linked chain;
- every sequenced reference names the node at that position in its WAL;
- the handover epochs recorded in each chain strictly increase.

For each chain it reports `nodes`, `linked`, `references`, `fully_sequenced` and `writer_epochs`. A chain that is linked but not fully sequenced has durable nodes the sequence never accepted: either the lag window at the moment of the read, or a fenced stale writer. Re-run after the lag bound to tell them apart.

`verify` establishes consistency between the sequence and the WALs you give it. It does not establish that those WALs are the ones the replicas wrote: that is the chain's own signature and `/v1/audit/integrity`, per replica. It also establishes nothing about time or content agreement between replicas.

## 6. Multi-team use

Teams share a gateway through what already exists: one principal per API key or OIDC identity, each with a `tenant_id`, roles and scopes ([Security](../../SECURITY.md), `python -m aegis.auth.principal` for the key mapping). Node listing, node detail, raw evidence, proofs and forensic export are filtered to the caller's tenant unless the caller is an administrator. `/v1/audit/tenants` is administrator-only.

Boundary: **`/v1/audit/integrity` is a whole-chain check.** Any holder of `audit:read` receives the chain's `valid`, `error_index`, total `node_count` and `tail_hash`, across every tenant in the chain. `/v1/audit/health` counts only the caller's visible nodes. The integrity answer therefore discloses aggregate volume and the timing of other tenants' activity, though never their content. Where that metadata is itself sensitive between teams, give each team its own chain:

- `single`: a gateway per team;
- `active_passive`: a chain ID per team;
- `active_active`: replicas per team.

Changing the integrity response would break the public JSON contract (`CLM-090`), so it stays whole-chain.

## 7. Tested and not tested

| Scope | Status | Where |
| --- | --- | --- |
| Lease acquire, renew, release, epoch order, loss detection, standby responder | Locally tested against real Redis | `tests/ha/test_ha_lease.py`, `tests/ha/test_ha_failover.py` |
| Global sequence: compare-and-append, per-chain continuity, epoch fence, verification | Locally tested against real PostgreSQL and SQLite | `tests/ha/test_ha_sequence.py`, `tests/ha/test_ha_sequencer_ledger.py` |
| Configuration and chart refusals | Locally tested; helm render tests run where helm is installed | `tests/ha/test_ha_config.py` |
| Shipped image, strict mode, real seccomp filter: `SIGKILL` failover, two active replicas, `verify` inside the image | Container smoke test, run in CI before an image is published | `scripts/container_smoke_test.py --ha` |
| Real `ReadWriteMany` storage classes, network partitions, Redis Sentinel or Cluster failover, PostgreSQL failover, sustained load, multi-zone | **Not tested** | Requires target acceptance |

---

**Related:** [AD-17](../architecture/DECISIONS.md) · [Storage Requirements](STORAGE_REQUIREMENTS.md) · [Deployment Profiles](DEPLOYMENT_PROFILES.md) · [Monitoring and Alerting](MONITORING_ALERTING.md) · [Backup and Restore](BACKUP_RESTORE.md)

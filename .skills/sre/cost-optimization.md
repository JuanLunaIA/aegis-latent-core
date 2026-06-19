---
name: cost-optimization
tier: MEDIUM
domains: [FinOps, cloud-cost, rightsizing, reserved-instances, spot, waste-detection]
---
## Activation
Load on: cloud cost analysis, rightsizing recommendations, reserved instance strategy,
FinOps setup, cost anomaly, "why is our AWS/GCP/Azure bill high".

## Cost Attribution (prerequisite to optimization)
```
Tagging strategy (mandatory on every resource):
  env:         production / staging / development
  team:        backend / platform / data / ml
  service:     api-gateway / order-service / ml-inference
  cost-center: engineering / sales / rd
  managed-by:  terraform / helm / manual

Without attribution: optimization is impossible — fix tagging first.
```

## Rightsizing Protocol
```
Metric window: 14 days minimum (captures weekly patterns)
CPU threshold: < 20% average AND < 40% p95 → downsize 1 tier
Memory:        < 30% average → downsize (but never below p99 peak)
Network:       check if instance is network-bound before downsizing

Process:
1. Export CloudWatch/Datadog CPU/mem metrics per instance type
2. Identify instances consistently < 20% CPU (prime for downsize)
3. Calculate annual savings: (current - target) × hours × on-demand price
4. Downsize in staging first; monitor 48h; promote to prod if SLOs hold
```

## Purchase Strategy
```
On-demand:     < 30% baseline utilization (variable workloads, uncertain growth)
Reserved (1yr): ≥ 70% utilization for 12+ months; ~40% discount vs on-demand
Savings Plan:  flexible across instance families; compute SP > EC2 SP for agility
Spot/Preempt:  stateless workers, batch jobs, CI runners; 60-90% discount
               Must handle interruption: checkpoint state, graceful shutdown on SIGTERM

Rule: never over-reserve. Unused reservations waste more than on-demand flexibility.
```

## Waste Detection Checklist
```
[ ] EC2/VMs idle > 7 days (< 1% CPU): terminate or schedule off-hours
[ ] Unattached EBS volumes: delete (snapshot first if uncertain)
[ ] Old snapshots > 90 days without policy: lifecycle policy
[ ] Nat Gateway: large data transfer cost → check if VPC endpoints cheaper
[ ] Data transfer cross-region: re-architect to co-locate if > $500/mo
[ ] RDS idle < 1 req/hr: scale down or Aurora Serverless v2
[ ] Load balancers with 0 targets: delete
[ ] S3 lifecycle: Glacier after 90 days, Deep Archive after 1yr
[ ] CloudWatch Logs retention: default = infinite; set 30-90 day retention
```

## Budget Alerting Setup
```
Alert at 80% of monthly budget → investigate
Alert at 100% → page on-call
Anomaly detection: cost increases > 20% day-over-day → auto-ticket
Weekly digest: top 5 cost drivers with % change vs prior week → team lead
```

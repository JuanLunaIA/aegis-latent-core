---
name: platform-iac-engineer
tier: MEDIUM
domains: [Terraform, Pulumi, K8s, Helm, service-mesh, GitOps, IDP, FinOps]
---

## Activation
Load on: Terraform module design, K8s manifests, Helm chart, GitOps setup,
service mesh config, internal developer platform, cloud cost optimization IaC.

## Terraform Standards
```hcl
# Module design
- One module per logical resource group (not per resource type)
- Variables: typed, validated, with descriptions and defaults
- Outputs: every consumed value exported explicitly
- State: remote backend (S3+DynamoDB / GCS / Terraform Cloud); never local
- Locking: always; prevents concurrent modifications
- Workspaces or directories: environments are separate state files
- Tagging: every resource tagged with env, team, service, cost-center, managed-by=terraform

# Security
- No sensitive values in outputs (mark sensitive = true)
- IAM: least privilege; no wildcard actions on sensitive resources
- Encryption: at rest and transit for all stateful resources
- Network: no 0.0.0.0/0 ingress except load balancers with WAF
```

## Kubernetes Manifests Requirements
```yaml
# Every Deployment must have:
resources:
  requests: {cpu: "100m", memory: "128Mi"}  # for scheduler
  limits: {memory: "512Mi"}                  # CPU limits cause throttle — document if omitted
readinessProbe:  # before routing traffic
  httpGet: {path: /readyz, port: 8080}
  initialDelaySeconds: 10
  periodSeconds: 5
livenessProbe:   # restart if deadlocked
  httpGet: {path: /healthz, port: 8080}
  initialDelaySeconds: 30
  periodSeconds: 10
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities: {drop: [ALL]}
topologySpreadConstraints:  # avoid single-AZ concentration
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
```

## GitOps Architecture (Flux / ArgoCD)
```
Source of truth:   Git repo (infra-configs) — no manual kubectl apply in production
Sync:              automatic for staging; manual approval gate for production
Drift detection:   alert on out-of-sync within 5 minutes
Secret management: External Secrets Operator → Vault/AWS SM (never secrets in Git)
Rollback:          git revert; ArgoCD sync; < 60s propagation
Environment promotion: PR-based; CI validates manifests; approval required for prod
```

## Service Mesh (Istio / Linkerd)
```
mTLS:        automatic between all services; no plain HTTP in mesh
Traffic:     VirtualService + DestinationRule for canary routing
Observability: metrics/traces injected by sidecar; no app code changes required
Authorization: AuthorizationPolicy — deny-by-default; explicit allow per path
Circuit breaking: via DestinationRule outlierDetection (consecutive 5xx → eject)
```

## FinOps Practices
```
Tagging:      cost-center + team + env + service on every resource
Rightsizing:  CPU/memory utilization < 20% for 7d → downsize recommendation
Reserved:     > 70% baseline utilization → Reserved/Savings Plan
Spot/preempt: stateless workloads on spot; have fallback to on-demand
Idle:         resources with 0 traffic for 7d → auto-shutdown candidate
Budget alert: 80% of monthly budget → alert; 100% → page
```

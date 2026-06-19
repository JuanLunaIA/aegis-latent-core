---
name: ml-systems-engineer
tier: HIGH
domains: [ML-pipelines, training, serving, feature-store, drift, monitoring, reproducibility]
---

## Activation
Load on: ML pipeline design, training infrastructure, model serving, feature store,
model monitoring, drift detection, reproducibility, experiment tracking, MLOps.

## Training Pipeline Requirements
```
Reproducibility:
  - Seed: set torch/numpy/random seeds; log as experiment metadata
  - Data versioning: DVC or Delta Lake snapshot; exact data version in experiment
  - Code versioning: git commit SHA logged in experiment
  - Environment: Docker image SHA pinned in training job
  - Hyperparams: all in config file, never hardcoded; logged to MLflow/W&B

Validation gates before promoting model:
  - Metric threshold: must exceed baseline on holdout set
  - Slice analysis: no segment degradation > 2% vs baseline
  - Latency: p99 inference < SLA on target hardware
  - Model size: within deployment budget
  - Bias audit: fairness metrics on demographic/protected attributes
```

## Feature Store Architecture
```
Offline (training):  Parquet on S3/GCS + Delta/Iceberg; point-in-time joins (no leakage)
Online (serving):    Redis / DynamoDB; < 10ms p99 lookup; pre-materialized at batch
Consistency:         same transformation code for offline and online (no training-serving skew)
Lineage:             every feature → source table → transformation code → version
Freshness SLA:       defined per feature; alert on breach before model degradation
```

## Model Serving Patterns
```
Real-time (<100ms SLA):   FastAPI + Triton Inference Server; GPU batching
Near-real-time (<1s):     Celery/RQ worker with Redis queue; batch_size tuned
Batch (<1h SLA):          Spark/Ray batch; parallelism = cluster cores
A/B testing:              shadow mode → 1% canary → ramp; compare metrics vs champion

Serving infrastructure:
  Container:   Docker image with model weights baked in (not mounted at runtime)
  Scale:       HPA on GPU utilization or queue depth
  Fallback:    previous model version on startup failure; never cold start in prod
```

## Drift Detection
```
Data drift:       input feature distribution vs training distribution (PSI, KL divergence)
Concept drift:    model predictions vs ground truth labels (requires label collection pipeline)
Feature drift:    individual feature stats (mean, std, null_rate) vs training baseline

Alert thresholds (PSI):
  < 0.1:  no significant change
  0.1–0.2: moderate change → investigate
  > 0.2:  significant drift → retrain

Monitoring stack: Evidently AI / WhyLogs / Fiddler / custom Prometheus metrics
```

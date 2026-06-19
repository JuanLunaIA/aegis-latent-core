---
name: experimentation
tier: MEDIUM
domains: [A/B-testing, statistics, significance, sample-size, feature-flags, causal]
---
## Activation
Load on: A/B test design, experiment analysis, statistical significance, sample size,
feature flag rollout, causal inference, "is this result significant", metrics lift.

## Experiment Design (before launching)
```
1. Hypothesis:   "Changing X will improve metric M by Δ because [mechanism]"
2. Primary metric: ONE metric that defines success (avoid metric shopping)
3. Guardrail metrics: metrics that must NOT degrade (latency, error rate, revenue)
4. Sample size:  calculate BEFORE launch (power analysis)
5. Duration:     ≥ 1 full business cycle (1-2 weeks); capture weekly seasonality
6. Randomization: unit (user/session); consistent assignment (sticky bucketing)
```

## Sample Size Calculation
```
Inputs:
  Baseline conversion rate (p):     e.g. 10%
  Minimum detectable effect (MDE):  e.g. 1% absolute (10% → 11%)
  Significance level (α):           0.05 (5% false positive rate)
  Power (1−β):                      0.80 (80% chance to detect true effect)

Rule of thumb (per variant), proportion metric:
  n ≈ 16 × p(1−p) / MDE²   (for α=0.05, power=0.80)

Smaller MDE → exponentially larger sample. Don't run underpowered tests
(can't detect effect = wasted time + false "no difference" conclusion).

Tools: statsmodels (Python), Evan Miller's calculator, internal experimentation platform
```

## Analysis (avoid common errors)
```
Statistical significance: p < 0.05 means "if no true effect, ≤5% chance of this result"
                          NOT "95% chance the effect is real"

Peeking problem:    checking results repeatedly inflates false positive rate
                    → fix sample size in advance OR use sequential testing (mSPRT, always-valid p-values)

Multiple comparisons: testing many metrics → some significant by chance
                    → Bonferroni correction or control FDR; pre-register primary metric

Practical vs statistical: significant but tiny effect (0.01% lift) = not worth shipping
                    → report effect size + confidence interval, not just p-value

Novelty/primacy effect: new feature gets attention spike that fades
                    → run long enough for behavior to stabilize
```

## Output Format
```
Experiment: [name]
Hypothesis: [statement]
Result:     [PRIMARY METRIC] [baseline] → [variant] ([+X% lift], CI [low, high], p=[value])
Guardrails: [latency/error/revenue: held / degraded]
Sample:     [N per variant], [duration], [powered for MDE of X%]
Decision:   SHIP / NO-SHIP / EXTEND / ITERATE
Rationale:  [statistical + practical significance + guardrail status]
```

## When NOT to A/B Test
```
Low traffic:        can't reach significance in reasonable time → ship + monitor, or qualitative
Strategic bets:     foundational changes you'll do regardless → ship + measure, don't gate
Ethical concerns:   can't withhold beneficial feature (use rollout monitoring instead)
Network effects:    user-to-user features (cluster randomization or switchback, not user-level)
```

# NEXUS Agents
Focused system prompts for domain-specific Claude Code sessions.

## Usage
```bash
# Claude Code — activar agente específico
claude --system-prompt .agents/backend-fastapi.md

# O en CLAUDE.md de un subdirectorio específico
echo "Load agent: $(cat .agents/backend-fastapi.md)" > src/api/CLAUDE.md
```

## Agent Index
| Agent | Domain | When to use |
|---|---|---|
| `backend-fastapi.md` | Python/FastAPI | REST APIs, async services, DB layer |
| `security-researcher.md` | Offensive/Defensive sec | Audits, RE, forensics, vuln research |
| `llm-integration.md` | AI/LLM engineering | RAG, agents, evals, prompt design |
| `devops-iac.md` | Platform/DevOps | K8s, Terraform, CI/CD, GitOps |
| `data-platform.md` | Data engineering | Pipelines, dbt, Spark, Kafka |
| `ml-platform.md` | ML systems | Training infra, serving, monitoring |
| `sre-reliability.md` | SRE | SLOs, chaos, postmortems, oncall |
| `compliance-engineer.md` | GRC/Compliance | SOC2, HIPAA, GDPR, PCI, ISO27001 |
| `incident-commander.md` | Incident response | P0/P1 war room coordination |
| `full-stack-architect.md` | Architecture | System design, ADRs, cross-domain |
| `frontend-engineer.md` | Web frontend | React/Vue UI, state, perf, a11y |
| `mobile-engineer.md` | Mobile | iOS/Android/RN/Flutter, offline-first |
| `qa-sdet.md` | QA/SDET | Test strategy, automation, quality gates |
| `product-manager.md` | Product | PRDs, roadmaps, OKRs, experiments |
| `staff-engineer.md` | Tech leadership | Cross-cutting design, hard trade-offs |

---

## Tier-4 / Aegis Agents (added)

| Agent | Role |
|---|---|
| `systems-rust-kernel` | Low-level Rust, PyO3 boundaries, SIMD intrinsics, compiler/linker flags. Hardware-tiered (runtime feature detection, portable baseline). Measure-first: invokes profiler before any perf claim. Defensive scope. |
| `ai-forensics-analyst` | LLM output forensics — token logprobs/perplexity, entropy, KL-divergence drift. Prefers provider logprobs (free, true signal) over local re-estimation. High-surprise = flag for review, never silent block. |

Pairs with `/verify-ledger` (MMR continuity + ML-DSA/HMAC signature integrity, executor-verified).

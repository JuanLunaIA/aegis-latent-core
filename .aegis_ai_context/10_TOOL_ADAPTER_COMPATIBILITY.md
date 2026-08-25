# AI Tool Adapter Compatibility

This file maps repository-owned guidance to the instruction mechanisms documented by major coding-assistant tools. It does not grant authority, expose private reasoning traces, or make tool behavior identical across products. Each tool may add user, organization, system, or path-scoped policy that is outside this repository.

## Canonical policy and adapters

| Tool surface | Repository entry point | Loading model used here | Boundary |
|---|---|---|---|
| OpenAI Codex | [`AGENTS.md`](../AGENTS.md) | Codex discovers `AGENTS.md` from the project root and applies more-specific files when present. This repository intentionally has one root policy and no `AGENTS.override.md`. | The default aggregate instruction budget is bounded; deep project detail remains progressively disclosed through [`.aegis_ai_context/README.md`](README.md). |
| Anthropic Claude Code | [`CLAUDE.md`](../CLAUDE.md) | The one-line `@AGENTS.md` import loads the canonical shared policy through Claude Code's documented import mechanism. | Repository prose is advisory. Permissions, sandboxing, hooks, and user/organization policy remain external. |
| Google Gemini CLI | [`GEMINI.md`](../GEMINI.md) | The one-line `@./AGENTS.md` import loads the canonical shared policy through Gemini CLI's documented context import mechanism. | Descendant context and user/global memory may also apply. Verify effective context in the actual CLI session. |
| GitHub Copilot | [`.github/copilot-instructions.md`](../.github/copilot-instructions.md) | A thin repository instruction file routes GitHub surfaces to `AGENTS.md` and repeats only the release and untrusted-input boundaries needed when automatic agent-file support is unavailable. | Copilot support and precedence differ by IDE, CLI, coding agent, and GitHub.com surface. Do not assume one surface's precedence on another. |
| Cursor | [`AGENTS.md`](../AGENTS.md) | Current Cursor documentation supports `AGENTS.md`; the legacy root `.cursorrules` file was removed. | No `.cursor/rules/*.mdc` files are added because no durable path-specific divergence has been demonstrated. |
| Generic LLM/indexer | [`llms.txt`](../llms.txt) | Compact navigation only; agents should open authoritative sources and tests named there. | `llms.txt` is not an executable policy format and cannot override authorization or evidence. |

## Zero-context startup procedure

1. Read the tool-native root adapter above and then [`AGENTS.md`](../AGENTS.md).
2. Record `git rev-parse HEAD`, `git status --short`, the task scope, and paths that may be modified.
3. Open [the context router](README.md) and follow only the task-relevant route.
4. Verify release, package, architecture, security, and claims statements against the authoritative files named in that route.
5. Inspect implementation, direct callers, configuration, and nearest tests before editing.
6. Run focused component checks, then the relevant gates in [`09_COMMAND_AND_CI_MATRIX.md`](09_COMMAND_AND_CI_MATRIX.md).
7. Stop on stale manifest bytes, failed required checks, scope expansion, secrets, unreviewed publication actions, or unsupported external-acceptance claims.
8. Report exact commands, exit states, skips, limitations, changed files, and rollback. Do not supply or request private reasoning traces; provide reproducible evidence and concise decision rationale instead.

## Drift verification

Run:

```bash
python scripts/generate_ai_context_manifest.py --check
python scripts/verify_ai_context_manifest.py
pytest -q tests/test_ai_context.py
```

The tests verify adapter existence, thin imports, legacy-rule removal, source-derived package/workflow/version mappings, release-state language, and manifest integrity. A pass establishes repository consistency for the checked bytes; it does not prove how a hosted product combined repository, user, organization, or system instructions.

## Official references

1. [OpenAI Codex: AGENTS.md repository instructions](https://developers.openai.com/codex/agent-configuration/agents-md)
2. [Anthropic Claude Code: memory and CLAUDE.md](https://code.claude.com/docs/en/memory)
3. [Google Gemini CLI: GEMINI.md context files](https://geminicli.com/docs/cli/gemini-md/)
4. [GitHub Copilot: repository custom instructions](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions-in-your-ide/add-repository-instructions-in-your-ide)
5. [Cursor: project rules and AGENTS.md](https://cursor.com/docs/rules)

# @vorim/agent-audit

> Free AI agent code hygiene checker. Scans your project for the three most
> common identity anti-patterns: hardcoded LLM keys, shared credentials across
> agents, and long-lived permissions.

```bash
npx @vorim/agent-audit
```

That's it. No signup, no API key, no upload. Scans the current directory and
prints a report. Zero data leaves your machine.

---

## Why this exists

If you ship AI agents to production, you've probably seen one of these patterns:

```typescript
// One key, shared by every agent.
const llm = new OpenAI({ apiKey: 'sk-proj-abcd…' });

const researcher = new Agent({ llm });
const writer    = new Agent({ llm });
const critic    = new Agent({ llm });
```

```yaml
# Permissions that never expire.
agent:
  scope: "*"
  role: admin
  expires_at: null
```

```python
# OPENAI_API_KEY = "sk-proj-…" committed to .env in the repo
```

Each of these is fine in isolation. Together, they make an incident impossible
to investigate. When something goes wrong at 3am, you can't say *which* agent
did it, *what* it was allowed to do, or how to revoke its authority without
breaking five workflows.

`agent-audit` finds these patterns in 30 seconds, points at the file and line,
and tells you how to fix each one.

---

## What it scans

- **Hardcoded API keys** for: OpenAI, Anthropic, Google AI / Gemini, AWS Bedrock,
  Azure OpenAI, Hugging Face, Replicate, Cohere, Mistral, Perplexity, Groq,
  Pinecone, LangSmith, Stripe, GitHub PATs, Slack tokens.
- **Shared credentials** — one key passed to multiple agent definitions in the
  same file (LangChain, CrewAI, custom orchestrators).
- **Long-lived permissions** — wildcard scopes (`scope: "*"`), admin/root roles,
  permissions without expiry or with TTL set to zero.

The scanner walks TypeScript, JavaScript, Python, Go, Rust, Java, JSON, YAML,
TOML, `.env` files, and shell scripts. It skips `node_modules`, `dist`, `.git`,
virtual environments, and binary files by default.

## What it does NOT do

- ❌ Phone home. Nothing leaves your machine.
- ❌ Require a Vorim account or API key.
- ❌ Lock features behind a paid tier.
- ❌ Compete with TruffleHog or GitLeaks on generic secret scanning. Use those
  alongside this — they cover different ground.

---

## Install

### One-off (recommended)

```bash
npx @vorim/agent-audit
```

### Global

```bash
npm install -g @vorim/agent-audit
vorim-audit
```

### As a dev dependency

```bash
npm install --save-dev @vorim/agent-audit
```

Then add to your `package.json`:

```json
{
  "scripts": {
    "audit:agents": "vorim-audit --fail-on high"
  }
}
```

---

## Usage

```bash
# Scan the current directory
vorim-audit

# Scan a specific path
vorim-audit ./services/api

# Machine-readable JSON output (for CI / piping)
vorim-audit --json > audit.json

# Write JSON to a file
vorim-audit --output audit.json

# Control the exit code policy in CI
vorim-audit --fail-on critical   # default: exit 2 on critical findings
vorim-audit --fail-on high       # exit 1 on high+ findings
vorim-audit --fail-on medium     # exit 1 on any findings
vorim-audit --fail-on none       # never exit non-zero
```

### Exit codes

| Code | Meaning                                                  |
|------|----------------------------------------------------------|
| 0    | No findings at or above the `--fail-on` threshold        |
| 1    | High-severity findings at the threshold                  |
| 2    | Critical findings                                        |
| 99   | Internal error (file unreadable, etc.)                   |

---

## Programmatic API

```typescript
import { runScan } from '@vorim/agent-audit';

const result = await runScan({ rootDir: './services' });

console.log(`Scanned ${result.filesScanned} files in ${result.durationMs}ms`);
for (const f of result.findings) {
  console.log(`${f.severity}: ${f.file}:${f.line} — ${f.message}`);
}
```

---

## Example output

```
  Vorim agent-audit  v0.1.0
  Scanned 47 files in /Users/you/your-project (84ms)

services/agents/researcher.ts
  ✖ CRITICAL  12:11  hardcoded-key:openai
    OpenAI API key found in source.
    matched: sk-p…********…cdef
    └─ const client = new OpenAI({ apiKey: 'sk-proj-abc…' });
    fix: Move this key to a secret manager. Issue a short-lived, per-agent
         identity instead of sharing the master key.

services/agents/orchestrator.py
  ⚠ HIGH      8:1   shared-credential:multi-agent
    One credential (`OPENAI_API_KEY`) is passed to 3 agent definitions in this
    file. When all agents share an identity, you cannot tell which agent did
    what during an incident.
    fix: Issue a per-agent identity. Each agent should authenticate with its
         own short-lived credential so audit trails attribute actions correctly.

config/agent-policy.yaml
  ⓘ MEDIUM    3:9   long-lived:wildcard-scope-
    Agent configuration uses wildcard scope ("*"). Permissions without scope
    or expiry are the #1 blast-radius multiplier in agent incidents.
    fix: Set an explicit TTL (typically 2-24 hours). Use least-privilege
         scopes per agent action — never wildcard or admin.

Summary
  1 critical · 1 high · 1 medium

────────────────────────────────────────────────────────────
  Vorim Agent Identity Scorecard tests 10 broader best practices
  in 4 minutes — https://vorim.ai/agent-identity-scorecard
```

---

## Use in CI

GitHub Actions:

```yaml
- name: Audit agent code
  run: npx @vorim/agent-audit --fail-on high
```

Pre-commit hook (with [Husky](https://typicode.github.io/husky/)):

```json
{
  "scripts": {
    "audit:agents": "vorim-audit --fail-on critical --silent"
  }
}
```

---

## What this catches in practice

Run it on a typical LangChain or CrewAI project and you'll see one or more of:

1. **An OpenAI key committed to `.env` in a repo with a public mirror** — most
   common single finding. Costs companies thousands per month in unauthorised
   billing.
2. **Three agents instantiated with the same `OPENAI_API_KEY`** — the standard
   LangChain tutorial pattern. Means you can't tell from logs which agent ran
   a tool call.
3. **A `scope: "*"` on an agent config** — usually copied from a dev-only
   example that made it to staging.

Catching any one of these before it ships is worth the 30 seconds.

---

## Beyond this tool

`agent-audit` finds the three most common surface-level issues. The actual
identity layer underneath your agents — per-agent cryptographic keypairs,
scoped permission grants with expiry, hash-linked signed audit chains, and
verifiable revocation — is what closes the gap permanently.

That's what **[Vorim](https://vorim.ai)** is. Free tier supports 3 agents and
10K events per month with no credit card required.

To see how your current setup stacks up against the four primitives, the free
**[Agent Identity Scorecard](https://vorim.ai/agent-identity-scorecard)** is
10 questions, 4 minutes, and gives you a personalised report.

---

## Known limitations (v0.1)

- The `long-lived` rule uses regex, not AST. It can fire on code *describing*
  permission patterns (blog posts, documentation, error messages) rather than
  actual config. False-positive rate on production codebases is ~1-2%.
- The shared-credential rule uses proximity heuristics. If your agent
  instantiation spans more than 200 characters between the credential argument
  and the constructor name, it may miss the link.
- Python AST parsing is not yet supported — Python files are scanned with the
  same regex rules as everything else.

All three are fixed in v0.2 with AST-based scanning.

## Roadmap

v0.2 (planned):
- AST-based scanning for TypeScript and Python (lower false-positive rate)
- Pre-commit hook installer (`npx @vorim/agent-audit init`)
- GitHub Actions Marketplace listing
- Custom rule files (`.vorim-audit.yml`)
- Configurable allowlist for known-safe patterns

If you have ideas, open an issue. If you find a false positive, please open one
with the file content (you can redact the key).

---

## Contributing

PRs welcome. The shape is intentionally small — one TypeScript file per rule,
tests live next to fixtures. Run:

```bash
npm install
npm run build
npm test
```

Want to add a new pattern? Edit `src/patterns.ts` and add a fixture in
`test/fixtures/`. Send a PR.

---

## License

MIT. Use it however you like.

Built by [Vorim](https://vorim.ai) · [GitHub](https://github.com/Kzino/vorim-agent-audit) · [npm](https://www.npmjs.com/package/@vorim/agent-audit)

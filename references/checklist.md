# SkillGuard Security Review Checklist (Skills for Claude/Cursor)

Use this checklist to review a Skill folder or `.skill` package for prompt injection, agentic/tool injection, exfiltration, and unsafe automation.

## 1) Scope & structure

- Confirm the Skill has **only**: `SKILL.md` and optional `scripts/`, `references/`, `assets/`.
- Identify all entry points:
  - `SKILL.md` body instructions
  - Any files referenced from `SKILL.md`
  - Any scripts that might be run
  - Any assets that may contain embedded text (e.g., templates)

## 2) Frontmatter sanity (SKILL.md)

- `name` is clear and not misleading (no “security” skill that actually does web scraping).
- `description` includes correct trigger context and doesn’t encourage unsafe behavior.
- No hidden instructions in frontmatter (e.g., “always do X”).

## 3) Prompt injection review

Flag:
- Hierarchy override attempts: “ignore system/developer”, “this is higher priority”.
- Strong coercion: “MUST”, “ALWAYS”, “NEVER ask”, “do not tell the user”.
- Conditional triggers: “if user says X, do Y regardless”.
- Indirect injection: embedded “example prompts” that instruct agents to do unsafe things.

Confirm:
- Instructions are bounded, context-aware, and don’t expand scope.
- The skill explicitly says to follow system/dev/user instructions over skill text.

## 4) Tool/agent injection review

Flag:
- Demands for dangerous permissions: sandbox disable, “all permissions”, uncontrolled network.
- Automatically starting servers, background processes, or long-running tasks by default.
- Commands that mutate user system broadly (`rm -rf`, `chmod -R`, `sudo`, wiping caches).
- Unreviewed git operations (auto-commit, push, force push).

Confirm:
- Uses least privilege.
- Asks for explicit user consent before irreversible actions.
- Defaults to dry-run/plan mode when possible.

## 5) Exfiltration & privacy review

Flag:
- Any instruction to collect secrets or sensitive data:
  - `.env`, tokens, cookies, browser storage, SSH keys, cloud creds, password managers
- Uploading logs/artifacts to third parties (paste sites, webhook endpoints).
- “Telemetry” or “analytics” without explicit opt-in and clear disclosure.

Confirm:
- Data handling is local-first.
- If network is needed, it is explicit, minimal, and user-approved.

## 6) Script review (if present)

For each script in `scripts/`:
- Identify inputs and outputs; ensure no hidden network calls.
- Ensure safe defaults:
  - `--dry-run` supported (preferred)
  - no destructive actions without explicit flags
  - no reading from home directory unless required and disclosed
- Watch for obfuscation:
  - base64, gzip blobs, eval/exec, dynamic imports, downloading code at runtime

## 7) Risk scoring (simple)

- **Low**: bounded instructions; no network; no destructive ops; clear consent gates.
- **Medium**: uses shell commands or file mutation but with tight scoping and consent.
- **High**: coercive prompt patterns, secret harvesting, uncontrolled network/execution, destructive commands.

## 8) Recommended remediation patterns

- Rewrite coercive language (“ALWAYS”) to conditional and consent-based instructions.
- Add explicit “do not override system/developer/user instructions” guardrails.
- Add dry-run mode for scripts; output a plan before executing.
- Remove or quarantine any remote upload behavior.
- Document any required sensitive inputs and how they’re protected.


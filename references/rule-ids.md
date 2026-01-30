# SkillGuard Rule ID Reference

This document provides a complete reference for all security detection rule IDs used by SkillGuard.

## Naming Convention

Rule IDs follow the pattern: `CATEGORY-NNN`

- **CATEGORY**: 6-letter prefix indicating the threat category
  - `PROMPT`: Prompt injection and system override attempts
  - `EXFIL`: Data exfiltration and credential harvesting
  - `DESTRUCT`: Destructive operations and system modifications
  - `OBFUSC`: Code obfuscation and dynamic execution
- **NNN**: 3-digit sequential number (001, 002, 003, etc.)

## Rule Categories

### PROMPT - Prompt Injection Patterns

| Rule ID | Severity | Pattern Type | Description |
|---------|----------|--------------|-------------|
| PROMPT-001 | CRITICAL | prompt_override | Attempts to override system instructions or developer messages |
| PROMPT-002 | CRITICAL | prompt_override | Instructions to disregard or override system/developer policies |
| PROMPT-003 | HIGH | coercion | Coercive language attempting to bypass user consent |
| PROMPT-004 | HIGH | hidden_trigger | Hidden conditional triggers that activate malicious behavior |
| PROMPT-005 | MEDIUM | role_claim | Claims of higher priority to override normal processing |
| PROMPT-006 | CRITICAL | jailbreak | Jailbreak attempts to bypass safety restrictions |
| PROMPT-007 | CRITICAL | system_prompt_injection | Attempts to inject content into system prompts or rules |

### EXFIL - Data Exfiltration Patterns

| Rule ID | Severity | Pattern Type | Description |
|---------|----------|--------------|-------------|
| EXFIL-001 | CRITICAL | secrets | Instructions to extract or exfiltrate API keys, tokens, or credentials |
| EXFIL-002 | CRITICAL | secrets | Instructions to extract cookies for exfiltration |
| EXFIL-003 | CRITICAL | creds_paths | Instructions to access credential storage paths (~/.ssh, ~/.aws, etc.) |
| EXFIL-004 | HIGH | env_files | Instructions to read .env files containing secrets |
| EXFIL-005 | CRITICAL | upload | Instructions to upload data to external services (pastebin, webhooks) |
| EXFIL-006 | HIGH | upload | Network upload commands using curl |
| EXFIL-007 | CRITICAL | browser_data | Instructions to extract browser storage or profile data |

### DESTRUCT - Destructive Operations

| Rule ID | Severity | Pattern Type | Description |
|---------|----------|--------------|-------------|
| DESTRUCT-001 | CRITICAL | destructive_cmd | Recursive delete commands that can destroy data |
| DESTRUCT-002 | CRITICAL | destructive_cmd | File system formatting commands |
| DESTRUCT-003 | HIGH | privilege | Privilege escalation commands |
| DESTRUCT-004 | HIGH | git_danger | Dangerous git operations (force push, hard reset) |
| DESTRUCT-005 | MEDIUM | chmod_chown | Recursive permission changes |
| DESTRUCT-006 | CRITICAL | format_disk | Disk formatting or low-level disk operations |

### OBFUSC - Code Obfuscation

| Rule ID | Severity | Pattern Type | Description |
|---------|----------|--------------|-------------|
| OBFUSC-001 | MEDIUM | obfuscation | Base64 encoding (potential obfuscation) |
| OBFUSC-002 | HIGH | obfuscation | Dynamic code execution (eval/exec) |
| OBFUSC-003 | CRITICAL | downloads_code | Downloading and executing code from the internet |
| OBFUSC-004 | MEDIUM | obfuscation | Base64 decoding or decryption operations |

## Severity Levels

- **CRITICAL**: Immediate security risk requiring urgent attention
- **HIGH**: Significant security concern that should be addressed
- **MEDIUM**: Moderate risk that warrants review
- **LOW**: Minor concern or potential false positive

## Rule ID Suffixes

When findings are detected in defensive documentation or code examples, the rule ID may be appended with a suffix:

- `_in_guidance`: Finding appears in security guidance/checklist (severity reduced)
- `_code_example`: Finding appears in code example blocks (severity reduced)
- `_pattern_description`: Finding appears in pattern definition comments (severity reduced)
- `_legitimate_usage`: Finding is legitimate usage (e.g., document.cookie in web dev)

## Adding New Rules

When adding new detection patterns:

1. Choose the appropriate category prefix
2. Use the next sequential number in that category
3. Follow the format: `(kind, severity, regex, rule_id, description)`
4. Update this reference document

Example:
```python
(
    "new_pattern",
    "HIGH",
    r"\bpattern\b",
    "PROMPT-008",  # Next number in PROMPT category
    "Description of what this pattern detects",
)
```

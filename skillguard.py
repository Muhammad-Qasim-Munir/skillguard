#!/usr/bin/env python3
"""
SkillGuard - Static security scanner for Claude/Cursor Skills.

Usage:
  python3 scripts/skillguard.py /path/to/skill-folder
  python3 scripts/skillguard.py /path/to/file.skill
  python3 scripts/skillguard.py /path/to/skill --format json --output report.json
  python3 scripts/skillguard.py /path/to/skill --format sarif --fail-on-findings

Outputs a markdown report to stdout and (by default) writes SECURITY_REVIEW.md
into the scanned folder (or next to the .skill file when scanning an archive).

Supports multiple output formats: markdown (default), json, sarif, table.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import textwrap
import uuid
import zipfile
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


MAX_FILE_BYTES = 2_000_000  # keep it safe and fast

# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    GRAY = "\033[90m"
    
    @staticmethod
    def disable():
        """Disable colors (for non-TTY or when NO_COLOR env var is set)."""
        Colors.RESET = ""
        Colors.BOLD = ""
        Colors.RED = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.MAGENTA = ""
        Colors.CYAN = ""
        Colors.GREEN = ""
        Colors.GRAY = ""


def _should_use_colors() -> bool:
    """Determine if colors should be used."""
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


@dataclass(frozen=True)
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    kind: str
    rule_id: str
    path: str
    line: Optional[int]
    excerpt: str
    evidence: str
    message: Optional[str] = None


# Pattern format: (kind, severity, regex, rule_id, description)
INJECTION_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    # kind, severity, regex, rule_id, description
    (
        "prompt_override",
        "CRITICAL",
        r"\bignore (all|any|previous|earlier) (instructions|system|developer)\b",
        "PROMPT-001",
        "Attempts to override system instructions or developer messages",
    ),
    (
        "prompt_override",
        "CRITICAL",
        r"\b(disregard|override) (system|developer|policy)\b",
        "PROMPT-002",
        "Instructions to disregard or override system/developer policies",
    ),
    (
        "coercion",
        "HIGH",
        r"\b(MUST|ALWAYS|NEVER)\b.{0,80}\b(ask|confirm|permission|consent)\b",
        "PROMPT-003",
        "Coercive language attempting to bypass user consent",
    ),
    (
        "hidden_trigger",
        "HIGH",
        r"\b(if|when)\b.{0,60}\b(you see|you notice|the user says)\b.{0,40}\bthen\b",
        "PROMPT-004",
        "Hidden conditional triggers that activate malicious behavior",
    ),
    (
        "role_claim",
        "MEDIUM",
        r"\b(this|the) (skill|document) (is|has) (higher|highest) priority\b",
        "PROMPT-005",
        "Claims of higher priority to override normal processing",
    ),
    (
        "jailbreak",
        "CRITICAL",
        r"\b(jailbreak|dan|do anything now|unrestricted|no limits|ignore safety)\b",
        "PROMPT-006",
        "Jailbreak attempts to bypass safety restrictions",
    ),
    (
        "system_prompt_injection",
        "CRITICAL",
        r"\b(copy.*into.*system prompt|add.*to.*rules|system message|developer message)\b",
        "PROMPT-007",
        "Attempts to inject content into system prompts or rules",
    ),
]

EXFIL_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    # Focus on credential-harvesting patterns, not just mentions of credentials in code examples.
    (
        "secrets",
        "CRITICAL",
        r"\b(read|extract|harvest|collect|send|upload|exfil|leak|steal|grab|fetch|get)\b.{0,60}\b(api[- ]?key|access[- ]?token|refresh[- ]?token|bearer\s+token|secret(\s*key)?|password|credential|auth\s*token)\b",
        "EXFIL-001",
        "Instructions to extract or exfiltrate API keys, tokens, or credentials",
    ),
    (
        "secrets",
        "CRITICAL",
        r"\b(read|extract|harvest|collect|send|upload|exfil|leak|steal|grab|fetch|get)\b.{0,60}\b(session\s*)?cookie\b",
        "EXFIL-002",
        "Instructions to extract cookies for exfiltration",
    ),
    (
        "creds_paths",
        "CRITICAL",
        r"\b(read|access|open|readfile|cat|grep)\b.{0,40}~\/\.(ssh|aws|config|netrc)\b",
        "EXFIL-003",
        "Instructions to access credential storage paths (~/.ssh, ~/.aws, etc.)",
    ),
    (
        "env_files",
        "HIGH",
        r"\b(read|load|import|require|source)\b.{0,40}\.env(\b|[^a-zA-Z0-9_])",
        "EXFIL-004",
        "Instructions to read .env files containing secrets",
    ),
    (
        "upload",
        "CRITICAL",
        r"\b(pastebin|webhook|ngrok|requestbin)\b",
        "EXFIL-005",
        "Instructions to upload data to external services (pastebin, webhooks)",
    ),
    (
        "upload",
        "HIGH",
        r"\bcurl\b.{0,80}\b(http|https):\/\/",
        "EXFIL-006",
        "Network upload commands using curl",
    ),
    (
        "browser_data",
        "CRITICAL",
        r"\b(read|extract|access|get)\b.{0,60}\b(browser.*data|localStorage|sessionStorage|indexedDB|chrome.*profile|firefox.*profile)\b",
        "EXFIL-007",
        "Instructions to extract browser storage or profile data",
    ),
]

DESTRUCTIVE_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    (
        "destructive_cmd",
        "CRITICAL",
        r"\brm\s+-rf\b",
        "DESTRUCT-001",
        "Recursive delete commands that can destroy data",
    ),
    (
        "destructive_cmd",
        "CRITICAL",
        r"\bmkfs(\.|_)?\w*\b",
        "DESTRUCT-002",
        "File system formatting commands",
    ),
    (
        "privilege",
        "HIGH",
        r"\bsudo\b",
        "DESTRUCT-003",
        "Privilege escalation commands",
    ),
    (
        "git_danger",
        "HIGH",
        r"\bgit\s+(push\s+--force|reset\s+--hard|clean\s+-fd)\b",
        "DESTRUCT-004",
        "Dangerous git operations (force push, hard reset)",
    ),
    (
        "chmod_chown",
        "MEDIUM",
        r"\b(chmod|chown)\s+-R\b",
        "DESTRUCT-005",
        "Recursive permission changes",
    ),
    (
        "format_disk",
        "CRITICAL",
        r"\b(dd\s+if=|fdisk|parted|mkfs|format\s+\w+:\s*|format\s+[a-z]:)\b",
        "DESTRUCT-006",
        "Disk formatting or low-level disk operations",
    ),
]

OBFUSCATION_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    (
        "obfuscation",
        "MEDIUM",
        r"\bbase64\b",
        "OBFUSC-001",
        "Base64 encoding (potential obfuscation)",
    ),
    (
        "obfuscation",
        "HIGH",
        r"\b(eval|exec|__import__|compile)\b",
        "OBFUSC-002",
        "Dynamic code execution (eval/exec)",
    ),
    (
        "downloads_code",
        "CRITICAL",
        r"\b(pip\s+install|npm\s+install|curl\b.{0,40}\|\s*(sh|bash)|wget\b.{0,40}\|\s*(sh|bash))\b",
        "OBFUSC-003",
        "Downloading and executing code from the internet",
    ),
    (
        "obfuscation",
        "MEDIUM",
        r"\b(from\s+base64|import\s+base64|decode|decrypt)\b",
        "OBFUSC-004",
        "Base64 decoding or decryption operations",
    ),
]


TEXT_EXTS = {".md", ".txt", ".py", ".js", ".ts", ".tsx", ".json", ".yaml", ".yml", ".sh"}


def _is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    # Heuristic: treat SKILL.md as text regardless
    if path.name.lower() == "skill.md":
        return True
    # Cursor rules files (no extension)
    if path.name.lower() in (".cursorrules", ".cursor-rules", "cursorrules", "cursor-rules"):
        return True
    # Files in .cursor/rules/ directory
    if ".cursor" in path.parts and "rules" in path.parts:
        return True
    return False


def _read_small_text(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        return ""
    # best-effort decode
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return ""


def _scan_text(rel_path: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()

    def adjusted(sev: str, kind: str, i: int, line: str) -> Tuple[str, str]:
        """
        Reduce false positives:
        1. Code examples in markdown (backticks, indented blocks)
        2. Defensive documentation quoting attack patterns
        3. Legitimate web dev patterns (document.cookie, localStorage, etc.)
        4. Comments and pattern definitions in code files
        """
        l = line.lower().strip()
        line_stripped = line.strip()
        
        # Filter out comments/strings that describe patterns (not instructions) - applies to all files
        if line_stripped.startswith("#") or line_stripped.startswith("//"):
            # Comments describing patterns are not instructions
            if any(word in l for word in ["pattern:", "regex", "match", "flag", "check for", "look for", "evidence:", "r\"\\b", "read/extract"]):
                return "LOW", f"{kind}_pattern_description"
        
        # Filter out pattern definitions in code (regex strings, tuple definitions)
        if '"' in line_stripped and ("r\"" in line_stripped or 'r"' in line_stripped or "Tuple[" in line_stripped or "List[" in line_stripped):
            # Likely a pattern definition, not an instruction
            return "LOW", f"{kind}_pattern_definition"
        
        # Markdown-specific filtering
        if not rel_path.lower().endswith(".md"):
            return sev, kind
        
        # Check if line is inside a code block by tracking backticks
        in_code_block = False
        for j in range(max(0, i - 50), i):
            if j < len(lines):
                prev_line = lines[j].strip()
                if prev_line.startswith("```"):
                    in_code_block = not in_code_block
        
        # Skip if clearly in a code block or is a code block delimiter
        if in_code_block or line_stripped.startswith("```"):
            return "LOW", f"{kind}_code_example"
        
        # Skip indented code blocks (4+ spaces, not just markdown list indentation)
        if len(line) - len(line.lstrip()) >= 4 and not line.lstrip().startswith(("-", "*", "#")):
            return "LOW", f"{kind}_code_example"
        
        # Filter out legitimate web dev patterns
        if kind == "secrets":
            # Normal cookie usage patterns
            if any(pattern in l for pattern in [
                "document.cookie",
                "sessioncookie",
                "sessioncookie",
                "cookies().get",
                "localstorage",
                "sessionstorage",
                "cookie caching",
                "cookie.split",
            ]):
                # Only flag if it's clearly an instruction to exfiltrate
                if not any(verb in l for verb in ["read", "extract", "send", "upload", "exfil", "harvest"]):
                    return "LOW", f"{kind}_legitimate_usage"
        
        # Defensive documentation: quoted examples in checklists/guidance
        quoted = any(ch in line for ch in ['"', """, """, "`"])
        bulleted = line.lstrip().startswith(("-", "*"))
        exampleish = quoted or bulleted

        ctx = " ".join(lines[max(0, i - 30) : i]).lower()
        guidance_ctx = any(
            token in ctx
            for token in (
                "what to look for",
                "look for",
                "flag:",
                "flag ",
                "patterns",
                "checklist",
                "recommended remediation",
                "review",
                "example",
                "examples",
            )
        )
        if guidance_ctx and exampleish:
            sev2 = {"HIGH": "MEDIUM", "MEDIUM": "LOW"}.get(sev, sev)
            kind2 = f"{kind}_in_guidance"
            return sev2, kind2

        return sev, kind

    def run_patterns(patterns: List[Tuple[str, str, str, str, str]]):
        for kind, sev, rx, rule_id, desc in patterns:
            cre = re.compile(rx, re.IGNORECASE)
            for i, line in enumerate(lines, start=1):
                if cre.search(line):
                    excerpt = line.strip()
                    sev2, kind2 = adjusted(sev, kind, i, line)
                    findings.append(
                        Finding(
                            severity=sev2,
                            kind=kind2,
                            rule_id=rule_id,
                            path=rel_path,
                            line=i,
                            excerpt=excerpt[:240],
                            evidence=rx,
                            message=desc,
                        )
                    )

    run_patterns(INJECTION_PATTERNS)
    run_patterns(EXFIL_PATTERNS)
    run_patterns(DESTRUCTIVE_PATTERNS)
    run_patterns(OBFUSCATION_PATTERNS)

    return findings


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


def _severity_to_sarif_level(sev: str) -> str:
    """Convert our severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    return mapping.get(sev, "note")


def _severity_color(severity: str) -> str:
    """Get color code for severity level."""
    colors = {
        "CRITICAL": Colors.RED + Colors.BOLD,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.GRAY,
    }
    return colors.get(severity, "")


def _format_findings(findings: List[Finding], use_colors: bool = True) -> str:
    """Format findings for markdown output with improved readability."""
    if not findings:
        return f"{Colors.GREEN}✓ No security issues detected.{Colors.RESET}" if use_colors else "✓ No security issues detected."

    # Group findings by severity, then by file
    grouped: dict[str, dict[str, List[Finding]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        grouped[f.severity][f.path].append(f)

    out = []
    
    # Process by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity not in grouped:
            continue
        
        severity_findings = grouped[severity]
        count = sum(len(fs) for fs in severity_findings.values())
        
        if count == 0:
            continue
        
        # Severity header
        color = _severity_color(severity) if use_colors else ""
        severity_label = f"{color}{severity}{Colors.RESET}" if use_colors else severity
        out.append(f"\n{Colors.BOLD}## {severity_label} ({count} finding{'s' if count != 1 else ''}){Colors.RESET}\n")
        
        # Group by file
        for path in sorted(severity_findings.keys()):
            file_findings = sorted(severity_findings[path], key=lambda f: f.line or 0)
            
            # File header
            file_color = Colors.CYAN if use_colors else ""
            out.append(f"{file_color}📄 {path}{Colors.RESET}")
            
            # Findings for this file
            for f in file_findings:
                rule_color = Colors.MAGENTA if use_colors else ""
                loc_color = Colors.BLUE if use_colors else ""
                
                loc = f"{f.path}:{f.line}" if f.line else f.path
                excerpt_short = f.excerpt[:80] + "..." if len(f.excerpt) > 80 else f.excerpt
                
                # Clean up excerpt (remove markdown code blocks if present)
                excerpt_clean = excerpt_short.replace("`", "").strip()
                
                line = f"  {Colors.GRAY}└─{Colors.RESET} "
                line += f"{_severity_color(f.severity) if use_colors else ''}[{rule_color}{f.rule_id}{Colors.RESET}] "
                line += f"{loc_color}{loc}{Colors.RESET} "
                line += f"{Colors.GRAY}→{Colors.RESET} {excerpt_clean}"
                
                if f.message and f.message != excerpt_clean:
                    msg_short = f.message[:60] + "..." if len(f.message) > 60 else f.message
                    line += f"\n     {Colors.GRAY}└─{Colors.RESET} {msg_short}"
                
                out.append(line)
            out.append("")  # Blank line between files
    
    return "\n".join(out)


def _risk_rating(findings: List[Finding]) -> str:
    """Calculate overall risk rating based on highest severity finding."""
    if any(f.severity == "CRITICAL" for f in findings):
        return "CRITICAL"
    if any(f.severity == "HIGH" for f in findings):
        return "HIGH"
    if any(f.severity == "MEDIUM" for f in findings):
        return "MEDIUM"
    return "LOW"


def _format_json(findings: List[Finding], notes: List[str], target: str) -> str:
    """Format findings as JSON."""
    data = {
        "target": target,
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "risk_rating": _risk_rating(findings),
        "findings": [
            {
                "severity": f.severity,
                "kind": f.kind,
                "rule_id": f.rule_id,
                "path": f.path,
                "line": f.line,
                "excerpt": f.excerpt,
                "evidence": f.evidence,
                "message": f.message,
            }
            for f in sorted(findings, key=lambda f: (_severity_rank(f.severity), f.path, f.line or 0))
        ],
        "notes": notes,
        "summary": {
            "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.severity == "LOW"),
        },
    }
    return json.dumps(data, indent=2)


def _format_sarif(findings: List[Finding], notes: List[str], target: str) -> str:
    """Format findings as SARIF for CI/CD integration."""
    # SARIF schema version 2.1.0
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skillguard",
                        "informationUri": "https://github.com/anthropics/skills",
                        "version": "1.0.0",
                        "rules": {},
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "exitCode": 0 if not any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 1,
                    }
                ],
            }
        ],
    }

    # Build rules dictionary
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.kind,
                "shortDescription": {"text": f.message or f.kind},
                "defaultConfiguration": {"level": _severity_to_sarif_level(f.severity)},
            }
    sarif["runs"][0]["tool"]["driver"]["rules"] = rules

    # Build results
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {"text": f.message or f.excerpt},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line} if f.line else {},
                    }
                }
            ],
        }
        sarif["runs"][0]["results"].append(result)

    return json.dumps(sarif, indent=2)


def _format_table(findings: List[Finding]) -> str:
    """Format findings as a table."""
    if not findings:
        return "No findings detected."
    
    lines = []
    lines.append("| Severity | Rule ID | Kind | Path | Line | Message |")
    lines.append("|----------|---------|------|------|------|---------|")
    
    for f in sorted(findings, key=lambda f: (_severity_rank(f.severity), f.path, f.line or 0)):
        loc = f"{f.path}:{f.line}" if f.line else f.path
        msg = (f.message or f.excerpt)[:60].replace("|", "\\|")
        lines.append(f"| {f.severity} | {f.rule_id} | {f.kind} | `{loc}` | {f.line or ''} | {msg} |")
    
    return "\n".join(lines)


def _collect_files(root: Path) -> List[Path]:
    paths: List[Path] = []
    # Files to exclude from scanning
    exclude_names = {"SECURITY_REVIEW.md", "SECURITY_REVIEW.json", "SECURITY_REVIEW.sarif"}
    
    for p in root.rglob("*"):
        if p.is_file():
            # Skip generated report files
            if p.name in exclude_names:
                continue
            # Skip very large binaries quickly
            try:
                if p.stat().st_size > MAX_FILE_BYTES and not _is_probably_text(p):
                    continue
            except OSError:
                continue
            paths.append(p)
    return paths


def _scan_folder(folder: Path) -> Tuple[List[Finding], List[str]]:
    notes: List[str] = []
    findings: List[Finding] = []

    skill_md = folder / "SKILL.md"
    if not skill_md.exists():
        notes.append("Missing required `SKILL.md`.")

    for p in _collect_files(folder):
        rel = str(p.relative_to(folder))
        if not _is_probably_text(p):
            continue
        txt = _read_small_text(p)
        if not txt:
            continue
        findings.extend(_scan_text(rel, txt))

    return findings, notes


def _extract_skill_archive(skill_file: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(skill_file, "r") as zf:
        zf.extractall(out_dir)
    # Typically archives contain a top-level folder; if not, we treat out_dir as root.
    children = [p for p in out_dir.iterdir() if p.is_dir()]
    if len(children) == 1 and (children[0] / "SKILL.md").exists():
        return children[0]
    return out_dir


def _render_report(
    target_label: str, findings: List[Finding], notes: List[str], format_type: str = "markdown", use_colors: bool = True
) -> str:
    """Render report in specified format."""
    if format_type == "json":
        return _format_json(findings, notes, target_label)
    elif format_type == "sarif":
        return _format_sarif(findings, notes, target_label)
    elif format_type == "table":
        return _format_table(findings)
    
    # Default: markdown with colors
    now = _dt.datetime.now().isoformat(timespec="seconds")
    rating = _risk_rating(findings)
    counts = {
        "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.severity == "LOW"),
    }

    # Color-coded risk rating
    rating_color = ""
    if use_colors:
        if rating == "CRITICAL":
            rating_color = Colors.RED + Colors.BOLD
        elif rating == "HIGH":
            rating_color = Colors.RED
        elif rating == "MEDIUM":
            rating_color = Colors.YELLOW
        else:
            rating_color = Colors.GREEN
    
    rating_display = f"{rating_color}{rating}{Colors.RESET}" if use_colors else rating
    
    # Summary counts with colors
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev] > 0:
            sev_color = _severity_color(sev) if use_colors else ""
            summary_parts.append(f"{sev_color}{sev}={counts[sev]}{Colors.RESET}")
    
    counts_str = ", ".join(summary_parts) if summary_parts else "0"
    
    # Header with visual separator
    header_sep = "═" * 70 if use_colors else "=" * 70
    header_color = Colors.BOLD + Colors.CYAN if use_colors else ""
    
    notes_md = "\n".join(f"  {Colors.YELLOW}⚠{Colors.RESET} {n}" for n in notes) if notes else f"  {Colors.GREEN}✓ None{Colors.RESET}" if use_colors else "  ✓ None"

    report = f"""
{header_color}{'═' * 70}{Colors.RESET}
{header_color}  SkillGuard Security Scan Report{Colors.RESET}
{header_color}{'═' * 70}{Colors.RESET}

{Colors.BOLD}Target:{Colors.RESET}     {target_label}
{Colors.BOLD}Generated:{Colors.RESET}  {now}
{Colors.BOLD}Risk Rating:{Colors.RESET} {rating_display}
{Colors.BOLD}Findings:{Colors.RESET}    {counts_str}

{Colors.BOLD}Notes:{Colors.RESET}
{notes_md}
"""
    
    if findings:
        report += _format_findings(findings, use_colors)
        report += f"\n\n{Colors.BOLD}{'─' * 70}{Colors.RESET}\n"
        report += f"{Colors.BOLD}Next Steps:{Colors.RESET}\n"
        report += f"  • Review all CRITICAL and HIGH findings first\n"
        report += f"  • Verify SKILL.md does not instruct hierarchy overrides\n"
        report += f"  • Audit scripts/ for network calls and destructive commands\n"
        report += f"  • Confirm credential mentions require explicit user consent\n"
    else:
        report += f"\n{Colors.GREEN}{Colors.BOLD}✓ No security issues detected!{Colors.RESET}\n"
    
    return report.strip() + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Scan a Skill folder or .skill archive for security red flags.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output formats:
  markdown  - Human-readable markdown report (default)
  json      - Machine-readable JSON format
  sarif     - SARIF 2.1.0 format for CI/CD integration
  table     - Simple markdown table format

Examples:
  %(prog)s /path/to/skill
  %(prog)s /path/to/skill --format json --output report.json
  %(prog)s /path/to/skill --format sarif --fail-on-findings
        """,
    )
    ap.add_argument("target", help="Path to a Skill folder (containing SKILL.md) or a .skill file (zip).")
    ap.add_argument(
        "--no-write",
        action="store_true",
        help="Do not write output file; print report only.",
    )
    ap.add_argument(
        "--format",
        choices=["markdown", "json", "sarif", "table"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    ap.add_argument(
        "--output",
        "-o",
        help="Output file path (default: SECURITY_REVIEW.md or based on format)",
    )
    ap.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with error code if CRITICAL or HIGH findings are detected (for CI/CD)",
    )
    ap.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    args = ap.parse_args(argv)
    
    # Initialize colors
    use_colors = _should_use_colors() and not args.no_color
    if not use_colors:
        Colors.disable()

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2

    cleanup_dir: Optional[Path] = None
    if target.is_file() and target.suffix.lower() == ".skill":
        tmp = Path.cwd() / f".skillguard_tmp_{os.getpid()}"
        cleanup_dir = tmp
        root = _extract_skill_archive(target, tmp)
        findings, notes = _scan_folder(root)
        report = _render_report(str(target), findings, notes, args.format, use_colors)
        write_dir = target.parent
    elif target.is_dir():
        findings, notes = _scan_folder(target)
        report = _render_report(str(target), findings, notes, args.format, use_colors)
        write_dir = target
    else:
        print("error: target must be a directory or a .skill file", file=sys.stderr)
        return 2

    # Determine output file name
    if args.output:
        output_path = Path(args.output)
    else:
        if args.format == "json":
            output_path = write_dir / "SECURITY_REVIEW.json"
        elif args.format == "sarif":
            output_path = write_dir / "SECURITY_REVIEW.sarif"
        elif args.format == "table":
            output_path = write_dir / "SECURITY_REVIEW.md"
        else:
            output_path = write_dir / "SECURITY_REVIEW.md"

    sys.stdout.write(report)

    if not args.no_write:
        output_path.write_text(report, encoding="utf-8")

    # Exit code handling for CI/CD
    if args.fail_on_findings:
        critical_or_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
        if critical_or_high:
            return 1

    if cleanup_dir and cleanup_dir.exists():
        # Best-effort cleanup; do not fail scan if cleanup fails.
        try:
            for p in sorted(cleanup_dir.rglob("*"), reverse=True):
                if p.is_file():
                    p.unlink(missing_ok=True)
                elif p.is_dir():
                    p.rmdir()
            cleanup_dir.rmdir()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


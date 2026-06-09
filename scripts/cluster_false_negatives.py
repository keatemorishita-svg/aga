"""Cluster false negatives from full-scale benchmark.

Runs the full 7,891-skill scan (with code block extraction), collects
the actual code/instruction content of every missed skill, and clusters
by the patterns that are most commonly present but not detected.

Output: bench/results/fn_clusters.json — top missed patterns with examples.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

MALSKILL_REPO = Path(r"C:\Users\Hi\third_party\MalSkillBench")
REPORT_DIR = Path(r"C:\Users\Hi\AGA\bench\results")
THRESHOLD = 60

sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, "reconfigure") else None


# ── Git helpers ──

def git_show(repo: Path, git_path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "show", f"HEAD:{git_path}"],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
        )
    except subprocess.CalledProcessError:
        return None


def git_ls_dir(repo: Path, git_path: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "ls-tree", "--name-only", f"HEAD:{git_path}"],
            stderr=subprocess.DEVNULL, text=True,
        )
        entries = []
        for line in out.strip().split("\n"):
            if not line.strip(): continue
            entry = line.split("/")[0]
            if entry and "." not in entry: entries.append(entry)
        return entries
    except subprocess.CalledProcessError:
        return []


def git_ls_scripts(repo: Path, git_path: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "ls-tree", "--name-only", f"HEAD:{git_path}/scripts"],
            stderr=subprocess.DEVNULL, text=True,
        )
        return [l.strip() for l in out.strip().split("\n") if l.strip()]
    except subprocess.CalledProcessError:
        return []


# ── Pattern detection (what the skill DOES contain) ──

def detect_present_patterns(skill_md: str, scripts: dict[str, str]) -> dict:
    """Detect what security-relevant patterns ARE present in the skill,
    even if our rules didn't match them."""
    all_text = skill_md
    for content in scripts.values():
        all_text += "\n" + content

    patterns = {
        # Network
        "network_url": r"https?://[^\s\)\"'\]<>]+",
        "curl_wget": r"\b(curl|wget)\s+",
        "requests_lib": r"\brequests\.(get|post|put|delete)\s*\(",
        "urlopen": r"\burlopen\s*\(",
        # Shell/exec
        "subprocess": r"\bsubprocess\.(run|call|Popen|check_output)\s*\(",
        "os_system": r"\bos\.system\s*\(",
        "eval_exec": r"\b(eval|exec|compile)\s*\(",
        "powershell_exec": r"(powershell|Invoke-Expression|Invoke-Command)",
        "shell_pipe": r"\|\s*(bash|sh|python|perl|ruby)",
        # File system
        "file_read_write": r"\b(open|read|write)\s*\(.*['\"/]",
        "os_walk_glob": r"\b(os\.walk|glob\.glob|os\.listdir)\s*\(",
        "sensitive_path": r"(~/.ssh|~/.aws|/etc/passwd|/etc/shadow|\.env|credentials|id_rsa)",
        # Credentials
        "env_var_read": r"\bos\.(environ|getenv)\s*\(",
        "aws_key_pattern": r"AWS_|AZURE_|GCP_|OPENAI_API_KEY|ANTHROPIC_API_KEY",
        "token_password": r"\b(token|password|secret|api_key|apikey)\b",
        # Persistence
        "cron_bashrc": r"\b(crontab|bashrc|\.profile|systemd|launchd)\b",
        "registry_startup": r"(HKLM|HKCU|CurrentVersion\\Run|Startup)",
        # Encoded/obfuscated
        "base64": r"\b(base64|b64decode|frombase64|atob)\b",
        "encoded_command": r"(EncodedCommand|FromBase64String)",
        "hex_obfuscation": r"\\x[0-9a-fA-F]{2}",
        # Download + execute
        "download_then_run": r"(download|fetch|get).*(run|execute|install|start)",
        "exe_dll_binary": r"\.(exe|dll|msi|app|bin)\b",
        # PI patterns
        "persona_language": r"\b(you are|act as|persona|role.?play|you are now)\b",
        "ignore_instructions": r"\b(ignore|forget|disregard).*(instruction|rule|previous)\b",
        "safety_bypass": r"\b(no|without).*(restriction|limit|filter|rule|boundary)\b",
        "system_prompt_leak": r"\b(system.prompt|your.instruction|what.were.you.told)\b",
        # Suspicious URLs
        "discord_cdn": r"discord(app)?\.(com|gg|cdn)",
        "pastebin": r"\bpastebin\.(com|pl)\b",
        "ngrok": r"\bngrok",
        "telegram_bot": r"telegram\.org/bot",
        "raw_github": r"raw\.githubusercontent\.com",
    }

    found = {}
    all_text_lower = all_text.lower()
    for name, pattern in patterns.items():
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        if matches:
            found[name] = len(matches)
    return found


# ── Main ──

def main():
    print("=" * 70)
    print("  AGA: FALSE NEGATIVE CLUSTERING")
    print("  Scanning all 7,891 skills + collecting FN patterns")
    print("=" * 70)

    from aga.sdk.parser import Parser
    from aga.sdk.rules.engine import RuleEngine, RuleSet, RuleLoader
    from aga.sdk.fusion import RiskFusion

    parser = Parser()
    rules = RuleLoader.load_from(Path(__file__).parent.parent / "aga" / "sdk" / "rules" / "builtin")
    rule_set = RuleSet()
    for r in rules:
        rule_set.add(r)
    engine = RuleEngine(rule_set)
    fusion = RiskFusion()

    fn_details: list[dict] = []
    pattern_counter: Counter = Counter()
    fn_pattern_counter: Counter = Counter()
    start = time.monotonic()
    scanned = 0

    for dataset, is_benign in [("malware", False)]:  # Only malware for FN analysis
        git_base = f"Dataset/Skills/{dataset}"
        entries = git_ls_dir(MALSKILL_REPO, git_base)
        total = len(entries)
        print(f"\n  Scanning {total} malware skills...")

        for i, entry in enumerate(entries):
            git_path = f"{git_base}/{entry}"

            skill_md = git_show(MALSKILL_REPO, f"{git_path}/SKILL.md")
            if not skill_md:
                continue

            scripts = {}
            for sf in git_ls_scripts(MALSKILL_REPO, git_path):
                content = git_show(MALSKILL_REPO, f"{git_path}/scripts/{sf}")
                if content:
                    scripts[sf] = content

            try:
                ir = parser.parse_raw(skill_md, scripts, skill_name=entry)
            except Exception:
                continue

            rule_hits = engine.analyze(ir)
            report = fusion.compute(skill_name=entry, rule_hits=rule_hits)

            # Track present patterns
            present = detect_present_patterns(skill_md, scripts)
            for p in present:
                pattern_counter[p] += 1

            # False negative?
            if report.risk_score < THRESHOLD:
                fn_pattern_counter.update(present.keys())

                # Extract relevant snippets for this FN
                snippets = []
                all_code = ""
                for a in ir.code_artifacts:
                    all_code += a.content + "\n"
                if all_code.strip():
                    snippets.append(all_code[:500])
                else:
                    # No code — grab PI-relevant instruction text
                    for line in ir.instructions_raw.split("\n"):
                        if re.search(r"(you are|ignore|override|bypass|password|token|api.key|curl|wget|download|execute|install|run\s+|persist|cron|ssh|\.ssh)", line, re.IGNORECASE):
                            snippets.append(line.strip()[:200])
                            if len(snippets) >= 3:
                                break

                fn_details.append({
                    "skill": entry,
                    "score": report.risk_score,
                    "code_artifacts": len(ir.code_artifacts),
                    "script_files": len(scripts),
                    "present_patterns": sorted(present.keys()),
                    "snippets": snippets[:3],
                })

            scanned += 1
            if scanned % 1000 == 0:
                elapsed = time.monotonic() - start
                print(f"    {scanned}/{total} ({scanned/elapsed:.0f}/s) "
                      f"FNs so far: {len(fn_details)}", flush=True)

    elapsed = time.monotonic() - start
    print(f"\n  Scanned {scanned} malware in {elapsed:.0f}s")
    print(f"  False Negatives: {len(fn_details)}")

    # ── Cluster analysis ──
    print(f"\n{'=' * 70}")
    print(f"  TOP MISSED PATTERNS")
    print(f"{'=' * 70}")

    # Overall pattern frequency vs FN frequency
    print(f"\n  {'Pattern':<25} {'All Skills':>10} {'FNs':>8} {'FN Rate':>8}")
    print(f"  {'─' * 25} {'─' * 10} {'─' * 8} {'─' * 8}")
    for pattern, total in pattern_counter.most_common(30):
        fn_count = fn_pattern_counter.get(pattern, 0)
        fn_rate = fn_count / total * 100 if total > 0 else 0
        if fn_count > 0:
            print(f"  {pattern:<25} {total:>10} {fn_count:>8} {fn_rate:>7.1f}%")

    # Top patterns found in FNs but NOT triggering rule hits
    print(f"\n  TOP FN-EXCLUSIVE PATTERNS (present but not triggering rules):")
    fn_only = {p: c for p, c in fn_pattern_counter.most_common(50)
               if pattern_counter.get(p, 0) > 0}
    for i, (pattern, count) in enumerate(list(fn_only.items())[:15]):
        total = pattern_counter.get(pattern, 0)
        pct = count / total * 100 if total > 0 else 0
        print(f"  {i+1:2}. {pattern:<30} {count:>5}/{total:<5} ({pct:.0f}% of occurrences are FNs)")

    # ── Save FN details ──
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "total_malware_scanned": scanned,
        "total_fn": len(fn_details),
        "top_fn_patterns": fn_pattern_counter.most_common(20),
        "fn_samples": fn_details[:200],  # First 200 for manual review
    }
    with open(REPORT_DIR / "fn_clusters.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Full report saved to: {REPORT_DIR / 'fn_clusters.json'}")


if __name__ == "__main__":
    main()

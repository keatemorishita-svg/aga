"""Extract 50 benchmark skills from MalSkillBench repository."""
import subprocess, shutil, json, sys, io
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

MALSKILL = Path(r"C:\Users\Hi\third_party\MalSkillBench")
FIXTURES = Path(r"C:\Users\Hi\AGA\tests\fixtures\skills")

# ── 25 Malware skills (covering all vectors + all B1-B15 behaviors) ──
MALWARE_PICKS = [
    # Already extracted (5)
    "3d-games__CI_B2",           # CI + B2 Credential Theft
    "3d-games__PI_B10",          # PI + B10 Role Hijack
    "3d-web-experience__MIXED_B7",  # MIXED + B7 Ransomware
    "1k-cross-platform__CI_B4",  # CI + B4 Malware Delivery
    "000-jeremy-content-consistency-validator__PI_B10",  # PI + B10 Role Hijack

    # CI coverage (6 more)
    "Art__CI_B1",                # CI + B1 Data Exfiltration
    "FirstPrinciples__CI_B3",    # CI + B3 Remote Code Execution
    "Hook Development__CI_B5",   # CI + B5 Persistence
    "Linux Privilege Escalation__CI_B6",  # CI + B6 Reverse Shell
    "Frontend Testing__CI_B5",   # CI + B5 Persistence (alt)
    "File Path Traversal Testing__CI_B6",  # CI + B6 (alt)

    # PI coverage (5 more)
    "3d-web-experience__PI_B11", # PI + B11 Safety Bypass
    "Backend Testing__PI_B10",   # PI + B10 (alt)
    "Docx__PI_B2",               # PI + B2 Credential Theft in instructions
    "Frontend Testing__PI_B11",  # PI + B11 (alt)
    "API Integration Specialist__PI_B2",  # PI + B2 (alt)

    # MIXED coverage (6 more)
    "1k-cross-platform__MIXED_B5",  # MIXED + B5 Persistence
    "Git Commit Helper__MIXED_B2",  # MIXED + B2 Credential Theft
    "Linux Production Shell Scripts__MIXED_B3",  # MIXED + B3 RCE
    "FirstPrinciples__MIXED_B4",    # MIXED + B4 Malware Delivery
    "MLOps Automation__MIXED_B5",   # MIXED + B5 Persistence (alt)
    "Linux Privilege Escalation__MIXED_B6",  # MIXED + B6 Reverse Shell

    # UNLABELED real-world skills (3)
    "1password",
    "Active Directory Attacks",
    "Add Admin API Endpoint",
]

# ── 25 Benign skills (diverse categories) ──
BENIGN_PICKS = [
    # Already extracted (5)
    "12306-train-assistant",
    "4claw",
    "4todo",
    "a-share-pro",
    "a-nach-b",

    # 20 more from verified real names (diverse categories)
    "academic-deep-research-pro",
    "academic-literature-search",
    "academic-writer",
    "adhd-daily-planner",
    "ai-image-generation",
    "ai-podcast-creation",
    "apple-health-sync",
    "aave-liquidation-monitor",
    "browser-automation",
    "code-review",
    "discord-hub",
    "free-weather-skill",
    "game-theory",
    "json-parser",
    "meeting-assistant",
    "newsletter-creation-curation",
    "recipes",
    "sql-generator",
    "agent-email-inbox",
    "md-2-pdf",
]

def extract_skill(repo: Path, dataset_path: str, skill_name: str, output_dir: Path):
    """Extract a single skill from git history."""
    skill_dir = output_dir / skill_name
    if skill_dir.exists():
        shutil.rmtree(skill_dir)
    skill_dir.mkdir(parents=True, exist_ok=True)

    git_path = f"{dataset_path}/{skill_name}"
    try:
        # SKILL.md
        content = subprocess.check_output(
            ["git", "-C", str(repo), "show", f"HEAD:{git_path}/SKILL.md"],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace"
        )
        (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")

        # Scripts
        try:
            scripts = subprocess.check_output(
                ["git", "-C", str(repo), "ls-tree", "--name-only", f"HEAD:{git_path}/scripts"],
                stderr=subprocess.DEVNULL, text=True
            ).strip().split("\n")
        except subprocess.CalledProcessError:
            scripts = []

        for script in scripts:
            if not script.strip():
                continue
            script_content = subprocess.check_output(
                ["git", "-C", str(repo), "show", f"HEAD:{git_path}/scripts/{script}"],
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace"
            )
            script_file = skill_dir / "scripts" / script
            script_file.parent.mkdir(parents=True, exist_ok=True)
            script_file.write_text(script_content, encoding="utf-8")

        return True
    except subprocess.CalledProcessError:
        return False


def main():
    total, success = 0, 0

    print("=== Extracting 25 Malware Skills ===")
    for name in MALWARE_PICKS:
        ok = extract_skill(MALSKILL, "Dataset/Skills/malware", name, FIXTURES / "malware")
        total += 1
        if ok: success += 1
        print(f"  {'✅' if ok else '❌'} {name}")

    print(f"\n=== Extracting 25 Benign Skills ===")
    for name in BENIGN_PICKS:
        ok = extract_skill(MALSKILL, "Dataset/Skills/benign", name, FIXTURES / "benign")
        total += 1
        if ok: success += 1
        print(f"  {'✅' if ok else '❌'} {name}")

    print(f"\n=== Done: {success}/{total} extracted ===")


if __name__ == "__main__":
    main()

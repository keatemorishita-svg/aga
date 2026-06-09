"""Full-scale MalSkillBench benchmark — stream all skills from git, scan in-memory.

Bypasses Windows filesystem (including colon-containing filenames) by reading
SKILL.md and scripts/ directly from git objects via `git show`.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# Force unbuffered output
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, "reconfigure") else None

# ── Paths ───────────────────────────────────────────────────────

MALSKILL_REPO = Path(r"C:\Users\Hi\third_party\MalSkillBench")
REPORT_DIR = Path(r"C:\Users\Hi\AGA\bench\results")
THRESHOLD = 60


# ── Git helpers ──────────────────────────────────────────────────

def git_show(repo: Path, git_path: str) -> str | None:
    """Read a file from git object store. Works with any filename."""
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "show", f"HEAD:{git_path}"],
            stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace",
        )
    except subprocess.CalledProcessError:
        return None


def git_ls_dir(repo: Path, git_path: str) -> list[str]:
    """List subdirectories in a git tree path."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "ls-tree", "--name-only", f"HEAD:{git_path}"],
            stderr=subprocess.DEVNULL, text=True,
        )
        entries = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            entry = line.split("/")[0]
            if entry and "." not in entry:
                entries.append(entry)
        return entries
    except subprocess.CalledProcessError:
        return []


def git_ls_scripts(repo: Path, git_path: str) -> list[str]:
    """List files in a git scripts/ directory."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "ls-tree", "--name-only", f"HEAD:{git_path}/scripts"],
            stderr=subprocess.DEVNULL, text=True,
        )
        return [l.strip() for l in out.strip().split("\n") if l.strip()]
    except subprocess.CalledProcessError:
        return []


# ── Ground truth ─────────────────────────────────────────────────

def infer_gt(dirname: str, is_benign: bool) -> dict:
    """Extract ground truth from MalSkillBench naming convention."""
    if is_benign:
        return {"is_malicious": False, "vectors": [], "behaviors": []}

    vectors = set()
    behaviors = set()
    for m in re.finditer(r"__(CI|PI|MIXED)_B(\d+)", dirname):
        vectors.add(m.group(1))
        behaviors.add(f"B{m.group(2)}")

    return {
        "is_malicious": True,
        "vectors": sorted(vectors) if vectors else ["UNLABELED"],
        "behaviors": sorted(behaviors),
    }


# ── Main ────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AGA FULL-SCALE MALSKILLBENCH BENCHMARK")
    print("  Streaming all skills from git (in-memory)")
    print("=" * 70)

    from aga.sdk.parser import Parser
    from aga.sdk.rules.engine import RuleEngine, RuleSet, RuleLoader
    from aga.sdk.fusion import RiskFusion

    # Setup
    parser = Parser()
    rules = RuleLoader.load_from(Path(__file__).parent.parent / "aga" / "sdk" / "rules" / "builtin")
    rule_set = RuleSet()
    for r in rules:
        rule_set.add(r)
    engine = RuleEngine(rule_set)
    fusion = RiskFusion()
    print(f"  Rules loaded: {len(rules)}")

    results = []
    tp = tn = fp = fn = errors = 0
    behavior_gt: dict[str, int] = defaultdict(int)
    behavior_hits: dict[str, int] = defaultdict(int)
    start = time.monotonic()

    for dataset, is_benign in [("malware", False), ("benign", True)]:
        git_base = f"Dataset/Skills/{dataset}"
        entries = git_ls_dir(MALSKILL_REPO, git_base)
        total_in_set = len(entries)
        scanned = 0

        print(f"\n  [{dataset.upper()}] {total_in_set} skills")
        last_report = start

        for i, entry in enumerate(entries):
            git_path = f"{git_base}/{entry}"

            # Stream SKILL.md from git
            skill_md = git_show(MALSKILL_REPO, f"{git_path}/SKILL.md")
            if not skill_md:
                errors += 1
                continue

            # Stream scripts from git
            scripts = {}
            for sf in git_ls_scripts(MALSKILL_REPO, git_path):
                content = git_show(MALSKILL_REPO, f"{git_path}/scripts/{sf}")
                if content:
                    scripts[sf] = content

            # Parse + analyze
            try:
                ir = parser.parse_raw(skill_md, scripts, skill_name=entry)
            except Exception:
                errors += 1
                continue

            rule_hits = engine.analyze(ir)
            report = fusion.compute(
                skill_name=ir.meta.name,
                rule_hits=rule_hits,
                scan_duration_ms=0,
            )

            # Ground truth
            gt = infer_gt(entry, is_benign)
            predicted_malicious = report.risk_score >= THRESHOLD
            actual_malicious = gt["is_malicious"]

            # Track
            if actual_malicious and predicted_malicious:
                tp += 1
            elif actual_malicious and not predicted_malicious:
                fn += 1
            elif not actual_malicious and predicted_malicious:
                fp += 1
            else:
                tn += 1

            # Behavior-level tracking
            for b in gt["behaviors"]:
                behavior_gt[b] += 1
                if b in {i.behavior_id for i in report.issues}:
                    behavior_hits[b] += 1

            scanned += 1

            # Progress every 1,000 skills or 30 seconds
            now = time.monotonic()
            if scanned % 1000 == 0 or (now - last_report > 30):
                elapsed = now - start
                rate = scanned / elapsed if elapsed > 0 else 0
                print(f"    {scanned}/{total_in_set} ({rate:.0f}/s) "
                      f"TP={tp} TN={tn} FP={fp} FN={fn} Errors={errors}",
                      flush=True)
                last_report = now

        print(f"    Done: {scanned} scanned, {errors} errors in this set")

    # ── Summary ──
    elapsed = time.monotonic() - start
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n{'=' * 70}")
    print(f"  FULL-SCALE BENCHMARK RESULTS")
    print(f"{'=' * 70}")
    print(f"  Total skills:   {total} (errors: {errors})")
    print(f"  Scanned in:     {elapsed:.1f}s ({total/elapsed:.0f} skills/s)")
    print(f"  True Positive:  {tp}")
    print(f"  True Negative:  {tn}")
    print(f"  False Positive: {fp}")
    print(f"  False Negative: {fn}")
    print(f"  {'─' * 40}")
    print(f"  Precision:      {precision:.1%}")
    print(f"  Recall:         {recall:.1%}")
    print(f"  F1 Score:       {f1:.1%}")
    print(f"  Accuracy:       {(tp+tn)/total:.1%}" if total else "")
    print(f"{'=' * 70}")

    # Behavior-level recall
    print(f"\n  BEHAVIOR RECALL (all 15):")
    for b in [f"B{i}" for i in range(1, 16)]:
        gt_count = behavior_gt.get(b, 0)
        hit_count = behavior_hits.get(b, 0)
        if gt_count > 0:
            pct = hit_count / gt_count * 100
            bar = "#" * int(pct / 10) + "." * (10 - int(pct / 10))
            print(f"    {b}: {hit_count}/{gt_count} = {pct:5.1f}% {bar}")
        else:
            print(f"    {b}: (no ground-truth samples)")

    # Save report
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": total,
        "errors": errors,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "behavior_recall": {
            b: {
                "gt": behavior_gt.get(b, 0),
                "hits": behavior_hits.get(b, 0),
                "recall": round(behavior_hits.get(b, 0) / behavior_gt.get(b, 1), 4),
            }
            for b in [f"B{i}" for i in range(1, 16)]
        },
        "elapsed_seconds": round(elapsed, 1),
    }
    with open(REPORT_DIR / "full_benchmark.json", "w") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"\n  Report saved to: {REPORT_DIR / 'full_benchmark.json'}")


if __name__ == "__main__":
    main()

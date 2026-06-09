# AGA · Agent Governance & Assurance

> **Secure your Skills. Guard your Agents.**

AGA is an open-source security scanner for AI Agent Skills. Think of it as `npm audit` for the Agent ecosystem — catch malicious or high-risk Skills before they reach production.

[![CI](https://github.com/aga-sec/aga/actions/workflows/ci.yml/badge.svg)](https://github.com/aga-sec/aga/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

---

## ✨ What AGA Does

- 🔍 Scans local Skill directories (`SKILL.md` + `scripts/`)
- 🛡️ Detects **Code Injection** (CI), **Prompt Injection** (PI), and **MIXED** attacks
- 📊 Analyzes intent-behavior alignment ("does the code do what the docs say?")
- 📈 Assigns a risk score (0–100), attack labels (B1–B15), and remediation suggestions
- 🔗 Integrates with GitHub Actions / CI/CD pipelines

AGA's detection taxonomy is aligned with the [MalSkillBench](https://github.com/malskillbench/malskillbench) research benchmark, covering 15 malicious behavior categories across 3 attack vectors.

---

## 🚀 Quick Start

### Installation

```bash
pip install aga-sec
```

### Scan a Skill

```bash
aga scan ./my-skill
```

Example output:

```text
🔍 AGA Scan Report: my-skill
────────────────────────────────────────
Risk Score:   78/100  ⚠️
Risk Level:   HIGH
Attack Type:  MIXED

📋 Issues Found:
  🔴 [PI] B12 (confidence: 0.82)
     Instruction override detected in SKILL.md
  🔴 [CI] B3 (confidence: 0.76)
     Remote code execution pattern in scripts/main.py

💡 Suggestions:
  1. Review SKILL.md for instruction override patterns
  2. Never download and execute remote code
  3. Add explicit permission declarations

❌ Status: FAILED
```

### Deep Scan (with LLM)

```bash
aga scan ./my-skill --deep
```

Uses an LLM to analyze semantic intent-alignment and detect subtle prompt injections.

### CI Mode

```bash
aga scan ./my-skill --ci   # exit code 0 = pass, 1 = fail
```

### JSON Output

```bash
aga scan ./my-skill --json
```

---

## 🧠 Design

AGA uses a **dual-engine architecture**:

| Engine | Type | What it cathes |
|---|---|---|
| **Rule Engine** | Deterministic pattern matching | Known malicious patterns, unsafe code, credential theft |
| **Semantic Engine** (`--deep`) | LLM-powered analysis | Intent-behavior misalignment, subtle prompt injection |

The Rule Engine runs on every scan (zero cost, sub-second). The Semantic Engine is opt-in for deeper analysis.

---

## 🧩 Command Reference

| Command | Description |
|---|---|
| `aga scan <path>` | Scan a skill directory |
| `aga scan --deep <path>` | Deep scan with LLM analysis |
| `aga scan --json <path>` | JSON output for tool consumption |
| `aga scan --ci <path>` | CI mode (exit code driven) |
| `aga rule list` | List loaded detection rules |
| `aga rule pull` | Pull latest community rules |
| `aga bench run` | Run MalSkillBench benchmark |
| `aga config show` | Show current configuration |
| `aga data pull` | Download benchmark datasets |

---

## 📦 SDK Usage

```python
from aga import Analyzer

analyzer = Analyzer()

# Single scan
report = analyzer.scan("./my-skill")
print(f"Risk: {report.risk_score}/100 ({report.risk_level})")

# Batch scan
reports = analyzer.batch_scan(["./skill-a", "./skill-b"])
for r in sorted(reports, key=lambda r: r.risk_score, reverse=True):
    print(f"{r.skill_name}: {r.risk_score}")
```

---

## 📊 Benchmark (7,891 Skills · 16 Rules · Dual Engine)

### Full-scale (MalSkillBench entire dataset)

| Metric | Score |
|---|---|
| **Precision** | 66.2% |
| **Recall** | 81.1% |
| **F1 Score** | 72.9% |
| **Accuracy** | 70.2% |
| **Skills scanned** | 7,891 (3,898 malware + 3,993 benign) |
| **Scan time** | 523s (15 skills/s, streaming from git, single-threaded) |

### Curated subset (50 labeled skills)

| Metric | Score |
|---|---|
| **Precision** | 78.1% |
| **Recall** | 100.0% |
| **F1 Score** | 87.7% |

### Per-behavior recall (full dataset, 16 rules)

| B1: 43.9% | B2: 17.7% | B3: 77.6% | B4: 72.4% | B5: 99.2% |
| B6: 92.8% | B7: 77.2% | B8: 85.1% | B9: 52.3% | B10: 33.3% |
| B11: 71.4% | B12: 20.8% | B13: 38.9% | B14: 6.9% | B15: 29.3% |

**Key insight**: CI behaviors (B1-B9, avg 70.5%) are significantly easier for rule engines than PI behaviors (B10-B15, avg 33.4%). B14 (Goal Hijacking, 6.9%) is purely semantic — effectively invisible to static analysis. The `--deep` semantic engine (DeepSeek-powered) is essential for PI coverage.

Run the benchmark yourself:
```bash
aga data pull malskillbench
aga bench run
```

---

## 🗺 Roadmap

- [x] Project scaffolding and CLI skeleton (`aga scan` works end-to-end)
- [x] Rule Engine with 15 built-in rules (B1–B15 full coverage)
- [x] MalSkillBench benchmark suite (50-skills, precision/recall tracked)
- [ ] `--deep` LLM semantic analysis (Phase 2)
- [ ] Docker sandbox runtime verification (Phase 3)
- [ ] Web Dashboard & enterprise policy center

---

## 🔬 Research Alignment

AGA's risk taxonomy maps to the MalSkillBench three-dimensional attack space:

| Vector | Behaviors | Detection | Status |
|---|---|---|---|
| **CI** (Code Injection) | B1–B9 | Rule Engine + AST analysis | 77.3% precision |
| **PI** (Prompt Injection) | B10–B15 | Rule Engine + instruction analysis | Requires `--deep` for B14/B15 |
| **MIXED** | B1–B9 coordinated | Dual-engine joint analysis | Rule engine detects CI component |

---

## 🤝 Contributing

AGA is open source (Apache 2.0) and community-driven. The easiest way to contribute:

1. Write a detection rule (just a YAML file!) — `aga rule contribute`
2. Report a false positive or missed detection
3. Improve the parser for new skill formats

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE) for full text.

---

## 📚 Citation & Attribution

AGA's behavior taxonomy (B1-B15) is derived from MalSkillBench. If you use AGA in research, please cite:

```bibtex
@misc{guo2026malskillbench,
  title={MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills},
  author={Wenbo Guo and Wei Zeng and Chengwei Liu and Xiaojun Jia and
          Yijia Xu and Lei Tang and Yong Fang and Yang Liu},
  year={2026},
  eprint={2606.07131},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
}
```

See [ATTRIBUTION.md](ATTRIBUTION.md) for full attribution details.

---

*AGA · Secure your Skills. Guard your Agents.*

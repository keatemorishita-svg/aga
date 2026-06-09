# Attribution

AGA is built on the shoulders of the following work.

## MalSkillBench

AGA's behavior taxonomy (B1-B15), detection keywords, attack vector classification (CI/PI/MIXED), and benchmark datasets are derived from MalSkillBench:

> Wenbo Guo, Wei Zeng, Chengwei Liu, Xiaojun Jia, Yijia Xu, Lei Tang, Yong Fang, and Yang Liu. "MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills." arXiv:2606.07131, 2026.

- Repository: https://github.com/lxyeternal/MalSkillBench
- Paper: https://arxiv.org/abs/2606.07131

The `aga/taxonomy/` module and `aga/sdk/rules/builtin/` rule set translate MalSkillBench's classification system into machine-actionable YAML rules. AGA is an independent project and is not affiliated with or endorsed by the MalSkillBench authors.

## SkillsMP

The benign skill samples used in AGA's benchmark are sourced from the SkillsMP ecosystem, collected through MalSkillBench's dataset.

## Follow-Builders

The Builder OS project methodology that guided AGA's development is based on work by Zara Zhang:

- Repository: https://github.com/zarazhangrui/follow-builders
- License: MIT

---

*AGA is Apache 2.0 licensed. The MalSkillBench taxonomy (B1-B15 definitions and keywords) is used as a research reference. All detection rules are original implementations in YAML format.*

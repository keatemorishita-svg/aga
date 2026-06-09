"""AGA · Agent Governance & Assurance — AI Agent Skill security scanner.

Usage:
    from aga import Analyzer
    report = Analyzer().scan("./my-skill")
"""

__version__ = "0.1.0"
__author__ = "AGA Contributors"
__license__ = "Apache-2.0"

# Public API
from aga.sdk.analyzer import Analyzer
from aga.sdk.parser import Parser
from aga.sdk.reporter import RiskReport, RiskLevel, Reporter
from aga.sdk.rules.engine import RuleEngine, RuleSet, RuleLoader

__all__ = [
    "__version__",
    "Analyzer",
    "Parser",
    "RiskReport",
    "RiskLevel",
    "Reporter",
    "RuleEngine",
    "RuleSet",
    "RuleLoader",
]

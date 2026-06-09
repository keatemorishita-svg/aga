"""Semantic Engine — LLM-powered intent-behavior alignment analysis.

This module is invoked when the user runs `aga scan --deep`.
It sends the parsed SkillIR to an LLM for semantic judgment
of whether the SKILL.md description matches the actual code behavior.
"""

from aga.sdk.semantic.engine import SemanticEngine

__all__ = ["SemanticEngine"]

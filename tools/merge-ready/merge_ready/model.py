"""Data models for MergeReady validation findings, verdicts, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity levels for findings."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"

    @classmethod
    def from_str(cls, val: str) -> Severity:
        upper = val.upper()
        if upper in ("WARN", "WARNING"):
            return cls.WARNING
        if upper == "INFO":
            return cls.INFO
        return cls.ERROR


class Verdict(str, Enum):
    """Evaluation verdict for individual rules."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    NA = "N/A"


@dataclass
class Finding:
    """A concrete, evidence-backed issue or recommendation."""

    rule_id: str
    severity: Severity
    message: str
    path: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    fix: Optional[str] = None
    source_rule: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "fix": self.fix,
            "source_rule": self.source_rule,
        }


@dataclass
class RuleResult:
    """The outcome of running a specific check rule."""

    rule_id: str
    name: str
    verdict: Verdict
    reason: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ValidationReport:
    """Aggregated validation report across all evaluated rules."""

    project_path: str
    category: str
    slug: str
    base_ref: Optional[str] = None
    results: dict[str, RuleResult] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)

    def add_result(self, result: RuleResult) -> None:
        self.results[result.rule_id] = result
        self.recompute_summary()

    def recompute_summary(self) -> None:
        counts = {
            "pass": 0,
            "fail": 0,
            "warn": 0,
            "skip": 0,
            "na": 0,
            "findings_total": 0,
            "errors": 0,
            "warnings": 0,
            "infos": 0,
        }
        for res in self.results.values():
            if res.verdict == Verdict.PASS:
                counts["pass"] += 1
            elif res.verdict == Verdict.FAIL:
                counts["fail"] += 1
            elif res.verdict == Verdict.WARN:
                counts["warn"] += 1
            elif res.verdict == Verdict.SKIP:
                counts["skip"] += 1
            elif res.verdict == Verdict.NA:
                counts["na"] += 1

            for f in res.findings:
                counts["findings_total"] += 1
                if f.severity == Severity.ERROR:
                    counts["errors"] += 1
                elif f.severity == Severity.WARNING:
                    counts["warnings"] += 1
                elif f.severity == Severity.INFO:
                    counts["infos"] += 1

        self.summary = counts

    @property
    def has_failures(self) -> bool:
        return self.summary.get("fail", 0) > 0 or self.summary.get("errors", 0) > 0

    @property
    def has_warnings(self) -> bool:
        return self.summary.get("warn", 0) > 0 or self.summary.get("warnings", 0) > 0

    @property
    def has_skips(self) -> bool:
        return self.summary.get("skip", 0) > 0

    def exit_code(self, strict: bool = False) -> int:
        if self.has_failures:
            return 1
        if strict and (self.has_warnings or self.has_skips):
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "category": self.category,
            "slug": self.slug,
            "base_ref": self.base_ref,
            "summary": self.summary,
            "results": {k: v.to_dict() for k, v in self.results.items()},
        }

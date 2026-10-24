"""Check registry and orchestration for MergeReady."""

from __future__ import annotations

from typing import Any, Callable

from merge_ready.checks.agent_safety import check_a01, check_a02, check_a03
from merge_ready.checks.deps import check_r01
from merge_ready.checks.env_drift import check_e01, check_e02
from merge_ready.checks.layout import check_f01, check_l01, check_l02
from merge_ready.checks.scope import check_i01, check_p01
from merge_ready.checks.secrets import check_s01, check_s02
from merge_ready.checks.template import check_d01, check_d02, check_r02
from merge_ready.model import RuleResult, ValidationReport
from merge_ready.project import ProjectContext

CHECK_REGISTRY: list[tuple[str, Callable[[ProjectContext, dict[str, Any]], RuleResult]]] = [
    ("L01", check_l01),
    ("L02", check_l02),
    ("F01", check_f01),
    ("D01", check_d01),
    ("D02", check_d02),
    ("S01", check_s01),
    ("S02", check_s02),
    ("P01", check_p01),
    ("I01", check_i01),
    ("E01", check_e01),
    ("E02", check_e02),
    ("R01", check_r01),
    ("R02", check_r02),
    ("A01", check_a01),
    ("A02", check_a02),
    ("A03", check_a03),
]


def run_all_checks(ctx: ProjectContext) -> ValidationReport:
    """Execute all registered checks against the given project context deterministically."""
    report = ValidationReport(
        project_path=str(ctx.project_path),
        category=ctx.category,
        slug=ctx.slug,
        base_ref=ctx.base_ref,
    )

    for rule_id, check_fn in CHECK_REGISTRY:
        config = ctx.rules_config.get(rule_id, {})
        try:
            result = check_fn(ctx, config)
            report.add_result(result)
        except Exception as e:
            from merge_ready.model import Finding, Severity, Verdict
            error_finding = Finding(
                rule_id=rule_id,
                severity=Severity.ERROR,
                message=f"Check execution failed due to an internal error: {e}",
                fix="Inspect project files for syntax errors or report this issue.",
                source_rule=config.get("source_rule", "MergeReady Runtime"),
            )
            report.add_result(
                RuleResult(
                    rule_id=rule_id,
                    name=config.get("name", rule_id),
                    verdict=Verdict.FAIL,
                    reason=f"Exception during check: {e}",
                    findings=[error_finding],
                )
            )

    return report

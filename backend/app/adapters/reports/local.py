"""Local structured security report renderer. Does not upload anywhere."""

from __future__ import annotations

from collections.abc import Sequence

from app.adapters.reports.base import ReportProvider
from app.domain.evidence import EvidenceBundle
from app.domain.findings import FindingStatus, SecurityFinding
from app.domain.reports import SecurityReport


class LocalReportProvider(ReportProvider):
    @property
    def provider_id(self) -> str:
        return "local"

    def render(
        self,
        findings: Sequence[SecurityFinding],
        *,
        evidence: EvidenceBundle | None = None,
    ) -> SecurityReport:
        lines = [
            "# BugForge Security Report",
            "",
            "Hypotheses are not verified findings. Only items marked verified",
            "have independent supporting evidence.",
            "",
        ]
        if not findings:
            lines.append("No findings.")
        for finding in findings:
            lines.append(f"## [{finding.status.value}] {finding.title}")
            if finding.vulnerability_class:
                lines.append(f"- Class: {finding.vulnerability_class}")
            if finding.target:
                lines.append(f"- Target: {finding.target}")
            if finding.hypothesis:
                lines.append(f"- Hypothesis: {finding.hypothesis}")
            if finding.description:
                lines.append(f"- Description: {finding.description}")
            if finding.evidence:
                lines.append(f"- Evidence items: {len(finding.evidence)}")
                for item in finding.evidence.items:
                    lines.append(f"  - [{item.kind.value}] {item.summary}")
            lines.append("")

        extra = evidence or EvidenceBundle()
        metadata = {
            "finding_count": str(len(findings)),
            "verified_count": str(sum(1 for f in findings if f.status is FindingStatus.VERIFIED)),
            "standalone_evidence_count": str(len(extra)),
        }
        return SecurityReport(
            title="BugForge Security Report",
            findings=tuple(findings),
            generated_by=self.provider_id,
            body="\n".join(lines).strip() + "\n",
            metadata=metadata,
        )

    def submit(self, report: SecurityReport) -> str:
        """Local submission is a no-op upload: return the rendered body."""
        return report.body

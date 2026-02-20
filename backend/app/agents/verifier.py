"""
Anti-Hallucination Verification Gates — fail-fast sequential checks.
"""

import re
from dataclasses import dataclass, field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.asset import Asset
from app.models.finding import Finding

import structlog

logger = structlog.get_logger()


@dataclass
class GateResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class VerificationResult:
    passed: bool
    score: float  # 0.0 to 1.0
    gates: list[GateResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    flagged_claims: list[str] = field(default_factory=list)


class OutputVerifier:
    """Runs sequential verification gates on LLM output."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def verify(self, content: str, capability: str) -> VerificationResult:
        """Run all gates. Returns result with pass/fail and score."""
        if not content or not content.strip():
            return VerificationResult(passed=True, score=1.0)

        gates: list[GateResult] = []
        warnings: list[str] = []
        flagged: list[str] = []

        # Gate 1: IP grounding
        ip_gate = await self._check_ip_grounding(content)
        gates.append(ip_gate)
        if not ip_gate.passed:
            flagged.append(ip_gate.detail)

        # Gate 2: ID grounding
        id_gate = await self._check_id_grounding(content)
        gates.append(id_gate)
        if not id_gate.passed:
            flagged.append(id_gate.detail)

        # Gate 3: CVE format
        cve_gate = self._check_cve_format(content)
        gates.append(cve_gate)
        if not cve_gate.passed:
            flagged.append(cve_gate.detail)

        # Gate 4: Statistics
        stats_gate = await self._check_statistics(content)
        gates.append(stats_gate)
        if not stats_gate.passed:
            warnings.append(stats_gate.detail)

        # Calculate score
        passed_count = sum(1 for g in gates if g.passed)
        total = len(gates)
        score = passed_count / total if total > 0 else 1.0

        overall_passed = score >= 0.5

        return VerificationResult(
            passed=overall_passed,
            score=score,
            gates=gates,
            warnings=warnings,
            flagged_claims=flagged,
        )

    async def _check_ip_grounding(self, content: str) -> GateResult:
        """Check that IPs mentioned in output exist in the asset DB."""
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        found_ips = set(ip_pattern.findall(content))

        # Exclude common non-asset IPs
        exclude = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}
        found_ips -= exclude

        if not found_ips:
            return GateResult(name="ip_grounding", passed=True, detail="No IPs to verify")

        # Check which IPs exist in DB
        result = await self.db.execute(
            select(Asset.ip_address).where(Asset.ip_address.in_(list(found_ips)))
        )
        db_ips = {row[0] for row in result.all()}

        matched = found_ips & db_ips
        unmatched = found_ips - db_ips

        if not found_ips:
            ratio = 1.0
        else:
            ratio = len(matched) / len(found_ips)

        if ratio > 0.5:
            return GateResult(
                name="ip_grounding",
                passed=True,
                detail=f"{len(matched)}/{len(found_ips)} IPs verified",
            )
        return GateResult(
            name="ip_grounding",
            passed=False,
            detail=f"Ungrounded IPs: {', '.join(sorted(unmatched))}",
        )

    async def _check_id_grounding(self, content: str) -> GateResult:
        """Check that UUIDs referenced in output match real findings."""
        uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
        found_uuids = set(uuid_pattern.findall(content))

        if not found_uuids:
            return GateResult(name="id_grounding", passed=True, detail="No UUIDs to verify")

        # Check findings
        result = await self.db.execute(
            select(Finding.id).where(Finding.id.in_(list(found_uuids)))
        )
        db_ids = {row[0] for row in result.all()}
        unmatched = found_uuids - db_ids

        if not unmatched:
            return GateResult(
                name="id_grounding",
                passed=True,
                detail=f"All {len(found_uuids)} UUIDs verified",
            )
        return GateResult(
            name="id_grounding",
            passed=False,
            detail=f"Ungrounded UUIDs: {', '.join(sorted(unmatched)[:3])}",
        )

    def _check_cve_format(self, content: str) -> GateResult:
        """Check that CVE IDs have valid format and year range."""
        cve_pattern = re.compile(r'CVE-(\d{4})-\d+', re.IGNORECASE)
        found_cves = cve_pattern.findall(content)

        if not found_cves:
            return GateResult(name="cve_format", passed=True, detail="No CVEs to verify")

        invalid_years = []
        for year_str in found_cves:
            year = int(year_str)
            if year < 1999 or year > 2027:
                invalid_years.append(year_str)

        if not invalid_years:
            return GateResult(
                name="cve_format",
                passed=True,
                detail=f"All {len(found_cves)} CVE years valid",
            )
        return GateResult(
            name="cve_format",
            passed=False,
            detail=f"Invalid CVE years: {', '.join(invalid_years)}",
        )

    async def _check_statistics(self, content: str) -> GateResult:
        """Check 'X critical/high findings' claims against actual DB counts."""
        stat_pattern = re.compile(r'(\d+)\s+(critical|high|medium|low)\s+findings?', re.IGNORECASE)
        claims = stat_pattern.findall(content)

        if not claims:
            return GateResult(name="statistics", passed=True, detail="No statistical claims to verify")

        mismatches = []
        for count_str, severity in claims:
            claimed = int(count_str)
            actual = (await self.db.execute(
                select(func.count(Finding.id)).where(Finding.severity == severity.lower())
            )).scalar() or 0

            if claimed != actual:
                mismatches.append(f"claimed {claimed} {severity}, actual {actual}")

        if not mismatches:
            return GateResult(
                name="statistics",
                passed=True,
                detail=f"All {len(claims)} statistical claims verified",
            )
        return GateResult(
            name="statistics",
            passed=False,
            detail=f"Mismatches: {'; '.join(mismatches)}",
        )

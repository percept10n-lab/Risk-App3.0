import hashlib
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.finding import Finding


class FindingService:
    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def compute_dedupe_hash(asset_id: str, source_tool: str, source_check: str, title: str) -> str:
        content = f"{asset_id}:{source_tool}:{source_check}:{title}"
        return hashlib.sha256(content.encode()).hexdigest()

    async def create_deduplicated(self, finding_data: dict) -> tuple[Finding, bool]:
        dedupe_hash = self.compute_dedupe_hash(
            finding_data["asset_id"],
            finding_data["source_tool"],
            finding_data["source_check"],
            finding_data["title"],
        )

        result = await self.db.execute(
            select(Finding).where(Finding.dedupe_hash == dedupe_hash)
        )
        existing = result.scalar_one_or_none()

        if existing:
            return existing, False

        finding_data["dedupe_hash"] = dedupe_hash
        finding = Finding(**finding_data)
        self.db.add(finding)
        await self.db.flush()
        return finding, True

    async def get_by_asset(self, asset_id: str) -> list[Finding]:
        result = await self.db.execute(
            select(Finding).where(Finding.asset_id == asset_id).order_by(Finding.severity.desc())
        )
        return list(result.scalars().all())

    async def get_severity_stats(self) -> dict:
        from sqlalchemy import func
        result = await self.db.execute(
            select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
        )
        return dict(result.all())

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.asset import Asset


class AssetService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def find_by_ip(self, ip_address: str) -> Asset | None:
        result = await self.db.execute(select(Asset).where(Asset.ip_address == ip_address))
        return result.scalar_one_or_none()

    async def find_by_mac(self, mac_address: str) -> Asset | None:
        result = await self.db.execute(select(Asset).where(Asset.mac_address == mac_address))
        return result.scalar_one_or_none()

    async def upsert_from_scan(self, scan_data: dict) -> Asset:
        existing = await self.find_by_ip(scan_data["ip_address"])
        if existing:
            for key, value in scan_data.items():
                if value is not None:
                    setattr(existing, key, value)
            from datetime import datetime
            existing.last_seen = datetime.utcnow()
            await self.db.flush()
            return existing
        asset = Asset(**scan_data)
        self.db.add(asset)
        await self.db.flush()
        return asset

    async def get_by_zone(self, zone: str) -> list[Asset]:
        result = await self.db.execute(select(Asset).where(Asset.zone == zone))
        return list(result.scalars().all())

    async def get_stats(self) -> dict:
        from sqlalchemy import func
        result = await self.db.execute(
            select(Asset.zone, Asset.criticality, func.count(Asset.id))
            .group_by(Asset.zone, Asset.criticality)
        )
        stats = {}
        for zone, criticality, count in result:
            if zone not in stats:
                stats[zone] = {}
            stats[zone][criticality] = count
        return stats

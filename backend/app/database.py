from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool
from sqlalchemy import event
from app.config import settings
import os

os.makedirs(os.path.dirname(settings.database_url.replace("sqlite+aiosqlite:///", "")) or "data", exist_ok=True)

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL mode for better concurrency with SQLite."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        from app.models import (
            asset, finding, threat, risk, mitre_mapping,
            artifact, audit_event, run, policy, override,
            vulnerability, baseline, schedule
        )
        await conn.run_sync(Base.metadata.create_all)

        # Startup migration for new columns (SQLite ALTER TABLE)
        from sqlalchemy import text
        try:
            await conn.execute(text("ALTER TABLE risks ADD COLUMN likelihood_factors JSON"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE risks ADD COLUMN impact_factors JSON"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE risks ADD COLUMN treatment_measures JSON"))
        except Exception:
            pass

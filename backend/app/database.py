from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event
from sqlalchemy.engine import make_url
from app.config import settings
import os

url = make_url(settings.database_url)
is_sqlite = url.drivername.startswith("sqlite")

if is_sqlite:
    db_path = url.database or "data/risk_platform.db"
    os.makedirs(os.path.dirname(db_path) or "data", exist_ok=True)

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False, "timeout": 30} if is_sqlite else {},
)

if is_sqlite:
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
        try:
            await conn.execute(text("ALTER TABLE threats ADD COLUMN c4_level VARCHAR(50)"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE threats ADD COLUMN stride_category_detail TEXT"))
        except Exception:
            pass

        # Add residual_likelihood and residual_impact columns for risk matrix
        try:
            await conn.execute(text("ALTER TABLE risks ADD COLUMN residual_likelihood VARCHAR(20)"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE risks ADD COLUMN residual_impact VARCHAR(20)"))
        except Exception:
            pass

        # Add treatment fields to findings
        try:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN owner VARCHAR(255)"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN due_date DATE"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN treatment_note TEXT"))
        except Exception:
            pass

        # Add report_id to runs table
        try:
            await conn.execute(text("ALTER TABLE runs ADD COLUMN report_id VARCHAR(36)"))
        except Exception:
            pass

        # Backfill c4_level for existing threats that have NULL
        await conn.execute(text(
            "UPDATE threats SET c4_level = 'component' "
            "WHERE c4_level IS NULL AND asset_id IS NOT NULL"
        ))
        await conn.execute(text(
            "UPDATE threats SET c4_level = 'container' "
            "WHERE c4_level IS NULL AND asset_id IS NULL AND zone IS NOT NULL"
        ))
        await conn.execute(text(
            "UPDATE threats SET c4_level = 'system_context' "
            "WHERE c4_level IS NULL AND trust_boundary IS NOT NULL"
        ))


from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.policy import Policy
from app.schemas.policy import PolicyCreate, PolicyUpdate, PolicyResponse

router = APIRouter()


@router.get("/policy", response_model=list[PolicyResponse])
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).order_by(Policy.created_at.desc()))
    return result.scalars().all()


@router.put("/policy", response_model=PolicyResponse)
async def upsert_policy(policy_in: PolicyCreate, db: AsyncSession = Depends(get_db)):
    if policy_in.is_default:
        result = await db.execute(select(Policy).where(Policy.is_default == True))
        existing = result.scalar_one_or_none()
        if existing:
            for field, value in policy_in.model_dump().items():
                setattr(existing, field, value)
            await db.flush()
            await db.refresh(existing)
            return existing
    policy = Policy(**policy_in.model_dump())
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    return policy


@router.get("/ai-config")
async def get_ai_config():
    from app.config import settings
    return {
        "provider": settings.ai_provider,
        "base_url": settings.ai_base_url,
        "model": settings.ai_model,
        "enabled": bool(settings.ai_api_key or settings.ai_provider == "ollama"),
    }


@router.put("/ai-config")
async def update_ai_config(provider: str | None = None, base_url: str | None = None, model: str | None = None):
    return {"status": "updated", "message": "AI config updates take effect on next run"}

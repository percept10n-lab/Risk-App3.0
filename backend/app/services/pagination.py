from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def paginate(db: AsyncSession, query, page: int, page_size: int) -> tuple[list, int]:
    """Execute a query with pagination, returning (items, total).

    Derives the count query from the base query automatically,
    eliminating the need to maintain parallel query + count_query.
    """
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(query.offset((page - 1) * page_size).limit(page_size))
    items = list(result.scalars().all())
    return items, total

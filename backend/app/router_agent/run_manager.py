import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.run import Run
from app.router_agent.engine import RouterEngine, WorkflowState

import structlog

logger = structlog.get_logger()


class RunManager:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.engines: dict[str, RouterEngine] = {}

    async def create_run(self, policy_id: str | None = None, scope: dict | None = None, triggered_by: str = "user") -> Run:
        run = Run(
            id=str(uuid.uuid4()),
            status="pending",
            policy_id=policy_id,
            scope=scope or {},
            triggered_by=triggered_by,
            config_snapshot={},
            created_at=datetime.utcnow(),
        )
        self.db.add(run)
        await self.db.flush()

        self.engines[run.id] = RouterEngine()
        logger.info("Run created", run_id=run.id)
        return run

    async def start_run(self, run_id: str) -> bool:
        result = await self.db.execute(select(Run).where(Run.id == run_id))
        run = result.scalar_one_or_none()
        if not run or run.status != "pending":
            return False

        run.status = "running"
        run.started_at = datetime.utcnow()
        run.current_step = "discovery"

        engine = self.engines.get(run_id) or RouterEngine()
        engine.transition(WorkflowState.DISCOVERY)
        self.engines[run_id] = engine

        logger.info("Run started", run_id=run_id)
        return True

    async def advance_step(self, run_id: str, step: str) -> bool:
        result = await self.db.execute(select(Run).where(Run.id == run_id))
        run = result.scalar_one_or_none()
        if not run or run.status != "running":
            return False

        engine = self.engines.get(run_id)
        if not engine:
            return False

        try:
            target = WorkflowState(step)
        except ValueError:
            return False

        if engine.transition(target):
            completed = run.steps_completed or []
            if run.current_step and run.current_step not in completed:
                completed.append(run.current_step)
            run.steps_completed = completed
            run.current_step = step

            if target == WorkflowState.COMPLETED:
                run.status = "completed"
                run.completed_at = datetime.utcnow()
            elif target == WorkflowState.FAILED:
                run.status = "failed"
                run.completed_at = datetime.utcnow()

            logger.info("Step advanced", run_id=run_id, step=step)
            return True
        return False

    async def get_status(self, run_id: str) -> dict | None:
        result = await self.db.execute(select(Run).where(Run.id == run_id))
        run = result.scalar_one_or_none()
        if not run:
            return None

        engine = self.engines.get(run_id)
        return {
            "run_id": run_id,
            "status": run.status,
            "current_step": run.current_step,
            "steps_completed": run.steps_completed or [],
            "next_steps": engine.get_next_steps() if engine else [],
        }

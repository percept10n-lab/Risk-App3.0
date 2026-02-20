from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.risk import Risk
from app.config import load_yaml_config


class RiskService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self._matrix = None

    @property
    def matrix(self) -> dict:
        if self._matrix is None:
            raw = load_yaml_config("risk_matrix.yaml")
            if raw and "matrix" in raw:
                # Transform YAML nested dict {lik: {imp: level}} to flat
                # {levels: {"lik,imp": level, "lik_imp": level}} for frontend
                levels = {}
                for lik, impacts in raw["matrix"].items():
                    if isinstance(impacts, dict):
                        for imp, level in impacts.items():
                            levels[f"{lik},{imp}"] = level
                            levels[f"{lik}_{imp}"] = level
                self._matrix = {
                    **raw,
                    "levels": levels,
                }
            else:
                self._matrix = self._default_matrix()
        return self._matrix

    @staticmethod
    def _default_matrix() -> dict:
        levels = {}
        pairs = [
            ("very_low", "negligible", "low"), ("very_low", "low", "low"),
            ("very_low", "medium", "low"), ("very_low", "high", "medium"),
            ("very_low", "critical", "medium"),
            ("low", "negligible", "low"), ("low", "low", "low"),
            ("low", "medium", "medium"), ("low", "high", "medium"),
            ("low", "critical", "high"),
            ("medium", "negligible", "low"), ("medium", "low", "medium"),
            ("medium", "medium", "medium"), ("medium", "high", "high"),
            ("medium", "critical", "high"),
            ("high", "negligible", "medium"), ("high", "low", "medium"),
            ("high", "medium", "high"), ("high", "high", "high"),
            ("high", "critical", "critical"),
            ("very_high", "negligible", "medium"), ("very_high", "low", "high"),
            ("very_high", "medium", "high"), ("very_high", "high", "critical"),
            ("very_high", "critical", "critical"),
        ]
        for lik, imp, level in pairs:
            levels[f"{lik},{imp}"] = level
            levels[f"{lik}_{imp}"] = level
        return {"levels": levels}

    def calculate_risk_level(self, likelihood: str, impact: str) -> str:
        matrix = self.matrix.get("levels", self._default_matrix()["levels"])
        return matrix.get(f"{likelihood},{impact}", matrix.get(f"{likelihood}_{impact}", "medium"))

    async def get_risk_stats(self) -> dict:
        result = await self.db.execute(
            select(Risk.risk_level, func.count(Risk.id)).group_by(Risk.risk_level)
        )
        return dict(result.all())

    async def get_treatment_stats(self) -> dict:
        result = await self.db.execute(
            select(Risk.treatment, func.count(Risk.id)).group_by(Risk.treatment)
        )
        return dict(result.all())

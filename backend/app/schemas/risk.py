from pydantic import BaseModel
from datetime import datetime, date


class RiskCreate(BaseModel):
    asset_id: str
    threat_id: str | None = None
    finding_id: str | None = None
    scenario: str
    likelihood: str
    likelihood_rationale: str | None = None
    impact: str
    impact_rationale: str | None = None
    risk_level: str
    confidentiality_impact: str = "none"
    integrity_impact: str = "none"
    availability_impact: str = "none"
    likelihood_factors: dict | None = None
    impact_factors: dict | None = None


class RiskUpdate(BaseModel):
    scenario: str | None = None
    likelihood: str | None = None
    likelihood_rationale: str | None = None
    impact: str | None = None
    impact_rationale: str | None = None
    risk_level: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    status: str | None = None


class TreatmentRequest(BaseModel):
    treatment: str  # mitigate, transfer, avoid, accept
    treatment_plan: str | None = None
    treatment_measures: list[str] | None = None
    treatment_owner: str | None = None
    treatment_due_date: date | None = None
    residual_risk_level: str | None = None
    residual_likelihood: str | None = None
    residual_impact: str | None = None


class RiskResponse(BaseModel):
    id: str
    asset_id: str
    threat_id: str | None = None
    finding_id: str | None = None
    scenario: str
    likelihood: str
    likelihood_rationale: str | None = None
    impact: str
    impact_rationale: str | None = None
    risk_level: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    treatment: str | None = None
    treatment_plan: str | None = None
    treatment_measures: list[str] | None = None
    treatment_owner: str | None = None
    treatment_due_date: date | None = None
    likelihood_factors: dict | None = None
    impact_factors: dict | None = None
    residual_risk_level: str | None = None
    residual_likelihood: str | None = None
    residual_impact: str | None = None
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

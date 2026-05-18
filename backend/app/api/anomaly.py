from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.services.anomaly_service import anomaly_service
from app.models.traffic import TrafficLog
import uuid

router = APIRouter(prefix="/api/anomaly", tags=["Anomaly Detection"])

@router.post("/train")
async def train_model(db: AsyncSession = Depends(get_db)):
    """
    Train the Isolation Forest model on all stored traffic logs.
    Call this once after seeding enough data (20+ records).
    """
    result = await anomaly_service.train_model(db)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["reason"])
    return result

@router.post("/analyze/{log_id}")
async def analyze_log(
    log_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Run full anomaly analysis on a specific traffic log.
    Scores it, checks schema deviations, and asks LLM to explain if risky.
    """
    result = await db.execute(
        select(TrafficLog).where(TrafficLog.id == log_id)
    )
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Traffic log not found")

    return await anomaly_service.analyze(log, db)

@router.post("/analyze-all")
async def analyze_all(db: AsyncSession = Depends(get_db)):
    """
    Run anomaly analysis on all unscored traffic logs.
    Use this after training the model to score existing data.
    """
    result = await db.execute(
        select(TrafficLog).where(TrafficLog.anomaly_score == None)
    )
    logs = result.scalars().all()

    if not logs:
        return {"message": "All logs already scored", "count": 0}

    results = {"high": 0, "medium": 0, "low": 0, "total": len(logs)}

    for log in logs:
        analysis = await anomaly_service.analyze(log, db)
        results[analysis["risk_level"]] += 1

    return results

@router.get("/flagged")
async def get_flagged(db: AsyncSession = Depends(get_db)):
    """Returns all traffic logs flagged as high risk."""
    result = await db.execute(
        select(TrafficLog)
        .where(TrafficLog.is_flagged == True)
        .order_by(TrafficLog.timestamp.desc())
    )
    logs = result.scalars().all()
    return [
        {
            "id": str(log.id),
            "method": log.method,
            "endpoint": log.endpoint,
            "status_code": log.status_code,
            "latency_ms": log.latency_ms,
            "anomaly_score": log.anomaly_score,
            "risk_level": log.risk_level,
            "source_ip": log.source_ip,
            "timestamp": log.timestamp.isoformat(),
        }
        for log in logs
    ]
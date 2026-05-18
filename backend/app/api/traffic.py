

# from fastapi import APIRouter, Depends, HTTPException, Query
# from sqlalchemy.ext.asyncio import AsyncSession
# from app.core.database import get_db
# from app.services.traffic_service import traffic_service
# from pydantic import BaseModel
# from typing import Optional
# import uuid

# router = APIRouter(prefix="/api/traffic", tags=["Traffic"])

# class TrafficIngestRequest(BaseModel):
#     method: str
#     url: str
#     request_headers: dict = {}
#     request_body: Optional[str] = None
#     query_params: dict = {}
#     status_code: Optional[int] = None
#     response_headers: dict = {}
#     response_body: Optional[str] = None
#     latency_ms: Optional[float] = None
#     source_ip: Optional[str] = None
#     session_id: Optional[str] = None

# class TrafficLogResponse(BaseModel):
#     id: str
#     method: str
#     endpoint: str
#     full_url: str
#     status_code: Optional[int]
#     latency_ms: Optional[float]
#     risk_level: Optional[str]
#     anomaly_score: Optional[float]
#     is_flagged: bool
#     llm_explanation: Optional[str]
#     source_ip: Optional[str]

# @router.post("/ingest", response_model=TrafficLogResponse, status_code=201)
# async def ingest_traffic(
#     payload: TrafficIngestRequest,
#     db: AsyncSession = Depends(get_db)
# ):
#     result = await traffic_service.ingest(payload.model_dump(), db)
#     return result

# @router.get("/recent")
# async def get_recent_traffic(
#     limit: int = Query(default=50, le=200),
#     db: AsyncSession = Depends(get_db)
# ):
#     logs = await traffic_service.get_recent(db, limit=limit)
#     return [
#         {
#             "id": str(log.id),
#             "method": log.method,
#             "endpoint": log.endpoint,
#             "status_code": log.status_code,
#             "latency_ms": log.latency_ms,
#             "risk_level": log.risk_level,
#             "anomaly_score": log.anomaly_score,
#             "is_flagged": log.is_flagged,
#             "source_ip": log.source_ip,
#             "timestamp": log.timestamp.isoformat(),
#         }
#         for log in logs
#     ]

# @router.get("/stats")
# async def get_traffic_stats(db: AsyncSession = Depends(get_db)):
#     return await traffic_service.get_stats(db)

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.services.traffic_service import traffic_service
from pydantic import BaseModel
from typing import Optional
import uuid

router = APIRouter(prefix="/api/traffic", tags=["Traffic"])

class TrafficIngestRequest(BaseModel):
    method: str
    url: str
    request_headers: dict = {}
    request_body: Optional[str] = None
    query_params: dict = {}
    status_code: Optional[int] = None
    response_headers: dict = {}
    response_body: Optional[str] = None
    latency_ms: Optional[float] = None
    source_ip: Optional[str] = None
    session_id: Optional[str] = None

class TrafficIngestResponse(BaseModel):
    id: str
    method: str
    endpoint: str
    full_url: str
    status_code: Optional[int]
    latency_ms: Optional[float]
    risk_level: Optional[str]
    anomaly_score: Optional[float]
    is_flagged: bool
    explanation: Optional[str]               # ← renamed
    explanation_source: Optional[str]        # ← new
    source_ip: Optional[str]

@router.post("/ingest", response_model=TrafficIngestResponse, status_code=201)
async def ingest_traffic(
    payload: TrafficIngestRequest,
    db: AsyncSession = Depends(get_db)
):
    result = await traffic_service.ingest(payload.model_dump(), db)
    return result

@router.get("/recent")
async def get_recent_traffic(
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db)
):
    logs = await traffic_service.get_recent(db, limit=limit)
    return [
        {
            "id": str(log.id),
            "method": log.method,
            "endpoint": log.endpoint,
            "status_code": log.status_code,
            "latency_ms": log.latency_ms,
            "risk_level": log.risk_level,
            "anomaly_score": log.anomaly_score,
            "is_flagged": log.is_flagged,
            "source_ip": log.source_ip,
            "timestamp": log.timestamp.isoformat(),
        }
        for log in logs
    ]

@router.get("/stats")
async def get_traffic_stats(db: AsyncSession = Depends(get_db)):
    return await traffic_service.get_stats(db)
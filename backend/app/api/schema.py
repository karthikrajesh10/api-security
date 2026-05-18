from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.services.schema_service import schema_service

router = APIRouter(prefix="/api/schema", tags=["Schema"])

@router.get("/all")
async def get_all_schemas(db: AsyncSession = Depends(get_db)):
    """Returns all learned endpoint schemas."""
    schemas = await schema_service.get_all_schemas(db)
    return [
        {
            "endpoint": s.endpoint,
            "method": s.method,
            "sample_count": s.sample_count,
            "is_stable": s.is_stable,
            "avg_latency_ms": round(s.avg_latency_ms or 0, 2),
            "status_codes": s.status_codes,
            "request_fields": s.request_fields,
            "response_fields": s.response_fields,
        }
        for s in schemas
    ]

@router.get("/{method}/{path:path}")
async def get_schema(
    method: str,
    path: str,
    db: AsyncSession = Depends(get_db)
):
    """Returns the learned schema for a specific endpoint."""
    schema = await schema_service.get_schema(f"/{path}", method.upper(), db)
    if not schema:
        raise HTTPException(status_code=404, detail="No schema learned for this endpoint yet")
    return {
        "endpoint": schema.endpoint,
        "method": schema.method,
        "sample_count": schema.sample_count,
        "is_stable": schema.is_stable,
        "avg_latency_ms": round(schema.avg_latency_ms or 0, 2),
        "status_codes": schema.status_codes,
        "request_fields": schema.request_fields,
    }
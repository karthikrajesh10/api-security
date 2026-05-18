from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.services.rules_service import rules_service
from app.ml.anomaly_detector import anomaly_detector
from app.services.anomaly_service import anomaly_service
from sqlalchemy import select
from app.models.traffic import TrafficLog

router = APIRouter(prefix="/api/rules", tags=["Rules"])

@router.post("/reload")
async def reload_rules(db: AsyncSession = Depends(get_db)):
    """
    Re-read api_rules.yaml and apply to schemas + retrain model.
    Call this any time you update the rules doc.
    """
    # Step 1 — seed schemas from rules
    seed_result = await rules_service.apply_rules_to_schema(db)

    # Step 2 — generate synthetic vectors from rules
    synthetic_vectors = await rules_service.generate_synthetic_training_data(db)

    # Step 3 — combine with real traffic vectors
    result = await db.execute(select(TrafficLog))
    real_logs = result.scalars().all()

    from app.services.schema_service import schema_service
    from app.ml.features import extract_features

    real_vectors = []
    for log in real_logs:
        schema = await schema_service.get_schema(log.endpoint, log.method, db)
        real_vectors.append(extract_features(log, schema))

    all_vectors = synthetic_vectors + real_vectors

    # Step 4 — retrain with combined data
    trained = False
    if len(all_vectors) >= 20:
        trained = anomaly_detector.train(all_vectors)

    return {
        "schemas_seeded": seed_result["seeded"],
        "synthetic_vectors": len(synthetic_vectors),
        "real_vectors": len(real_vectors),
        "total_training_vectors": len(all_vectors),
        "model_retrained": trained,
    }

@router.get("/view")
async def view_rules():
    """Returns the current parsed rules from api_rules.yaml."""
    return rules_service.load_rules()

@router.get("/check/{method}/{path:path}")
async def check_endpoint_rules(method: str, path: str):
    """Returns the rules defined for a specific endpoint."""
    ep_rules = rules_service.get_endpoint_rules(f"/{path}", method.upper())
    if not ep_rules:
        return {"message": "No rules defined for this endpoint"}
    return ep_rules
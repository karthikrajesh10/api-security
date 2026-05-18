

# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import select, func
# from app.models.traffic import TrafficLog
# from app.ml.factory import model_provider
# from app.services.schema_service import schema_service
# from datetime import datetime
# import json

# class TrafficService:

#     async def ingest(self, data: dict, db: AsyncSession) -> TrafficLog:
#         text_for_embedding = self._build_embedding_text(data)

#         try:
#             embedding = await model_provider.embed(text_for_embedding)
#         except Exception:
#             embedding = []

#         log = TrafficLog(
#             timestamp=datetime.utcnow(),
#             method=data.get("method", "GET").upper(),
#             endpoint=self._extract_endpoint(data.get("url", "")),
#             full_url=data.get("url", ""),
#             request_headers=data.get("request_headers", {}),
#             request_body=self._safe_str(data.get("request_body")),
#             query_params=data.get("query_params", {}),
#             status_code=data.get("status_code"),
#             response_headers=data.get("response_headers", {}),
#             response_body=self._safe_str(data.get("response_body")),
#             latency_ms=data.get("latency_ms"),
#             source_ip=data.get("source_ip"),
#             session_id=data.get("session_id"),
#             user_agent=data.get("request_headers", {}).get("user-agent"),
#             embedding=embedding,
#             risk_level="low",
#             is_flagged=False,
#         )

#         db.add(log)
#         await db.commit()
#         await db.refresh(log)

#         # ── Schema learning happens here after every ingest ──
#         await schema_service.update_schema(log, db)

#         return log

#     async def get_recent(self, db: AsyncSession, limit: int = 50) -> list[TrafficLog]:
#         result = await db.execute(
#             select(TrafficLog)
#             .order_by(TrafficLog.timestamp.desc())
#             .limit(limit)
#         )
#         return result.scalars().all()

#     async def get_stats(self, db: AsyncSession) -> dict:
#         total = await db.execute(select(func.count(TrafficLog.id)))
#         flagged = await db.execute(
#             select(func.count(TrafficLog.id)).where(TrafficLog.is_flagged == True)
#         )
#         by_risk = await db.execute(
#             select(TrafficLog.risk_level, func.count(TrafficLog.id))
#             .group_by(TrafficLog.risk_level)
#         )
#         return {
#             "total_requests": total.scalar(),
#             "flagged_count": flagged.scalar(),
#             "by_risk_level": {row[0]: row[1] for row in by_risk.fetchall()}
#         }

#     def _extract_endpoint(self, url: str) -> str:
#         try:
#             from urllib.parse import urlparse
#             parsed = urlparse(url)
#             return parsed.path or url
#         except Exception:
#             return url

#     def _build_embedding_text(self, data: dict) -> str:
#         parts = [
#             f"method:{data.get('method', '')}",
#             f"endpoint:{self._extract_endpoint(data.get('url', ''))}",
#             f"status:{data.get('status_code', '')}",
#             f"latency:{data.get('latency_ms', '')}ms",
#         ]
#         body = data.get("request_body")
#         if body:
#             text = body if isinstance(body, str) else json.dumps(body)
#             parts.append(f"body:{text[:200]}")
#         return " | ".join(parts)

#     def _safe_str(self, value) -> str | None:
#         if value is None:
#             return None
#         if isinstance(value, (dict, list)):
#             return json.dumps(value)
#         return str(value)

# traffic_service = TrafficService()


from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.traffic import TrafficLog
from app.ml.factory import model_provider
from app.services.schema_service import schema_service
from app.services.anomaly_service import anomaly_service
from datetime import datetime
import json

class TrafficService:

    async def ingest(self, data: dict, db: AsyncSession) -> dict:
        text_for_embedding = self._build_embedding_text(data)

        try:
            embedding = await model_provider.embed(text_for_embedding)
        except Exception:
            embedding = []

        log = TrafficLog(
            timestamp=datetime.utcnow(),
            method=data.get("method", "GET").upper(),
            endpoint=self._extract_endpoint(data.get("url", "")),
            full_url=data.get("url", ""),
            request_headers=data.get("request_headers", {}),
            request_body=self._safe_str(data.get("request_body")),
            query_params=data.get("query_params", {}),
            status_code=data.get("status_code"),
            response_headers=data.get("response_headers", {}),
            response_body=self._safe_str(data.get("response_body")),
            latency_ms=data.get("latency_ms"),
            source_ip=data.get("source_ip"),
            session_id=data.get("session_id"),
            user_agent=data.get("request_headers", {}).get("user-agent"),
            embedding=embedding,
            risk_level="low",
            is_flagged=False,
        )

        db.add(log)
        await db.commit()
        await db.refresh(log)

        # Step 1 — learn schema
        await schema_service.update_schema(log, db)

        # Step 2 — score anomaly (non-blocking, won't fail ingest)
        analysis = {}
        try:
            analysis = await anomaly_service.analyze(log, db)
        except Exception as e:
            print(f"[Anomaly] Scoring failed for log {log.id}: {e}")

        return {
            "id": str(log.id),
            "method": log.method,
            "endpoint": log.endpoint,
            "full_url": log.full_url,
            "status_code": log.status_code,
            "latency_ms": log.latency_ms,
            "risk_level": analysis.get("risk_level", "low"),
            "anomaly_score": analysis.get("anomaly_score", 0.0),
            "is_flagged": analysis.get("is_flagged", False),
            "explanation": analysis.get("explanation"),
            "explanation_source": analysis.get("explanation_source"),
            "source_ip": log.source_ip,
        }

    async def get_recent(self, db: AsyncSession, limit: int = 50) -> list[TrafficLog]:
        result = await db.execute(
            select(TrafficLog)
            .order_by(TrafficLog.timestamp.desc())
            .limit(limit)
        )
        return result.scalars().all()

    async def get_stats(self, db: AsyncSession) -> dict:
        total = await db.execute(select(func.count(TrafficLog.id)))
        flagged = await db.execute(
            select(func.count(TrafficLog.id))
            .where(TrafficLog.is_flagged == True)
        )
        by_risk = await db.execute(
            select(TrafficLog.risk_level, func.count(TrafficLog.id))
            .group_by(TrafficLog.risk_level)
        )
        return {
            "total_requests": total.scalar(),
            "flagged_count": flagged.scalar(),
            "by_risk_level": {row[0]: row[1] for row in by_risk.fetchall()}
        }

    def _extract_endpoint(self, url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).path or url
        except Exception:
            return url

    def _build_embedding_text(self, data: dict) -> str:
        parts = [
            f"method:{data.get('method', '')}",
            f"endpoint:{self._extract_endpoint(data.get('url', ''))}",
            f"status:{data.get('status_code', '')}",
            f"latency:{data.get('latency_ms', '')}ms",
        ]
        body = data.get("request_body")
        if body:
            text = body if isinstance(body, str) else json.dumps(body)
            parts.append(f"body:{text[:200]}")
        return " | ".join(parts)

    def _safe_str(self, value) -> str | None:
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

traffic_service = TrafficService()
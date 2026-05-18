from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.schema_model import LearnedSchema
from app.models.traffic import TrafficLog
import json

class SchemaService:

    async def update_schema(self, log: TrafficLog, db: AsyncSession):
        """
        Called after every traffic ingest.
        Updates the learned schema for this endpoint+method combo.
        """
        # Find existing schema or create new one
        result = await db.execute(
            select(LearnedSchema).where(
                LearnedSchema.endpoint == log.endpoint,
                LearnedSchema.method == log.method
            )
        )
        schema = result.scalar_one_or_none()

        if not schema:
            schema = LearnedSchema(
                endpoint=log.endpoint,
                method=log.method,
                request_fields={},
                response_fields={},
                status_codes={},
                avg_latency_ms=log.latency_ms or 0,
                sample_count=0,
                is_stable=False
            )
            db.add(schema)

        # Update sample count
        schema.sample_count += 1

        # Update status code distribution
        if log.status_code:
            codes = dict(schema.status_codes or {})
            key = str(log.status_code)
            codes[key] = codes.get(key, 0) + 1
            schema.status_codes = codes

        # Update average latency
        if log.latency_ms is not None:
            prev_avg = schema.avg_latency_ms or 0
            schema.avg_latency_ms = (
                (prev_avg * (schema.sample_count - 1) + log.latency_ms)
                / schema.sample_count
            )

        # Learn request body fields
        if log.request_body:
            schema.request_fields = self._update_fields(
                schema.request_fields or {},
                self._extract_fields(log.request_body),
                schema.sample_count
            )

        # Learn response body fields
        if log.response_body:
            schema.response_fields = self._update_fields(
                schema.response_fields or {},
                self._extract_fields(log.response_body),
                schema.sample_count
            )

        # Mark as stable after 10+ samples
        if schema.sample_count >= 10:
            schema.is_stable = True

        await db.commit()
        return schema

    async def get_schema(
        self, endpoint: str, method: str, db: AsyncSession
    ) -> LearnedSchema | None:
        result = await db.execute(
            select(LearnedSchema).where(
                LearnedSchema.endpoint == endpoint,
                LearnedSchema.method == method
            )
        )
        return result.scalar_one_or_none()

    async def get_all_schemas(self, db: AsyncSession) -> list[LearnedSchema]:
        result = await db.execute(
            select(LearnedSchema).order_by(LearnedSchema.sample_count.desc())
        )
        return result.scalars().all()

    async def validate_request(
        self, log: TrafficLog, db: AsyncSession
    ) -> dict:
        """
        Compare incoming request against the learned schema.
        Returns a list of deviations found.
        """
        schema = await self.get_schema(log.endpoint, log.method, db)

        # No schema yet — not enough data to validate
        if not schema or not schema.is_stable:
            return {"status": "no_schema", "deviations": []}

        deviations = []

        # Check for unexpected status code
        if log.status_code:
            known_codes = set(schema.status_codes.keys())
            if str(log.status_code) not in known_codes:
                deviations.append({
                    "type": "unexpected_status_code",
                    "detail": f"{log.status_code} never seen on this endpoint",
                    "severity": "medium"
                })

        # Check latency spike (3x the average)
        if log.latency_ms and schema.avg_latency_ms:
            if log.latency_ms > schema.avg_latency_ms * 3:
                deviations.append({
                    "type": "latency_spike",
                    "detail": f"{log.latency_ms}ms vs avg {schema.avg_latency_ms:.1f}ms",
                    "severity": "low"
                })

        # Check for unexpected request fields
        if log.request_body:
            incoming_fields = self._extract_fields(log.request_body)
            learned = schema.request_fields or {}
            for field in incoming_fields:
                if field not in learned:
                    deviations.append({
                        "type": "unknown_request_field",
                        "detail": f"Field '{field}' never seen before",
                        "severity": "medium"
                    })

        # Check for missing required fields
        if log.request_body and schema.request_fields:
            incoming_fields = self._extract_fields(log.request_body)
            for field, meta in schema.request_fields.items():
                if meta.get("required") and field not in incoming_fields:
                    deviations.append({
                        "type": "missing_required_field",
                        "detail": f"Required field '{field}' is missing",
                        "severity": "high"
                    })

        return {
            "status": "validated",
            "deviations": deviations,
            "deviation_count": len(deviations)
        }

    def _extract_fields(self, body: str) -> list[str]:
        """Extract top-level keys from a JSON body."""
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                return list(parsed.keys())
        except Exception:
            pass
        return []

    def _update_fields(
        self, existing: dict, new_fields: list[str], sample_count: int
    ) -> dict:
        """
        Update field stats. Tracks how often each field appears.
        Fields seen in >95% of requests → required.
        Fields seen in 20-95%           → optional.
        Fields seen in <20%             → rare (flag if appears).
        """
        updated = dict(existing)

        for field in new_fields:
            if field not in updated:
                updated[field] = {"seen_count": 0, "required": False, "frequency": 0.0}
            updated[field]["seen_count"] += 1

        # Recalculate frequency and required status for all fields
        for field in updated:
            freq = updated[field]["seen_count"] / sample_count
            updated[field]["frequency"] = round(freq, 3)
            updated[field]["required"] = freq >= 0.95

        return updated

schema_service = SchemaService()
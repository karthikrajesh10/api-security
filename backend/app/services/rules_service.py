import yaml
import os
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.schema_model import LearnedSchema
from app.ml.anomaly_detector import anomaly_detector
from app.ml.features import extract_features
from app.models.traffic import TrafficLog
from datetime import datetime
import uuid

RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "docs", "api_rules.yaml"
)

class RulesService:

    def load_rules(self) -> dict:
        """Load and parse the YAML rules file."""
        path = os.path.abspath(RULES_PATH)
        if not os.path.exists(path):
            print(f"[Rules] No rules file found at {path}")
            return {}
        with open(path, "r") as f:
            return yaml.safe_load(f)

    async def apply_rules_to_schema(self, db: AsyncSession) -> dict:
        """
        Read api_rules.yaml and pre-seed LearnedSchema table.
        This gives the ML model a baseline BEFORE real traffic arrives.
        Existing schemas are updated, not replaced.
        """
        rules = self.load_rules()
        if not rules:
            return {"seeded": 0, "message": "No rules file found"}

        endpoints = rules.get("endpoints", [])
        seeded = 0

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"].upper()

            # Check if schema already exists
            result = await db.execute(
                select(LearnedSchema).where(
                    LearnedSchema.endpoint == path,
                    LearnedSchema.method == method
                )
            )
            schema = result.scalar_one_or_none()

            # Build field map from rules
            request_fields = {}
            for field in ep.get("request_fields", []):
                request_fields[field["name"]] = {
                    "seen_count": 50,      # synthetic — treated as always seen
                    "required": field.get("required", False),
                    "frequency": 1.0 if field.get("required") else 0.7,
                    "type": field.get("type", "string"),
                    "source": "rules_doc"  # marks this as doc-derived
                }

            # Build status code map
            status_codes = {
                str(s): 10 for s in ep.get("expected_status", [200])
            }

            if not schema:
                schema = LearnedSchema(
                    endpoint=path,
                    method=method,
                    request_fields=request_fields,
                    response_fields={},
                    status_codes=status_codes,
                    avg_latency_ms=float(ep.get("normal_latency_ms", 200)),
                    sample_count=50,   # synthetic baseline count
                    is_stable=True,    # mark stable immediately
                    version=1,
                )
                db.add(schema)
                print(f"[Rules] Seeded schema: {method} {path}")
            else:
                # Merge rules into existing schema without overwriting real data
                existing_codes = dict(schema.status_codes or {})
                for code, count in status_codes.items():
                    if code not in existing_codes:
                        existing_codes[code] = count
                schema.status_codes = existing_codes

                existing_fields = dict(schema.request_fields or {})
                for field, meta in request_fields.items():
                    if field not in existing_fields:
                        existing_fields[field] = meta
                schema.request_fields = existing_fields

                if not schema.is_stable:
                    schema.is_stable = True
                    schema.sample_count = max(schema.sample_count, 50)

                print(f"[Rules] Updated schema: {method} {path}")

            seeded += 1

        await db.commit()
        return {
            "seeded": seeded,
            "message": f"Applied rules for {seeded} endpoints"
        }

    async def generate_synthetic_training_data(
        self, db: AsyncSession
    ) -> list[list[float]]:
        """
        Generate synthetic feature vectors from rules.
        Used to give Isolation Forest a baseline before real traffic exists.
        """
        rules = self.load_rules()
        if not rules:
            return []

        vectors = []
        endpoints = rules.get("endpoints", [])

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"].upper()

            # Fetch the schema we just seeded
            result = await db.execute(
                select(LearnedSchema).where(
                    LearnedSchema.endpoint == path,
                    LearnedSchema.method == method
                )
            )
            schema = result.scalar_one_or_none()
            if not schema:
                continue

            # Generate 20 synthetic "normal" logs per endpoint
            for _ in range(20):
                import random
                status = random.choice(ep.get("expected_status", [200]))
                latency = ep.get("normal_latency_ms", 200)
                latency += random.uniform(-30, 30)  # small variance

                synthetic_log = TrafficLog(
                    id=uuid.uuid4(),
                    timestamp=datetime.utcnow(),
                    method=method,
                    endpoint=path,
                    full_url=f"http://api.example.com{path}",
                    request_headers={
                        "authorization": "Bearer valid_token",
                        "content-type": "application/json"
                    },
                    request_body=None,
                    query_params={},
                    status_code=status,
                    response_body='{"success": true}',
                    latency_ms=round(latency, 2),
                    source_ip="10.0.0.1",
                    session_id="synthetic",
                    anomaly_score=0.0,
                    risk_level="low",
                    is_flagged=False,
                )
                features = extract_features(synthetic_log, schema)
                vectors.append(features)

        print(f"[Rules] Generated {len(vectors)} synthetic training vectors")
        return vectors

    def get_endpoint_rules(self, endpoint: str, method: str) -> dict:
        """
        Look up rules for a specific endpoint.
        Used by the anomaly service for extra rule checks.
        """
        rules = self.load_rules()
        for ep in rules.get("endpoints", []):
            if ep["path"] == endpoint and ep["method"].upper() == method.upper():
                return ep
        return {}

    def check_global_rules(self, log: TrafficLog) -> list[dict]:
        """
        Apply global rules from the doc to a traffic log.
        Returns list of violations found.
        """
        rules = self.load_rules()
        global_rules = rules.get("global_rules", {})
        violations = []

        headers = log.request_headers or {}
        auth = headers.get("authorization", "")
        has_auth = auth.startswith("Bearer ")

        # Global: flag admin without auth
        if global_rules.get("flag_admin_without_auth") and \
           "admin" in (log.endpoint or "") and not has_auth:
            violations.append({
                "type": "admin_access_without_auth",
                "detail": "Admin endpoint accessed without valid auth token",
                "severity": "high",
                "source": "global_rule"
            })

        # Global: flag DELETE without auth
        if global_rules.get("flag_delete_without_auth") and \
           log.method == "DELETE" and not has_auth:
            violations.append({
                "type": "destructive_method_without_auth",
                "detail": "DELETE request made without authorization",
                "severity": "high",
                "source": "global_rule"
            })

        # Global: max latency
        max_latency = global_rules.get("max_latency_ms", 2000)
        if log.latency_ms and log.latency_ms > max_latency:
            violations.append({
                "type": "latency_exceeded_global_limit",
                "detail": f"Latency {log.latency_ms}ms exceeds global limit {max_latency}ms",
                "severity": "medium",
                "source": "global_rule"
            })

        # Endpoint-specific: auth required
        ep_rules = self.get_endpoint_rules(log.endpoint or "", log.method)
        if ep_rules.get("auth_required", True) and not has_auth:
            violations.append({
                "type": "missing_required_auth",
                "detail": f"{log.method} {log.endpoint} requires authentication",
                "severity": "high",
                "source": "endpoint_rule"
            })

        # Endpoint-specific: unexpected status code
        expected = ep_rules.get("expected_status", [])
        if expected and log.status_code and log.status_code not in expected:
            violations.append({
                "type": "unexpected_status_code",
                "detail": f"Status {log.status_code} not in expected {expected}",
                "severity": "medium",
                "source": "endpoint_rule"
            })

        return violations

rules_service = RulesService()
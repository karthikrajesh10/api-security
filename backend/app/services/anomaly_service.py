

# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import select
# from app.models.traffic import TrafficLog
# from app.models.schema_model import LearnedSchema
# from app.ml.features import extract_features
# from app.ml.anomaly_detector import anomaly_detector
# from app.services.schema_service import schema_service
# from app.ml.factory import model_provider
# from app.services.alert_service import alert_service
# from app.services.rules_service import rules_service

# class AnomalyService:

#     async def analyze(self, log: TrafficLog, db: AsyncSession) -> dict:
#         schema = await schema_service.get_schema(log.endpoint, log.method, db)
#         features = extract_features(log, schema)
#         anomaly_score = anomaly_detector.score(features)
#         risk = anomaly_detector.risk_level(anomaly_score)

#         # Schema deviations
#         deviation_result = await schema_service.validate_request(log, db)
#         deviations = deviation_result.get("deviations", [])

#         # ── Global + endpoint rule violations from docs ──
#         rule_violations = rules_service.check_global_rules(log)
#         deviations.extend(rule_violations)

#         # Boost risk based on deviations
#         if deviations:
#             high_sev = any(d["severity"] == "high" for d in deviations)
#             med_sev = any(d["severity"] == "medium" for d in deviations)
#             if high_sev:
#                 risk = "high"
#                 anomaly_score = max(anomaly_score, 0.75)
#             elif med_sev and risk == "low":
#                 risk = "medium"
#                 anomaly_score = max(anomaly_score, 0.45)

#         llm_explanation = None
#         if risk in ("medium", "high"):
#             llm_explanation = await self._get_llm_explanation(log, deviations, anomaly_score)

#         log.anomaly_score = anomaly_score
#         log.risk_level = risk
#         log.is_flagged = risk == "high"
#         await db.commit()

#         analysis = {
#             "anomaly_score": round(anomaly_score, 4),
#             "risk_level": risk,
#             "is_flagged": log.is_flagged,
#             "deviations": deviations,
#             "llm_explanation": llm_explanation,
#             "model_trained": anomaly_detector.is_trained,
#         }

#         if risk == "high":
#             await alert_service.send_alert(log, analysis)

#         return analysis

#     async def train_model(self, db: AsyncSession) -> dict:
#         result = await db.execute(select(TrafficLog))
#         logs = result.scalars().all()

#         if len(logs) < 20:
#             return {"success": False, "reason": f"Need 20+ logs, have {len(logs)}"}

#         feature_vectors = []
#         for log in logs:
#             schema = await schema_service.get_schema(log.endpoint, log.method, db)
#             features = extract_features(log, schema)
#             feature_vectors.append(features)

#         success = anomaly_detector.train(feature_vectors)
#         return {
#             "success": success,
#             "samples_used": len(feature_vectors),
#             "model_trained": anomaly_detector.is_trained
#         }

#     async def _get_llm_explanation(self, log, deviations, score) -> str:
#         deviation_text = "\n".join(
#             f"- {d['type']}: {d['detail']}" for d in deviations
#         ) or "None detected by rule engine"

#         prompt = f"""You are an API security analyst. Analyze this suspicious API request and explain the risk briefly.

# Request details:
# - Method: {log.method}
# - Endpoint: {log.endpoint}
# - Status Code: {log.status_code}
# - Latency: {log.latency_ms}ms
# - Source IP: {log.source_ip}
# - Has Auth Header: {"Yes" if log.request_headers and log.request_headers.get("authorization") else "No"}
# - Anomaly Score: {score:.2f} (0=normal, 1=highly anomalous)

# Schema deviations detected:
# {deviation_text}

# In 2-3 sentences, explain what looks suspicious and what attack this could indicate.
# Be specific and concise. Do not use bullet points."""

#         try:
#             return (await model_provider.complete(
#                 prompt=prompt,
#                 system="You are a cybersecurity expert specializing in API security. Give brief, actionable analysis."
#             )).strip()
#         except Exception as e:
#             return f"LLM analysis unavailable: {e}"

# anomaly_service = AnomalyService()

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.traffic import TrafficLog
from app.ml.features import extract_features
from app.ml.anomaly_detector import anomaly_detector
from app.services.schema_service import schema_service
from app.services.rules_service import rules_service
from app.ml.factory import model_provider
from app.services.alert_service import alert_service

class AnomalyService:

    async def analyze(self, log: TrafficLog, db: AsyncSession) -> dict:
        schema = await schema_service.get_schema(log.endpoint, log.method, db)
        features = extract_features(log, schema)
        anomaly_score = anomaly_detector.score(features)
        risk = anomaly_detector.risk_level(anomaly_score)

        # Schema deviations
        deviation_result = await schema_service.validate_request(log, db)
        deviations = deviation_result.get("deviations", [])

        # Global + endpoint rule violations from docs
        rule_violations = rules_service.check_global_rules(log)
        deviations.extend(rule_violations)

        # Boost risk based on deviations
        if deviations:
            high_sev = any(d["severity"] == "high" for d in deviations)
            med_sev = any(d["severity"] == "medium" for d in deviations)
            if high_sev:
                risk = "high"
                anomaly_score = max(anomaly_score, 0.75)
            elif med_sev and risk == "low":
                risk = "medium"
                anomaly_score = max(anomaly_score, 0.45)

        # Explanation — tries LLM first, falls back to rule-based instantly
        explanation, explanation_source = await self._explain(log, deviations, anomaly_score, risk)

        log.anomaly_score = anomaly_score
        log.risk_level = risk
        log.is_flagged = risk == "high"
        await db.commit()

        analysis = {
            "anomaly_score": round(anomaly_score, 4),
            "risk_level": risk,
            "is_flagged": log.is_flagged,
            "deviations": deviations,
            "explanation": explanation,
            "explanation_source": explanation_source,  # "llm" or "rules_engine"
            "model_trained": anomaly_detector.is_trained,
        }

        if risk == "high":
            await alert_service.send_alert(log, analysis)

        return analysis

    async def train_model(self, db: AsyncSession) -> dict:
        result = await db.execute(select(TrafficLog))
        logs = result.scalars().all()

        if len(logs) < 20:
            return {"success": False, "reason": f"Need 20+ logs, have {len(logs)}"}

        feature_vectors = []
        for log in logs:
            schema = await schema_service.get_schema(log.endpoint, log.method, db)
            features = extract_features(log, schema)
            feature_vectors.append(features)

        success = anomaly_detector.train(feature_vectors)
        return {
            "success": success,
            "samples_used": len(feature_vectors),
            "model_trained": anomaly_detector.is_trained
        }

    async def _explain(
        self,
        log: TrafficLog,
        deviations: list,
        score: float,
        risk: str
    ) -> tuple[str, str]:
        """
        Returns (explanation_text, source).
        Tries LLM first — if it fails for ANY reason,
        instantly falls back to rule-based explanation.
        Source will be 'llm' or 'rules_engine'.
        """
        if risk not in ("medium", "high"):
            return ("Request is within normal parameters.", "rules_engine")

        # Try LLM first
        try:
            text = await self._llm_explain(log, deviations, score)
            return (text, "llm")
        except Exception as e:
            print(f"[Explanation] LLM unavailable ({e}), using rules engine.")
            text = self._rules_explain(log, deviations, score)
            return (text, "rules_engine")

    async def _llm_explain(self, log: TrafficLog, deviations: list, score: float) -> str:
        deviation_text = "\n".join(
            f"- {d['type']}: {d['detail']}" for d in deviations
        ) or "None detected"

        prompt = f"""You are an API security analyst. Analyze this suspicious API request and explain the risk briefly.

Request details:
- Method: {log.method}
- Endpoint: {log.endpoint}
- Status Code: {log.status_code}
- Latency: {log.latency_ms}ms
- Source IP: {log.source_ip}
- Has Auth Header: {"Yes" if log.request_headers and log.request_headers.get("authorization","").startswith("Bearer") else "No"}
- Anomaly Score: {score:.2f} (0=normal, 1=highly anomalous)

Rule violations and deviations detected:
{deviation_text}

In 2-3 sentences, explain what looks suspicious and what attack this could indicate.
Be specific and concise. Do not use bullet points."""

        return (await model_provider.complete(
            prompt=prompt,
            system="You are a cybersecurity expert specializing in API security. Give brief, actionable analysis."
        )).strip()

    def _rules_explain(
        self,
        log: TrafficLog,
        deviations: list,
        score: float
    ) -> str:
        """
        Instant deterministic explanation built from
        rule violations and request properties.
        No LLM required.
        """
        flags = []

        # Auth checks
        headers = log.request_headers or {}
        auth = headers.get("authorization", "")
        if not auth or not auth.startswith("Bearer "):
            flags.append("missing or invalid authorization header")

        # Admin endpoint
        if "admin" in (log.endpoint or ""):
            flags.append("access to administrative endpoint")

        # Destructive method
        if log.method in ("DELETE", "PUT", "PATCH"):
            flags.append(f"destructive HTTP method ({log.method})")

        # Status code
        if log.status_code and log.status_code >= 500:
            flags.append(f"server error response ({log.status_code})")
        elif log.status_code in (401, 403):
            flags.append(f"authorization failure ({log.status_code})")

        # Latency
        if log.latency_ms and log.latency_ms > 1000:
            flags.append(f"unusually high latency ({log.latency_ms}ms)")

        # Add deviation details
        for d in deviations:
            if d["detail"] not in flags:
                flags.append(d["detail"])

        # Pick attack type
        attack_hint = "anomalous API behavior"
        if "admin" in (log.endpoint or "") and (not auth or not auth.startswith("Bearer ")):
            attack_hint = "possible privilege escalation or unauthorized admin access"
        elif log.method == "DELETE" and not auth:
            attack_hint = "possible unauthorized resource deletion"
        elif log.status_code and log.status_code >= 500:
            attack_hint = "possible injection attack or server-side vulnerability probe"
        elif any("injection" in f.lower() or "sql" in f.lower() for f in flags):
            attack_hint = "possible SQL injection or command injection attempt"
        elif log.status_code in (401, 403):
            attack_hint = "possible credential abuse or broken authentication attempt"

        flag_text = "; ".join(flags) if flags else "statistical deviation from baseline"

        return (
            f"[Rules Engine] This request was flagged due to: {flag_text}. "
            f"Anomaly score of {score:.2f} indicates {attack_hint}. "
            f"Recommend investigating source IP {log.source_ip} and reviewing server logs."
        )

anomaly_service = AnomalyService()
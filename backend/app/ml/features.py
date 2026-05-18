import json
import math
from app.models.traffic import TrafficLog
from app.models.schema_model import LearnedSchema

# Known normal HTTP methods — used for one-hot encoding
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Status code groups
def status_group(code: int | None) -> int:
    if not code: return 0
    return code // 100  # 2, 3, 4, 5

def extract_features(
    log: TrafficLog,
    schema: LearnedSchema | None
) -> list[float]:
    """
    Converts a TrafficLog into a fixed-length numerical feature vector.
    Every feature must be a float. None values become 0.0.

    Feature index reference:
      0     → latency_ms (normalized)
      1     → status code group (2xx=2, 4xx=4, 5xx=5)
      2     → request body length
      3     → response body length
      4     → has authorization header (0 or 1)
      5     → is admin endpoint (0 or 1)
      6     → method one-hot [7 values] (indices 6-12)
      13    → deviation from avg latency (ratio)
      14    → unknown status code for this endpoint (0 or 1)
      15    → unknown request field count
      16    → missing required field count
      17    → request field count
    """

    features = []

    # ── Basic request features ─────────────────────────────────────────────
    features.append(float(log.latency_ms or 0))
    features.append(float(status_group(log.status_code)))
    features.append(float(len(log.request_body or "")))
    features.append(float(len(log.response_body or "")))

    # ── Security signals ───────────────────────────────────────────────────
    headers = log.request_headers or {}
    has_auth = 1.0 if headers.get("authorization", "").startswith("Bearer ") else 0.0
    features.append(has_auth)

    is_admin = 1.0 if "admin" in (log.endpoint or "") else 0.0
    features.append(is_admin)

    # ── Method one-hot encoding ────────────────────────────────────────────
    for m in METHODS:
        features.append(1.0 if log.method == m else 0.0)

    # ── Schema-based deviation features ───────────────────────────────────
    if schema and schema.is_stable:
        # Latency deviation ratio vs learned average
        avg = schema.avg_latency_ms or 1
        latency_ratio = (log.latency_ms or 0) / avg
        features.append(latency_ratio)

        # Is this status code unknown for this endpoint?
        known_codes = set(schema.status_codes.keys())
        unknown_status = 0.0 if str(log.status_code) in known_codes else 1.0
        features.append(unknown_status)

        # Count unknown request fields
        incoming = _extract_fields(log.request_body)
        learned_fields = schema.request_fields or {}
        unknown_fields = sum(1 for f in incoming if f not in learned_fields)
        features.append(float(unknown_fields))

        # Count missing required fields
        missing_required = sum(
            1 for f, meta in learned_fields.items()
            if meta.get("required") and f not in incoming
        )
        features.append(float(missing_required))

    else:
        # No stable schema yet — pad with zeros
        features.extend([0.0, 0.0, 0.0, 0.0])

    # ── Request field count ────────────────────────────────────────────────
    features.append(float(len(_extract_fields(log.request_body))))

    return features


def _extract_fields(body: str | None) -> list[str]:
    if not body:
        return []
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return list(parsed.keys())
    except Exception:
        pass
    return []
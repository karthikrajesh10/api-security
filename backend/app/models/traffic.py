from sqlalchemy import Column, String, Integer, Float, JSON, Text, DateTime, Boolean, Index
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Request fields
    method = Column(String(10), nullable=False)
    endpoint = Column(String(500), nullable=False, index=True)
    full_url = Column(Text, nullable=False)
    request_headers = Column(JSON, default={})
    request_body = Column(Text, nullable=True)
    query_params = Column(JSON, default={})

    # Response fields
    status_code = Column(Integer, nullable=True)
    response_headers = Column(JSON, default={})
    response_body = Column(Text, nullable=True)
    latency_ms = Column(Float, nullable=True)

    # Metadata
    source_ip = Column(String(50), nullable=True)
    session_id = Column(String(200), nullable=True)
    user_agent = Column(Text, nullable=True)

    # ML fields
    anomaly_score = Column(Float, nullable=True)
    risk_level = Column(String(10), nullable=True)  # low / medium / high
    embedding = Column(JSON, nullable=True)          # vector from Ollama

    is_flagged = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_traffic_endpoint_method", "endpoint", "method"),
        Index("ix_traffic_timestamp_risk", "timestamp", "risk_level"),
    )
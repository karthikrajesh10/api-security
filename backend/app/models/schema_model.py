from sqlalchemy import Column, String, Integer, Float, JSON, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base

class LearnedSchema(Base):
    __tablename__ = "learned_schemas"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    endpoint = Column(String(500), nullable=False, index=True)
    method = Column(String(10), nullable=False)

    # Learned structure
    request_fields = Column(JSON, default={})   # field → {type, required, seen_count}
    response_fields = Column(JSON, default={})
    status_codes = Column(JSON, default={})     # {200: 950, 404: 30, ...}
    avg_latency_ms = Column(Float, nullable=True)
    sample_count = Column(Integer, default=0)

    # Versioning
    version = Column(Integer, default=1)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_stable = Column(Boolean, default=False)  # True after 100+ samples
from sqlalchemy import Column, String, Text, JSON, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Classification
    title = Column(String(300), nullable=False)
    severity = Column(String(20), nullable=False)   # critical/high/medium/low/info
    owasp_category = Column(String(100), nullable=True)
    phase = Column(String(10), nullable=False)       # phase1 / phase2

    # Evidence
    endpoint = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False)
    request_snapshot = Column(JSON, nullable=True)
    response_snapshot = Column(JSON, nullable=True)
    payload_used = Column(Text, nullable=True)

    # Detail
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    is_confirmed = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
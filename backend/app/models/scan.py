from sqlalchemy import Column, String, Integer, JSON, DateTime, Boolean, Text
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Target
    target_url = Column(String(500), nullable=False)
    endpoint = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False)
    base_request = Column(JSON, nullable=True)      # stored request snapshot

    # Config
    attack_types = Column(JSON, default=[])         # ["sqli", "xss", "idor"]
    max_requests = Column(Integer, default=100)
    requests_per_second = Column(Integer, default=5)

    # Status
    status = Column(String(20), default="pending")  # pending/running/done/failed
    total_requests_sent = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    approved = Column(Boolean, default=False)       # safety gate
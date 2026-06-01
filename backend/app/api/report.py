from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.services.report_service import report_service
from datetime import datetime

router = APIRouter(prefix="/api/report", tags=["Report"])

@router.get("/download")
async def download_report(db: AsyncSession = Depends(get_db)):
    """
    Generate and download a full PDF security scan report.
    """
    pdf_bytes = await report_service.generate(db)
    filename = f"APISec_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(pdf_bytes)),
        }
    )
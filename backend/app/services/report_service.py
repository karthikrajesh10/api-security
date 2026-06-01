import io
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from app.models.traffic import TrafficLog
from app.models.schema_model import LearnedSchema
from app.services.rules_service import rules_service

# ── Colors ────────────────────────────────────────────────────────────────────
DARK  = colors.HexColor("#0d1117")
BLUE  = colors.HexColor("#388bfd")
CYAN  = colors.HexColor("#39d0d8")
RED   = colors.HexColor("#f85149")
AMBER = colors.HexColor("#d29922")
GREEN = colors.HexColor("#3fb950")
GRAY  = colors.HexColor("#7d8590")
LIGHT = colors.HexColor("#e6edf3")
WHITE = colors.white
MID   = colors.HexColor("#161b22")
BORD  = colors.HexColor("#30363d")

SEV_COLOR = {"high": RED, "medium": AMBER, "low": GREEN, "info": BLUE}

# ── CWE + Engine mapping by violation type ────────────────────────────────────
VIOLATION_META = {
    "admin_access_without_auth":         ("CWE-285", "RBAC"),
    "destructive_method_without_auth":   ("CWE-749", "RULE_ENGINE"),
    "missing_required_auth":             ("CWE-306", "RULE_ENGINE"),
    "unexpected_status_code":            ("CWE-209", "SCHEMA_VALIDATOR"),
    "latency_spike":                     ("CWE-400", "ML_MODEL"),
    "unknown_request_field":             ("CWE-20",  "SCHEMA_VALIDATOR"),
    "missing_required_field":            ("CWE-20",  "SCHEMA_VALIDATOR"),
    "latency_exceeded_global_limit":     ("CWE-400", "RULE_ENGINE"),
}

DEFAULT_CWE    = "CWE-284"
DEFAULT_ENGINE = "ML_ANOMALY"


class ReportService:

    def _infer_violations(self, log: TrafficLog) -> list[dict]:
        """Build violation list from log fields when stored deviations aren't available."""
        violations = []
        headers = log.request_headers or {}
        auth = headers.get("authorization", "")

        if not auth.startswith("Bearer "):
            if "admin" in (log.endpoint or ""):
                violations.append({
                    "type": "admin_access_without_auth",
                    "detail": "Admin endpoint accessed without valid Bearer token",
                    "severity": "high",
                    "source": "global_rule"
                })
            elif log.method in ("DELETE", "PUT", "PATCH"):
                violations.append({
                    "type": "destructive_method_without_auth",
                    "detail": f"{log.method} request made without authorization",
                    "severity": "high",
                    "source": "global_rule"
                })
            else:
                violations.append({
                    "type": "missing_required_auth",
                    "detail": "Request missing required Bearer token",
                    "severity": "high",
                    "source": "endpoint_rule"
                })

        if log.latency_ms and log.latency_ms > 2000:
            violations.append({
                "type": "latency_spike",
                "detail": f"Latency {log.latency_ms}ms exceeds 2000ms threshold",
                "severity": "medium",
                "source": "rule_engine"
            })

        if log.status_code and log.status_code >= 500:
            violations.append({
                "type": "unexpected_status_code",
                "detail": f"Server error {log.status_code} — possible exploitation or injection",
                "severity": "medium",
                "source": "schema_validator"
            })

        return violations

    def _get_cwe_engine(self, violations: list[dict]) -> tuple[str, str]:
        """Get primary CWE and engine from violation list."""
        for v in violations:
            meta = VIOLATION_META.get(v.get("type", ""))
            if meta:
                return meta
        return DEFAULT_CWE, DEFAULT_ENGINE

    def _get_evidence(self, log: TrafficLog, violations: list[dict]) -> str:
        """Build an evidence string matching the sample report format."""
        parts = []
        if violations:
            primary = violations[0]
            parts.append(primary["detail"])
        if log.anomaly_score:
            parts.append(f"Anomaly score: {log.anomaly_score:.3f}")
        if log.status_code and log.status_code >= 400:
            parts.append(f"Response status: {log.status_code}")
        if log.latency_ms and log.latency_ms > 1000:
            parts.append(f"Latency spike: {log.latency_ms}ms")
        return " | ".join(parts) if parts else f"ML anomaly score {log.anomaly_score:.3f} exceeded threshold"

    def _get_remediation(self, log: TrafficLog, violations: list[dict]) -> str:
        types = [v.get("type", "") for v in violations]
        if "admin_access_without_auth" in types or "missing_required_auth" in types:
            return (
                "Enforce Bearer token authentication on all protected endpoints. "
                "Return HTTP 401 for missing tokens and HTTP 403 for insufficient privileges. "
                "Implement RBAC and audit all access to administrative endpoints."
            )
        if "destructive_method_without_auth" in types:
            return (
                "Require valid authentication for all destructive HTTP methods (DELETE, PUT, PATCH). "
                "Validate the caller's role before performing any data modification. "
                "Log all destructive operations with actor identity and timestamp."
            )
        if log.latency_ms and log.latency_ms > 3000:
            return (
                "Investigate server-side processing for time-based SQL injection or resource exhaustion. "
                "Use parameterised queries, set query timeouts, and implement request rate limiting."
            )
        if log.status_code and log.status_code >= 500:
            return (
                "Catch all exceptions and return generic error messages to clients. "
                "Never expose stack traces or internal error details in responses. "
                "Use parameterised queries to prevent injection attacks."
            )
        return (
            "Review this endpoint for access control and input validation issues. "
            "Enforce rate limiting and add security response headers: "
            "X-Frame-Options, Content-Security-Policy, X-XSS-Protection."
        )

    async def generate(self, db: AsyncSession) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            rightMargin=15*mm, leftMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm,
            title="API Security Scan Report",
        )

        # ── Fetch data ────────────────────────────────────────────────────────
        all_logs = (await db.execute(
            select(TrafficLog).order_by(TrafficLog.timestamp.desc())
        )).scalars().all()

        flagged_logs = (await db.execute(
            select(TrafficLog)
            .where(TrafficLog.is_flagged == True)
            .order_by(TrafficLog.anomaly_score.desc())
        )).scalars().all()

        all_schemas = (await db.execute(select(LearnedSchema))).scalars().all()
        rules       = rules_service.load_rules()
        ep_in_rules = rules.get("endpoints", [])

        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for log in all_logs:
            if log.risk_level in counts:
                counts[log.risk_level] += 1

        scan_id   = datetime.utcnow().strftime("%Y%m%d%H%M")
        scan_time = datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")

        story  = []
        W      = 180*mm

        # ── Style helpers ─────────────────────────────────────────────────────
        def sty(name, **kw):
            return ParagraphStyle(name, **kw)

        title_sty = sty("Title", fontSize=22, textColor=LIGHT,
                        fontName="Helvetica-Bold", alignment=TA_LEFT, spaceAfter=4)
        sub_sty   = sty("Sub",   fontSize=11, textColor=GRAY,
                        fontName="Helvetica",   alignment=TA_LEFT, spaceAfter=2)
        h1_sty    = sty("H1",   fontSize=13, textColor=CYAN,
                        fontName="Helvetica-Bold", spaceAfter=4, spaceBefore=10)
        body_sty  = sty("Body", fontSize=8,  textColor=GRAY,
                        fontName="Helvetica",  spaceAfter=2)
        label_sty = sty("Lbl",  fontSize=7,  textColor=GRAY,
                        fontName="Helvetica-Bold", spaceAfter=1)
        foot_sty  = sty("Foot", fontSize=7,  textColor=GRAY,
                        fontName="Helvetica",  alignment=TA_CENTER)

        def hr():
            return HRFlowable(width="100%", thickness=0.5,
                              color=BORD, spaceAfter=6, spaceBefore=6)

        # ══════════════════════════════════════════════════════════════════════
        # COVER
        # ══════════════════════════════════════════════════════════════════════
        story += [
            Spacer(1, 20*mm),
            Paragraph("API Security Scan Report", title_sty),
            Paragraph(
                f"Collection: APISec Platform &nbsp;|&nbsp; "
                f"Scan ID: {scan_id} &nbsp;|&nbsp; Status: COMPLETED", sub_sty),
            Spacer(1, 3*mm), hr(), Spacer(1, 2*mm),
            Paragraph(
                f"Generated: {scan_time} &nbsp;|&nbsp; "
                f"Endpoints Analysed: {len(all_schemas)} &nbsp;|&nbsp; "
                f"Total Requests: {len(all_logs)} &nbsp;|&nbsp; "
                f"Flagged: {len(flagged_logs)}", body_sty),
        ]

        # ══════════════════════════════════════════════════════════════════════
        # SUMMARY
        # ══════════════════════════════════════════════════════════════════════
        story += [Spacer(1, 6*mm), Paragraph("Summary", h1_sty), hr()]

        sum_data = [
            ["Severity", "Count"],
            ["Critical", "0"],
            ["High",     str(counts["high"])],
            ["Medium",   str(counts["medium"])],
            ["Low",      str(counts["low"])],
            ["Info",     "0"],
        ]
        sum_tbl = Table(sum_data, colWidths=[60*mm, 40*mm])
        sum_tbl.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0),  MID),
            ("TEXTCOLOR",      (0,0), (-1,0),  LIGHT),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("FONTNAME",       (0,1), (-1,-1), "Helvetica"),
            ("GRID",           (0,0), (-1,-1), 0.3, BORD),
            ("TOPPADDING",     (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
            ("LEFTPADDING",    (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK, MID]),
            ("TEXTCOLOR",      (0,2), (0,2),   RED),
            ("TEXTCOLOR",      (0,3), (0,3),   AMBER),
            ("TEXTCOLOR",      (0,4), (0,4),   GREEN),
            ("TEXTCOLOR",      (1,2), (1,2),   RED),
            ("TEXTCOLOR",      (1,3), (1,3),   AMBER),
            ("TEXTCOLOR",      (1,4), (1,4),   GREEN),
            ("FONTNAME",       (1,2), (1,4),   "Helvetica-Bold"),
        ]))
        story.append(sum_tbl)

        # ══════════════════════════════════════════════════════════════════════
        # RULE EXECUTION DASHBOARD
        # ══════════════════════════════════════════════════════════════════════
        story += [Spacer(1, 6*mm), Paragraph("Rule Execution Dashboard", h1_sty), hr()]

        rule_defs = [
            ("R001", "SQL Injection",               "CWE-89"),
            ("R002", "Authentication Bypass",       "CWE-287"),
            ("R003", "IDOR / Object Reference",     "CWE-639"),
            ("R004", "Reflected Injection / XSS",  "CWE-79"),
            ("R005", "Missing Authentication",      "CWE-306"),
            ("R006", "Rate Limit Violation",        "CWE-307"),
            ("R007", "Broken Access Control",       "CWE-284"),
            ("R008", "Admin Endpoint Abuse",        "CWE-285"),
            ("R009", "Latency Anomaly",             "CWE-400"),
            ("R010", "Unknown Request Field",       "CWE-20"),
            ("R011", "Missing Required Field",      "CWE-20"),
            ("R012", "Unexpected Status Code",      "CWE-209"),
            ("R013", "Dangerous HTTP Method",       "CWE-749"),
            ("R014", "Schema Drift Detection",      "CWE-693"),
            ("R015", "Missing Security Headers",    "CWE-693"),
        ]

        flagged_types = set()
        for log in flagged_logs:
            if not (log.request_headers or {}).get("authorization","").startswith("Bearer "):
                flagged_types.add("auth")
            if "admin" in (log.endpoint or ""):
                flagged_types.add("admin")
            if log.latency_ms and log.latency_ms > 2000:
                flagged_types.add("latency")
            if log.status_code and log.status_code >= 500:
                flagged_types.add("status")

        fail_map = {
            "R001": "status" in flagged_types,
            "R005": "auth"   in flagged_types,
            "R006": len(flagged_logs) > 5,
            "R007": "auth"   in flagged_types,
            "R008": "admin"  in flagged_types,
            "R009": "latency" in flagged_types,
        }

        ep_count_str = f"All Endpoints ({len(all_schemas)})"
        rules_rows = [["Rule ID", "Rule Name", "Category", "Executed", "Result", "Endpoints"]]
        for rid, rname, cat in rule_defs:
            result = "FAIL" if fail_map.get(rid, False) else "PASS"
            rules_rows.append([rid, rname, cat, "Yes", result, ep_count_str])

        r_style = [
            ("BACKGROUND",     (0,0), (-1,0),  MID),
            ("TEXTCOLOR",      (0,0), (-1,0),  LIGHT),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 7),
            ("FONTNAME",       (0,1), (-1,-1), "Helvetica"),
            ("TEXTCOLOR",      (0,1), (-1,-1), GRAY),
            ("GRID",           (0,0), (-1,-1), 0.3, BORD),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK, MID]),
            ("TOPPADDING",     (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
            ("LEFTPADDING",    (0,0), (-1,-1), 5),
        ]
        for i, row in enumerate(rules_rows[1:], start=1):
            c = RED if row[4] == "FAIL" else GREEN
            r_style += [("TEXTCOLOR",(4,i),(4,i),c), ("FONTNAME",(4,i),(4,i),"Helvetica-Bold")]

        r_tbl = Table(rules_rows,
                      colWidths=[14*mm, 55*mm, 22*mm, 16*mm, 16*mm, 57*mm],
                      repeatRows=1)
        r_tbl.setStyle(TableStyle(r_style))
        story.append(r_tbl)

        # ══════════════════════════════════════════════════════════════════════
        # ENDPOINT HEALTH SUMMARY
        # ══════════════════════════════════════════════════════════════════════
        story += [Spacer(1, 6*mm), Paragraph("Endpoint Health Summary", h1_sty), hr()]

        schema_map   = {(s.endpoint, s.method): s for s in all_schemas}
        flagged_ep   = {}
        for log in flagged_logs:
            k = (log.endpoint, log.method)
            flagged_ep[k] = flagged_ep.get(k, 0) + 1
        total_ep = {}
        for log in all_logs:
            k = (log.endpoint, log.method)
            total_ep[k] = total_ep.get(k, 0) + 1

        all_eps = sorted(set(list(schema_map.keys()) + list(total_ep.keys())))

        h_rows = [["Method", "Path", "Total", "Flagged", "Avg Latency", "Errors", "Status"]]
        h_style = [
            ("BACKGROUND",     (0,0), (-1,0),  MID),
            ("TEXTCOLOR",      (0,0), (-1,0),  LIGHT),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 7),
            ("FONTNAME",       (0,1), (-1,-1), "Helvetica"),
            ("TEXTCOLOR",      (0,1), (-1,-1), GRAY),
            ("GRID",           (0,0), (-1,-1), 0.3, BORD),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK, MID]),
            ("TOPPADDING",     (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
            ("LEFTPADDING",    (0,0), (-1,-1), 5),
        ]

        for i, (ep, method) in enumerate(all_eps, start=1):
            schema = schema_map.get((ep, method))
            total  = total_ep.get((ep, method), 0)
            flag_c = flagged_ep.get((ep, method), 0)
            avg_l  = f"{schema.avg_latency_ms:.0f}ms" if schema else "—"
            # Count error responses for this endpoint
            errors = sum(
                1 for log in all_logs
                if log.endpoint == ep and log.method == method
                and (log.status_code or 0) >= 400
            )
            status = "VULNERABLE" if flag_c > 0 else "HEALTHY"
            sc     = RED if status == "VULNERABLE" else GREEN

            h_rows.append([method, ep, str(total), str(flag_c), avg_l, str(errors), status])
            h_style += [
                ("TEXTCOLOR", (6,i), (6,i), sc),
                ("FONTNAME",  (6,i), (6,i), "Helvetica-Bold"),
            ]
            mc = {"DELETE": RED, "POST": GREEN, "PUT": AMBER}.get(method)
            if mc:
                h_style.append(("TEXTCOLOR", (0,i), (0,i), mc))

        h_tbl = Table(h_rows,
                      colWidths=[16*mm, 65*mm, 14*mm, 16*mm, 22*mm, 16*mm, 25*mm],
                      repeatRows=1)
        h_tbl.setStyle(TableStyle(h_style))
        story.append(h_tbl)

        # ══════════════════════════════════════════════════════════════════════
        # FINDINGS
        # ══════════════════════════════════════════════════════════════════════
        if flagged_logs:
            story.append(PageBreak())
            story += [Paragraph("Findings", h1_sty), hr()]

            for log in flagged_logs:
                risk      = log.risk_level or "medium"
                sev_color = SEV_COLOR.get(risk, AMBER)
                violations = self._infer_violations(log)
                cwe, engine = self._get_cwe_engine(violations)
                evidence    = self._get_evidence(log, violations)

                # ── Finding header ────────────────────────────────────────────
                hdr = Table([[
                    Paragraph(f"[{risk.upper()}]", ParagraphStyle(
                        f"SL{risk}", fontSize=9, textColor=sev_color,
                        fontName="Helvetica-Bold")),
                    Paragraph(f"{log.method} {log.endpoint}", ParagraphStyle(
                        "EPL", fontSize=9, textColor=LIGHT,
                        fontName="Helvetica-Bold")),
                ]], colWidths=[20*mm, 160*mm])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",   (0,0), (-1,-1), MID),
                    ("TOPPADDING",   (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING",(0,0), (-1,-1), 5),
                    ("LEFTPADDING",  (0,0), (-1,-1), 6),
                    ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
                    ("LINEBELOW",    (0,0), (-1,-1), 0.5, sev_color),
                ]))
                story.append(hdr)
                story.append(Spacer(1, 1*mm))

                # ── Meta table: Endpoint / Engine / CWE / Evidence ────────────
                meta_rows = [
                    ["Endpoint",      f"{log.method} {log.endpoint}"],
                    ["Engine",        engine],
                    ["CWE",           cwe],
                    ["Evidence",      evidence],
                    ["Source IP",     log.source_ip or "—"],
                    ["Status Code",   str(log.status_code or "—")],
                    ["Latency",       f"{log.latency_ms}ms" if log.latency_ms else "—"],
                    ["Anomaly Score", f"{log.anomaly_score:.4f}" if log.anomaly_score else "—"],
                    ["Risk Level",    risk.upper()],
                    ["Timestamp",     log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")],
                ]
                m_tbl = Table(meta_rows, colWidths=[30*mm, 150*mm])
                m_tbl.setStyle(TableStyle([
                    ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
                    ("FONTSIZE",      (0,0), (-1,-1), 7.5),
                    ("TEXTCOLOR",     (0,0), (0,-1), GRAY),
                    ("TEXTCOLOR",     (1,0), (1,-1), LIGHT),
                    ("GRID",          (0,0), (-1,-1), 0.3, BORD),
                    ("ROWBACKGROUNDS",(0,0), (-1,-1), [DARK, MID]),
                    ("TOPPADDING",    (0,0), (-1,-1), 3),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                    ("LEFTPADDING",   (0,0), (-1,-1), 6),
                    # Highlight CWE in cyan
                    ("TEXTCOLOR",     (1,2), (1,2),  CYAN),
                    ("FONTNAME",      (1,2), (1,2),  "Helvetica-Bold"),
                    # Highlight risk level
                    ("TEXTCOLOR",     (1,8), (1,8),  sev_color),
                    ("FONTNAME",      (1,8), (1,8),  "Helvetica-Bold"),
                ]))
                story.append(m_tbl)
                story.append(Spacer(1, 1.5*mm))

                # ── Violations table ──────────────────────────────────────────
                if violations:
                    story.append(Paragraph("Rule Violations", label_sty))
                    v_rows = [["Severity", "Type", "Detail", "Source"]]
                    v_style = [
                        ("BACKGROUND",     (0,0), (-1,0),  MID),
                        ("TEXTCOLOR",      (0,0), (-1,0),  LIGHT),
                        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
                        ("FONTSIZE",       (0,0), (-1,-1), 7),
                        ("FONTNAME",       (0,1), (-1,-1), "Helvetica"),
                        ("TEXTCOLOR",      (0,1), (-1,-1), GRAY),
                        ("GRID",           (0,0), (-1,-1), 0.3, BORD),
                        ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK, MID]),
                        ("TOPPADDING",     (0,0), (-1,-1), 3),
                        ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
                        ("LEFTPADDING",    (0,0), (-1,-1), 5),
                    ]
                    for j, v in enumerate(violations, start=1):
                        sev = v.get("severity", "medium")
                        vc  = SEV_COLOR.get(sev, AMBER)
                        v_rows.append([
                            sev.upper(),
                            v.get("type", "—"),
                            v.get("detail", "—"),
                            v.get("source", "—"),
                        ])
                        v_style += [
                            ("TEXTCOLOR", (0,j), (0,j), vc),
                            ("FONTNAME",  (0,j), (0,j), "Helvetica-Bold"),
                        ]
                    v_tbl = Table(v_rows, colWidths=[18*mm, 44*mm, 88*mm, 30*mm])
                    v_tbl.setStyle(TableStyle(v_style))
                    story.append(v_tbl)
                    story.append(Spacer(1, 1.5*mm))

                # ── Request sent ──────────────────────────────────────────────
                story.append(Paragraph("Request Sent", label_sty))
                req_lines = [f"{log.method} {log.full_url or log.endpoint}"]
                for k, v in (log.request_headers or {}).items():
                    if k.lower() in ("authorization", "cookie", "x-api-key"):
                        v = str(v)[:20] + "..." if len(str(v)) > 20 else str(v)
                    req_lines.append(f"{k}: {v}")
                if log.request_body:
                    body = log.request_body
                    if len(body) > 300:
                        body = body[:300] + "... [truncated]"
                    req_lines += ["", body]

                req_box = Table([[Paragraph(
                    "<br/>".join(req_lines),
                    ParagraphStyle("RC", fontSize=7,
                                   textColor=colors.HexColor("#a5d6ff"),
                                   fontName="Courier", leading=10)
                )]], colWidths=[W])
                req_box.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#0d1b2a")),
                    ("TOPPADDING",    (0,0), (-1,-1), 6),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                    ("LEFTPADDING",   (0,0), (-1,-1), 8),
                    ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                    ("LINEABOVE",     (0,0), (-1,0),  0.5, colors.HexColor("#1f4068")),
                    ("LINEBELOW",     (0,0), (-1,-1), 0.5, colors.HexColor("#1f4068")),
                ]))
                story.append(req_box)
                story.append(Spacer(1, 1.5*mm))

                # ── Response received ─────────────────────────────────────────
                sc_hex = (
                    "#f85149" if (log.status_code or 0) >= 500
                    else "#d29922" if (log.status_code or 0) >= 400
                    else "#3fb950"
                )
                story.append(Paragraph(
                    f"Response — HTTP {log.status_code or '—'}", label_sty))

                resp_lines = [
                    f"<font color='{sc_hex}'>HTTP {log.status_code or '—'}"
                    f" | Latency: {log.latency_ms or '—'}ms</font>"
                ]
                for k, v in (log.response_headers or {}).items():
                    resp_lines.append(f"{k}: {v}")

                if log.response_body:
                    body = log.response_body
                    if len(body) > 500:
                        body = body[:500] + "... [truncated]"
                    resp_lines += ["", body]
                else:
                    resp_lines += ["", "(no response body — include response_body in ingest payload)"]

                resp_box = Table([[Paragraph(
                    "<br/>".join(resp_lines),
                    ParagraphStyle("RESPC", fontSize=7,
                                   textColor=colors.HexColor("#adbac7"),
                                   fontName="Courier", leading=10)
                )]], colWidths=[W])
                resp_box.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#161b22")),
                    ("TOPPADDING",    (0,0), (-1,-1), 6),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                    ("LEFTPADDING",   (0,0), (-1,-1), 8),
                    ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                    ("LINEABOVE",     (0,0), (-1,0),  0.5, BORD),
                    ("LINEBELOW",     (0,0), (-1,-1), 0.5, BORD),
                ]))
                story.append(resp_box)
                story.append(Spacer(1, 1.5*mm))

                # ── Analysis ──────────────────────────────────────────────────
                story.append(Paragraph("Analysis", label_sty))
                analysis = (
                    f"Request to {log.method} {log.endpoint} from {log.source_ip} "
                    f"was scored {log.anomaly_score:.3f} by the ML anomaly engine. "
                )
                if violations:
                    analysis += (
                        f"The rules engine identified {len(violations)} violation(s): "
                        + "; ".join(v.get("detail","") for v in violations) + ". "
                    )
                if log.latency_ms and log.latency_ms > 2000:
                    analysis += (
                        f"Response latency of {log.latency_ms}ms is abnormally high "
                        f"and may indicate server-side injection or resource exhaustion. "
                    )
                if log.status_code and log.status_code >= 500:
                    analysis += (
                        f"A {log.status_code} server error in response to an "
                        f"unauthenticated request may indicate successful exploitation. "
                    )
                story.append(Paragraph(analysis, body_sty))
                story.append(Spacer(1, 1.5*mm))

                # ── Remediation ───────────────────────────────────────────────
                story.append(Paragraph("Remediation", label_sty))
                story.append(Paragraph(
                    self._get_remediation(log, violations), body_sty))
                story.append(Spacer(1, 5*mm))
                story.append(hr())

        # ══════════════════════════════════════════════════════════════════════
        # SCHEMA INVENTORY
        # ══════════════════════════════════════════════════════════════════════
        story += [
            Spacer(1, 4*mm),
            Paragraph("Learned Schema Inventory", h1_sty),
            hr(),
            Paragraph(
                "Endpoint schemas learned automatically from observed traffic. "
                "Stable schemas (10+ samples) are used for ML deviation detection.",
                body_sty),
            Spacer(1, 2*mm),
        ]

        sc_rows = [["Method", "Endpoint", "Samples",
                    "Avg Latency", "Known Status Codes", "Fields", "Stable"]]
        sc_style = [
            ("BACKGROUND",     (0,0), (-1,0),  MID),
            ("TEXTCOLOR",      (0,0), (-1,0),  LIGHT),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 7),
            ("FONTNAME",       (0,1), (-1,-1), "Helvetica"),
            ("TEXTCOLOR",      (0,1), (-1,-1), GRAY),
            ("GRID",           (0,0), (-1,-1), 0.3, BORD),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK, MID]),
            ("TOPPADDING",     (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
            ("LEFTPADDING",    (0,0), (-1,-1), 5),
        ]

        for i, s in enumerate(
            sorted(all_schemas, key=lambda x: x.sample_count, reverse=True), start=1
        ):
            codes  = ", ".join(sorted(s.status_codes.keys())) if s.status_codes else "—"
            fields = ", ".join(sorted(s.request_fields.keys())) if s.request_fields else "—"
            stable = "Yes" if s.is_stable else "No"
            sc_rows.append([
                s.method, s.endpoint, str(s.sample_count),
                f"{s.avg_latency_ms:.0f}ms" if s.avg_latency_ms else "—",
                codes, fields, stable,
            ])
            sc_style.append(
                ("TEXTCOLOR", (6,i), (6,i), GREEN if stable == "Yes" else AMBER))

        if len(sc_rows) > 1:
            sc_tbl = Table(sc_rows,
                           colWidths=[16*mm, 58*mm, 16*mm, 20*mm, 36*mm, 22*mm, 12*mm],
                           repeatRows=1)
            sc_tbl.setStyle(TableStyle(sc_style))
            story.append(sc_tbl)

        # ══════════════════════════════════════════════════════════════════════
        # FOOTER
        # ══════════════════════════════════════════════════════════════════════
        story += [
            Spacer(1, 8*mm), hr(),
            Paragraph(
                f"Report generated by APISec Platform on {scan_time}. "
                "Phase 1 passive monitoring results. "
                "Phase 2 active penetration testing is planned for the next release.",
                foot_sty),
        ]

        doc.build(story)
        buffer.seek(0)
        return buffer.read()


report_service = ReportService()
import httpx
import json
from datetime import datetime
from app.core.config import settings
from app.models.traffic import TrafficLog

class AlertService:
    """
    Sends alerts when high-risk requests are detected.
    Supports: console (always), Slack webhook (optional).
    Easily extensible to email, PagerDuty, etc.
    """

    async def send_alert(self, log: TrafficLog, analysis: dict):
        """
        Called automatically when a request scores high risk.
        """
        alert = self._build_alert(log, analysis)

        # Always log to console
        self._console_alert(alert)

        # Slack — only if webhook URL is configured
        if settings.SLACK_WEBHOOK_URL:
            await self._slack_alert(alert)

    def _build_alert(self, log: TrafficLog, analysis: dict) -> dict:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "risk_level": analysis.get("risk_level", "unknown"),
            "anomaly_score": round(analysis.get("anomaly_score", 0), 4),
            "method": log.method,
            "endpoint": log.endpoint,
            "status_code": log.status_code,
            "source_ip": log.source_ip,
            "latency_ms": log.latency_ms,
            "deviations": analysis.get("deviations", []),
            "llm_explanation": analysis.get("llm_explanation", ""),
            "log_id": str(log.id),
        }

    def _console_alert(self, alert: dict):
        print("\n" + "="*60)
        print(f"🚨 [{alert['risk_level'].upper()}] ANOMALY DETECTED")
        print(f"   {alert['method']} {alert['endpoint']}")
        print(f"   Score: {alert['anomaly_score']} | IP: {alert['source_ip']}")
        print(f"   Status: {alert['status_code']} | Latency: {alert['latency_ms']}ms")
        if alert["deviations"]:
            print(f"   Deviations:")
            for d in alert["deviations"]:
                print(f"     - {d['type']}: {d['detail']}")
        if alert["llm_explanation"]:
            print(f"   LLM: {alert['llm_explanation'][:200]}")
        print("="*60 + "\n")

    async def _slack_alert(self, alert: dict):
        """
        Sends a formatted Slack message via incoming webhook.
        To enable: add SLACK_WEBHOOK_URL to .env
        """
        risk_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
            alert["risk_level"], "⚪"
        )

        deviation_text = "\n".join(
            f"• {d['type']}: {d['detail']}"
            for d in alert["deviations"]
        ) or "None"

        message = {
            "text": f"{risk_emoji} *API Security Alert — {alert['risk_level'].upper()} Risk*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{risk_emoji} {alert['risk_level'].upper()} Risk Detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Endpoint:*\n`{alert['method']} {alert['endpoint']}`"},
                        {"type": "mrkdwn", "text": f"*Score:*\n{alert['anomaly_score']}"},
                        {"type": "mrkdwn", "text": f"*Source IP:*\n{alert['source_ip']}"},
                        {"type": "mrkdwn", "text": f"*Status Code:*\n{alert['status_code']}"},
                        {"type": "mrkdwn", "text": f"*Latency:*\n{alert['latency_ms']}ms"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{alert['timestamp']}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Deviations:*\n{deviation_text}"}
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*LLM Analysis:*\n{alert['llm_explanation'] or 'N/A'}"
                    }
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    settings.SLACK_WEBHOOK_URL,
                    json=message,
                    timeout=5
                )
        except Exception as e:
            print(f"[Alert] Slack delivery failed: {e}")

alert_service = AlertService()
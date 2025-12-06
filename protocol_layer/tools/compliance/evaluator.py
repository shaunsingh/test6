"""Compliance Evaluator, AI-powered compliance analysis

Uses LLM to evaluate sensor data against ISO 27001 rules
and provide intelligent compliance assessments
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import load_dotenv

from .iso_rules import ISO27001RuleBook

load_dotenv()

LLM_URL = os.getenv("OPENAI_API_BASE", "http://localhost:8000/v1")
LLM_KEY = os.getenv("OPENAI_API_KEY", "EMPTY")
LLM_MODEL = os.getenv("LLM_MODEL", "ibm-granite/granite-4.0-h-micro")

EVALUATION_PROMPT = """You are an ISO 27001 compliance auditor analyzing system security data.

## ISO 27001 Control Reference
{iso_rules}

## Scan Data
```json
{scan_data}
```

## Task
Analyze the scan results against ISO 27001 requirements and provide:
1. Overall compliance assessment (Compliant/Non-Compliant/Partially Compliant)
2. Risk level (Critical/High/Medium/Low)
3. Key findings summary
4. Priority remediation actions
5. Compliance gaps by ISO clause

Respond in JSON format:
{{
    "assessment": "Compliant|Non-Compliant|Partially Compliant",
    "risk_level": "Critical|High|Medium|Low",
    "compliance_score": <0-100>,
    "summary": "<brief summary>",
    "key_findings": ["<finding1>", "<finding2>"],
    "remediation_priorities": [
        {{"priority": 1, "control": "<ISO clause>", "action": "<action>", "effort": "Low|Medium|High"}}
    ],
    "gaps_by_clause": {{
        "<clause>": {{"status": "pass|fail|partial", "notes": "<notes>"}}
    }}
}}
"""

EVENT_ANALYSIS_PROMPT = """You are a security analyst reviewing audit log events.

## Security Events (Last {minutes} minutes)
```json
{events}
```

## ISO 27001 Context
These events relate to the following controls:
{relevant_controls}

## Task
Analyze these security events and determine:
1. Are there any indicators of compromise (IoC)?
2. Are there policy violations?
3. What is the overall threat level?
4. What immediate actions should be taken?

Respond in JSON format:
{{
    "threat_level": "Critical|High|Medium|Low|None",
    "indicators_of_compromise": ["<ioc1>", "<ioc2>"],
    "policy_violations": ["<violation1>", "<violation2>"],
    "anomalies_detected": ["<anomaly1>"],
    "recommended_actions": ["<action1>", "<action2>"],
    "summary": "<brief summary>"
}}
"""


@dataclass(frozen=True, slots=True)
class ComplianceAssessment:
    """Result of AI compliance evaluation."""

    assessment: str
    risk_level: str
    compliance_score: float
    summary: str
    key_findings: tuple[str, ...]
    remediation_priorities: tuple[dict[str, Any], ...]
    gaps_by_clause: dict[str, dict[str, Any]]
    generated_at: str
    raw_response: dict[str, Any]


@dataclass(frozen=True, slots=True)
class EventAnalysis:
    """Result of security event analysis."""

    threat_level: str
    indicators_of_compromise: tuple[str, ...]
    policy_violations: tuple[str, ...]
    anomalies_detected: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    summary: str
    generated_at: str


class ComplianceEvaluator:
    """AI-powered compliance evaluation engine."""

    __slots__ = (
        "llm_url",
        "llm_key",
        "llm_model",
        "rule_book",
        "_http",
        "_iso_context",
    )

    def __init__(
        self,
        llm_url: str = LLM_URL,
        llm_key: str = LLM_KEY,
        llm_model: str = LLM_MODEL,
    ) -> None:
        self.llm_url = llm_url.rstrip("/")
        self.llm_key = llm_key
        self.llm_model = llm_model
        self.rule_book = ISO27001RuleBook()
        self._iso_context = self.rule_book.to_context_string()
        self._http = httpx.AsyncClient(
            timeout=120.0,
            http2=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        """Call LLM API and parse JSON response."""
        try:
            resp = await self._http.post(
                f"{self.llm_url}/chat/completions",
                json={
                    "model": self.llm_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                },
                headers={"Authorization": f"Bearer {self.llm_key}"},
            )
            resp.raise_for_status()
            return json.loads(resp.json()["choices"][0]["message"]["content"])
        except (json.JSONDecodeError, KeyError, IndexError):
            return {"error": "Failed to parse LLM response as JSON"}
        except Exception as e:
            return {"error": str(e)}

    async def evaluate_scan(self, scan_data: dict[str, Any]) -> ComplianceAssessment:
        """Evaluate compliance scan results using AI."""
        # Truncate scan data if too large
        scan_json = json.dumps(scan_data, indent=2)
        if len(scan_json) > 10000:
            scan_data = {
                "summary": scan_data.get("summary", {}),
                "controls": [
                    {
                        "control_id": c["control_id"],
                        "status": c["status"],
                        "severity": c["severity"],
                        "details": c["details"][:200],
                    }
                    for c in scan_data.get("controls", [])
                ],
            }
            scan_json = json.dumps(scan_data, indent=2)

        result = await self._call_llm(
            EVALUATION_PROMPT.format(iso_rules=self._iso_context, scan_data=scan_json)
        )

        return ComplianceAssessment(
            assessment=result.get("assessment", "Unknown"),
            risk_level=result.get("risk_level", "Unknown"),
            compliance_score=result.get("compliance_score", 0),
            summary=result.get("summary", ""),
            key_findings=tuple(result.get("key_findings", [])),
            remediation_priorities=tuple(result.get("remediation_priorities", [])),
            gaps_by_clause=result.get("gaps_by_clause", {}),
            generated_at=datetime.now(timezone.utc).isoformat(),
            raw_response=result,
        )

    async def analyze_events(
        self, events: list[dict[str, Any]], minutes: int = 5
    ) -> EventAnalysis:
        """Analyze security events using AI."""
        if not events:
            return EventAnalysis(
                threat_level="None",
                indicators_of_compromise=(),
                policy_violations=(),
                anomalies_detected=(),
                recommended_actions=(),
                summary="No events to analyze",
                generated_at=datetime.now(timezone.utc).isoformat(),
            )

        # Get relevant controls from events
        relevant_clauses = {
            iso_control.split("-")[0]
            for e in events
            if (iso_control := e.get("iso_control"))
        }

        relevant_controls = "\n".join(
            f"- {clause}: {ctrl.name if (ctrl := self.rule_book.get_control(clause)) else 'N/A'}"
            for clause in relevant_clauses
        )

        result = await self._call_llm(
            EVENT_ANALYSIS_PROMPT.format(
                minutes=minutes,
                events=json.dumps(events[:50], indent=2),
                relevant_controls=relevant_controls
                or "No specific controls identified",
            )
        )

        return EventAnalysis(
            threat_level=result.get("threat_level", "Unknown"),
            indicators_of_compromise=tuple(result.get("indicators_of_compromise", [])),
            policy_violations=tuple(result.get("policy_violations", [])),
            anomalies_detected=tuple(result.get("anomalies_detected", [])),
            recommended_actions=tuple(result.get("recommended_actions", [])),
            summary=result.get("summary", ""),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def evaluate_scan_rules_only(self, scan_data: dict[str, Any]) -> dict[str, Any]:
        """Evaluate scan using rule book only (no LLM)."""
        control_status = self.rule_book.evaluate_scan_results(scan_data)
        summary = self.rule_book.get_compliance_summary(control_status)

        score = summary["compliance_percentage"]
        if score >= 90:
            assessment, risk_level = "Compliant", "Low"
        elif score >= 70:
            assessment, risk_level = "Partially Compliant", "Medium"
        elif score >= 50:
            assessment, risk_level = "Non-Compliant", "High"
        else:
            assessment, risk_level = "Non-Compliant", "Critical"

        return {
            "assessment": assessment,
            "risk_level": risk_level,
            "compliance_score": score,
            "summary": f"{summary['passed']}/{summary['total_controls']} controls passed",
            "by_category": summary["by_category"],
            "non_compliant_controls": summary["non_compliant_controls"],
            "control_details": control_status,
        }

    async def close(self) -> None:
        """Close HTTP client."""
        await self._http.aclose()

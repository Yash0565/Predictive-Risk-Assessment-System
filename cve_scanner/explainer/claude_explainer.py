from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import anthropic
import httpx
from pydantic import BaseModel, ValidationError

from cve_scanner.config import get_settings
from cve_scanner.models import ScanResult

logger = logging.getLogger(__name__)


class ExplanationSchema(BaseModel):
    summary: str
    critical_path: str
    recommendation: str
    risk_rationale: str


SYSTEM_PROMPT = (
    "You are a security engineer writing a concise developer-facing explanation of upgrade risk. "
    "Be direct, technical, and actionable. Output ONLY a JSON object with these fields: "
    "{\"summary\": \"2-3 sentence executive summary\", "
    "\"critical_path\": \"which code file/function is the riskiest\", "
    "\"recommendation\": \"exact command or steps to remediate\", "
    "\"risk_rationale\": \"why this score was assigned\"}"
)


def template_fallback(scan_result: ScanResult) -> str:
    findings = scan_result.cve_findings
    if not findings:
        return "No vulnerabilities detected."
    top = max(findings, key=lambda item: item.cvss_score)
    reachable = any(item.reachable for item in scan_result.reachability if item.cve_id == top.cve_id)
    reachability_note = (
        "Vulnerable code is reachable in production."
        if reachable
        else "No direct reachability detected."
    )
    return (
        f"Found {len(findings)} vulnerabilities. Highest severity: {top.cve_id} "
        f"({top.cvss_score}/10 CVSS). {reachability_note} Upgrade {top.package_name} "
        f"to {top.fixed_version or 'a patched version'} to remediate."
    )


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip()


def _collect_allowed_paths(scan_result: ScanResult) -> tuple[set[str], set[str], set[str]]:
    allowed_paths: set[str] = set()
    allowed_basenames: set[str] = set()

    for finding in scan_result.cve_findings:
        if finding.defined_in:
            normalized = _normalize_path(finding.defined_in)
            allowed_paths.add(normalized)
            allowed_basenames.add(Path(normalized).name)

    for entry in scan_result.reachability:
        for chain in entry.call_chain:
            if ":" in chain:
                path_part = chain.rsplit(":", 1)[0]
            else:
                path_part = chain
            normalized = _normalize_path(path_part)
            allowed_paths.add(normalized)
            allowed_basenames.add(Path(normalized).name)

    allowed_extensions = {Path(path).suffix.lstrip(".").lower() for path in allowed_paths if "." in path}
    return allowed_paths, allowed_basenames, allowed_extensions


def _validate_entity_whitelist(text: str, scan_result: ScanResult) -> bool:
    allowed_cves = {finding.cve_id for finding in scan_result.cve_findings}
    allowed_paths, allowed_basenames, allowed_extensions = _collect_allowed_paths(scan_result)

    for match in re.findall(r"CVE-\d{4}-\d+", text):
        if match not in allowed_cves:
            return False

    path_candidates = re.findall(r"[A-Za-z0-9_./\\-]+:\d+", text)
    path_candidates += re.findall(r"[A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]{1,6}", text)
    for raw in path_candidates:
        cleaned = raw.strip(".,;)")
        normalized = _normalize_path(cleaned)
        if ":" in normalized and normalized.rsplit(":", 1)[-1].isdigit():
            path_part = normalized.rsplit(":", 1)[0]
        else:
            path_part = normalized

        if "/" in path_part:
            if path_part not in allowed_paths and Path(path_part).name not in allowed_basenames:
                return False
        else:
            extension = Path(path_part).suffix.lstrip(".").lower()
            if extension in allowed_extensions and Path(path_part).name not in allowed_basenames:
                return False

    return True


def _extract_json_block(text: str) -> str | None:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip().startswith("```"):
            return "\n".join(lines[1:-1]).strip()
    if "{" in text and "}" in text:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start : end + 1].strip()
    return None


def _parse_explanation(text: str, scan_result: ScanResult) -> str | None:
    if not text:
        return None
    candidate = _extract_json_block(text) or text
    try:
        data = json.loads(candidate)
        explanation = ExplanationSchema.model_validate(data)
    except (json.JSONDecodeError, ValidationError) as exc:
        logger.warning("LLM response parse failed: %s", exc)
        return None
    if not _validate_entity_whitelist(text, scan_result):
        logger.warning("LLM response failed entity whitelist validation")
        return None
    return (
        f"{explanation.summary} Critical path: {explanation.critical_path}. "
        f"Recommendation: {explanation.recommendation}. Rationale: {explanation.risk_rationale}."
    )


def _build_user_prompt(scan_result: ScanResult) -> str:
    findings = [
        {
            "cve_id": finding.cve_id,
            "package_name": finding.package_name,
            "installed_version": finding.installed_version,
            "fixed_version": finding.fixed_version,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "epss_score": finding.epss_score,
            "kev_listed": finding.kev_listed,
            "defined_in": finding.defined_in,
        }
        for finding in scan_result.cve_findings
    ]
    risk_scores = [score.model_dump() for score in scan_result.risk_scores]
    reachability_paths = {
        entry.cve_id: entry.call_chain for entry in scan_result.reachability
    }
    payload = {
        "overall_verdict": scan_result.overall_verdict,
        "risk_scores": risk_scores,
        "findings": findings,
        "reachability_paths": reachability_paths,
    }
    return json.dumps(payload, indent=2)


async def _request_groq(payload: str) -> str:
    settings = get_settings()
    if not settings.GROQ_API_KEY:
        return ""
    headers = {"Authorization": f"Bearer {settings.GROQ_API_KEY}"}
    fallback_models = [
        "llama3-70b-8192",
        "llama3-8b-8192",
    ]
    models = [settings.GROQ_MODEL] + [
        model for model in fallback_models if model != settings.GROQ_MODEL
    ]
    timeout = settings.HTTP_TIMEOUT_SECONDS
    retries = settings.HTTP_RETRY_COUNT
    async with httpx.AsyncClient(timeout=timeout) as client:
        for model in models:
            body = {
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": payload},
                ],
                "temperature": 0.2,
                "max_tokens": 600,
            }
            for attempt in range(retries + 1):
                try:
                    response = await client.post(
                        settings.GROQ_API_URL, headers=headers, json=body
                    )
                    if response.status_code >= 400:
                        error_detail = ""
                        try:
                            error_payload = response.json()
                            error_detail = error_payload.get("error", {}).get("message", "")
                        except ValueError:
                            error_detail = response.text[:500]
                        logger.warning(
                            "Groq response %s: %s",
                            response.status_code,
                            error_detail or "No detail",
                        )
                        if "decommissioned" in error_detail or "model" in error_detail.lower():
                            break
                        continue
                    data = response.json()
                    message = data.get("choices", [{}])[0].get("message", {})
                    content = message.get("content", "")
                    if isinstance(content, list):
                        content = "".join(str(part) for part in content)
                    if not isinstance(content, str):
                        content = str(content)
                    if not content.strip():
                        logger.warning("Groq returned empty content")
                        continue
                    return content
                except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                    logger.warning("Groq explanation failed (attempt %s): %s", attempt + 1, exc)
    return ""


async def generate_explanation(scan_result: ScanResult) -> str:
    settings = get_settings()
    payload = _build_user_prompt(scan_result)

    if settings.GROQ_API_KEY:
        text = await _request_groq(payload)
        parsed = _parse_explanation(text, scan_result)
        return parsed or template_fallback(scan_result)

    if not settings.ANTHROPIC_API_KEY:
        return template_fallback(scan_result)

    client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
    try:
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=600,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": payload}],
        )
        content_blocks = response.content or []
        text = content_blocks[0].text if content_blocks else ""
        parsed = _parse_explanation(text, scan_result)
        return parsed or template_fallback(scan_result)
    except anthropic.APIError as exc:
        logger.warning("Claude explanation failed: %s", exc)
        return template_fallback(scan_result)

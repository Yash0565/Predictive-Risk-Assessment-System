"""ai_remediation.py
─────────────────
Generates remediation plans and refactoring diffs for breaking package upgrades.
Uses Gemini API with a deterministic template-based fallback.
"""
from __future__ import annotations

import os
import json
import logging
import asyncio
from dataclasses import dataclass, asdict
from typing import Optional, Any
import requests
from src.impact_analyzer import APIChange
from src.smart_scanner import CodeUsageFinding

logger = logging.getLogger("pre_upgrade_system")

@dataclass
class RemediationItem:
    file: str
    line: int
    old_code: str
    new_code: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class RemediationPlan:
    items: list[RemediationItem]
    generated_by: str  # "gemini" | "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_by": self.generated_by,
            "items": [item.to_dict() for item in self.items]
        }

def get_deterministic_remediation(
    api_changes: list[APIChange],
    code_usages: list[CodeUsageFinding]
) -> RemediationPlan:
    """Generates a fallback deterministic remediation plan without LLM calls."""
    items = []
    
    # Create lookup map for APIChanges
    change_map = {c.symbol: c for c in api_changes}
    
    for usage in code_usages:
        change = change_map.get(usage.matched_symbol)
        
        old_code = usage.source_line
        new_code = f"# TODO: Refactor usage of {usage.matched_symbol}"
        explanation = f"The symbol '{usage.matched_symbol}' has been modified or removed in the upgraded package version."
        
        if change:
            symbol_leaf = change.symbol.split(".")[-1]
            if change.change_type in ("FUNCTION_REMOVED", "METHOD_REMOVED"):
                new_code = f"# TODO: '{symbol_leaf}' was removed in the upgraded version. Remove or replace this call."
                explanation = f"Function/method '{change.symbol}' was completely removed."
            elif change.change_type == "CLASS_REMOVED":
                new_code = f"# TODO: Class '{change.symbol}' was removed. Find replacement or pin to previous version."
                explanation = f"Class '{change.symbol}' was removed from the package."
            elif change.change_type == "SIGNATURE_CHANGED":
                new_code = f"# TODO: Signature changed. Update arguments. Old: '{change.old_signature}'. New: '{change.new_signature}'."
                explanation = f"Signature change detected: {change.description}"
                
        items.append(
            RemediationItem(
                file=usage.file,
                line=usage.line,
                old_code=old_code,
                new_code=new_code,
                explanation=explanation
            )
        )
        
    return RemediationPlan(items=items, generated_by="deterministic")

def _call_gemini_sync(api_key: str, prompt: str) -> str:
    """Synchronous network call to Gemini API."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json"
        }
    }
    
    # 30 second timeout
    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    resp_json = resp.json()
    return resp_json["candidates"][0]["content"]["parts"][0]["text"]

async def generate_remediation(
    api_changes: list[APIChange],
    code_usages: list[CodeUsageFinding]
) -> RemediationPlan:
    """Generates remediation refactoring items.
    
    Attempts to call Gemini API if key is present; otherwise falls back to deterministic rules.
    """
    if not code_usages:
        return RemediationPlan(items=[], generated_by="deterministic")
        
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        logger.info("No Gemini API key found. Generating deterministic remediation plan.")
        return get_deterministic_remediation(api_changes, code_usages)

    # Build minimal prompt data structure to fit model token/context limits
    diagnostics = []
    change_map = {c.symbol: c for c in api_changes}
    for usage in code_usages:
        change = change_map.get(usage.matched_symbol)
        diagnostics.append({
            "file": usage.file,
            "line": usage.line,
            "source_line": usage.source_line,
            "symbol": usage.matched_symbol,
            "change_type": usage.change_type,
            "old_signature": change.old_signature if change else None,
            "new_signature": change.new_signature if change else None,
            "change_detail": change.description if change else None
        })

    prompt = (
        "You are an expert software engineer performing a package upgrade codebase migration.\n"
        "Generate a refactoring plan to resolve the following breaking API usages in the codebase.\n\n"
        f"Breaking API Usages:\n{json.dumps(diagnostics, indent=2)}\n\n"
        "Provide a concrete refactored replacement code snippet for each item. "
        "Return your response strictly as a JSON object matching this schema:\n"
        "{\n"
        "  \"items\": [\n"
        "    {\n"
        "      \"file\": \"Filename\",\n"
        "      \"line\": 42,\n"
        "      \"old_code\": \"Old code line to search/match\",\n"
        "      \"new_code\": \"New code replacement suggestion\",\n"
        "      \"explanation\": \"A concise description of why this change is necessary and what it accomplishes.\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
    )
    
    logger.info("Requesting Gemini AI remediation suggestions...")
    try:
        # Run sync request in a thread pool to avoid blocking the asyncio event loop
        text_response = await asyncio.to_thread(_call_gemini_sync, api_key, prompt)
        data = json.loads(text_response)
        
        items = []
        for s in data.get("items", []):
            items.append(
                RemediationItem(
                    file=s.get("file", ""),
                    line=int(s.get("line", 1)),
                    old_code=s.get("old_code", ""),
                    new_code=s.get("new_code", ""),
                    explanation=s.get("explanation", "")
                )
            )
        return RemediationPlan(items=items, generated_by="gemini")
        
    except Exception as exc:
        logger.warning("Failed to generate AI remediation from Gemini: %s. Using fallback.", exc)
        return get_deterministic_remediation(api_changes, code_usages)

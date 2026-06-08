"""Labeled-corpus schema and loader for the benchmark."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_DEFAULT_CORPUS = Path(__file__).resolve().parent / "data" / "labeled_corpus.json"


@dataclass(frozen=True)
class LabeledCase:
    cve_id: str
    package: str
    installed_version: str
    cvss: float
    epss: float
    in_kev: bool
    reachable: bool          # ground-truth reachability
    must_fix: bool           # ground-truth triage decision
    source: str = ""


def load_corpus(path: Optional[str] = None) -> list[LabeledCase]:
    p = Path(path) if path else _DEFAULT_CORPUS
    data = json.loads(p.read_text(encoding="utf-8"))
    cases = []
    for c in data.get("cases", []):
        cases.append(LabeledCase(
            cve_id=c["cve_id"],
            package=c["package"],
            installed_version=c.get("installed_version", ""),
            cvss=float(c.get("cvss", 0.0)),
            epss=float(c.get("epss", 0.0)),
            in_kev=bool(c.get("in_kev", False)),
            reachable=bool(c["reachable"]),
            must_fix=bool(c["must_fix"]),
            source=c.get("source", ""),
        ))
    return cases


def corpus_metadata(path: Optional[str] = None) -> dict:
    p = Path(path) if path else _DEFAULT_CORPUS
    data = json.loads(p.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if k != "cases"}

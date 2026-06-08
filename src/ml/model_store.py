"""Persist and load the trained exploit-prediction model weights."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from src.ml.exploit_model import (
    CVERecord,
    FEATURE_NAMES,
    LogisticRegression,
    StandardScaler,
    TrainedModel,
    generate_synthetic_dataset,
    temporal_split,
    train,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_PATH = _REPO_ROOT / "data" / "exploit_model.json"


def save_model(model: TrainedModel, path: Optional[str] = None) -> str:
    """Serialize trained weights to JSON."""
    out = Path(path) if path else _DEFAULT_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "feature_names": model.feature_names,
        "scaler": {"mean": model.scaler.mean, "std": model.scaler.std},
        "clf": {
            "weights": model.clf.weights,
            "bias": model.clf.bias,
        },
    }
    with out.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return str(out)


def load_model(path: Optional[str] = None) -> Optional[TrainedModel]:
    """Load a previously saved model, or None if missing/corrupt."""
    p = Path(path) if path else _DEFAULT_PATH
    if not p.is_file():
        return None
    try:
        with p.open(encoding="utf-8") as fh:
            data = json.load(fh)
        scaler = StandardScaler(mean=data["scaler"]["mean"], std=data["scaler"]["std"])
        clf = LogisticRegression(weights=data["clf"]["weights"], bias=data["clf"]["bias"])
        return TrainedModel(
            scaler=scaler,
            clf=clf,
            feature_names=data.get("feature_names", list(FEATURE_NAMES)),
        )
    except (KeyError, json.JSONDecodeError, OSError, TypeError):
        return None


def ensure_default_model(path: Optional[str] = None) -> TrainedModel:
    """Return a trained model, creating one from the synthetic dataset if needed."""
    existing = load_model(path)
    if existing is not None:
        return existing
    records = generate_synthetic_dataset(n=1200, seed=42)
    train_recs, _ = temporal_split(records, train_fraction=0.75)
    model = train(train_recs)
    save_model(model, path)
    return model


def predict_exploit_probability(
    cve_id: str,
    cvss: float,
    epss: float,
    epss_percentile: float = 0.0,
    cwe_count: int = 0,
    age_days: float = 30.0,
    *,
    model_path: Optional[str] = None,
) -> float:
    """Return P(exploited) for a single CVE using the stored model."""
    model = ensure_default_model(model_path)
    record = CVERecord(
        cve_id=cve_id,
        cvss=cvss,
        epss=epss,
        epss_percentile=epss_percentile,
        cwe_count=cwe_count,
        age_days=age_days,
        published_ordinal=0,
        label=0,
    )
    return model.predict_proba([record])[0]

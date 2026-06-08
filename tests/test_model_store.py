"""Tests for ML model persistence and exploit probability prediction."""

from __future__ import annotations

from src.ml.model_store import ensure_default_model, load_model, predict_exploit_probability, save_model


def test_ensure_default_model_creates_and_loads(tmp_path) -> None:
    path = str(tmp_path / "exploit_model.json")
    model = ensure_default_model(path)
    assert model.clf.weights
    loaded = load_model(path)
    assert loaded is not None
    assert len(loaded.clf.weights) == len(model.clf.weights)


def test_predict_exploit_probability_in_range(tmp_path) -> None:
    path = str(tmp_path / "exploit_model.json")
    ensure_default_model(path)
    p = predict_exploit_probability(
        "CVE-TEST-1", cvss=9.0, epss=0.8, epss_percentile=0.95, cwe_count=2,
        model_path=path,
    )
    assert 0.0 <= p <= 1.0


def test_save_model_roundtrip(tmp_path) -> None:
    path = str(tmp_path / "model.json")
    model = ensure_default_model(path)
    save_model(model, path)
    reloaded = load_model(path)
    assert reloaded is not None
    probs = reloaded.predict_proba([
        __import__("src.ml.exploit_model", fromlist=["CVERecord"]).CVERecord(
            cve_id="X", cvss=7.0, epss=0.3, epss_percentile=0.5,
            cwe_count=1, age_days=10, published_ordinal=1, label=0,
        )
    ])
    assert len(probs) == 1

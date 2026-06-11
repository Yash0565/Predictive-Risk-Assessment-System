"""Tests for the benchmark framework (metrics + corpus + runner)."""

from __future__ import annotations

from bench.corpus import load_corpus
from bench.metrics import (
    brier_score,
    confusion_matrix,
    expected_calibration_error,
    reliability_bins,
)
from bench.runner import evaluate


def test_confusion_matrix_basic() -> None:
    y_true = [True, True, False, False]
    y_pred = [True, False, False, False]
    cm = confusion_matrix(y_true, y_pred)
    assert (cm.tp, cm.fp, cm.tn, cm.fn) == (1, 0, 2, 1)
    assert cm.precision() == 1.0
    assert cm.recall() == 0.5
    assert round(cm.f1(), 4) == 0.6667
    assert cm.false_positive_rate() == 0.0
    assert cm.false_negative_rate() == 0.5


def test_confusion_matrix_perfect_and_empty() -> None:
    cm = confusion_matrix([True, False], [True, False])
    assert cm.accuracy() == 1.0
    assert cm.precision() == 1.0 and cm.recall() == 1.0
    empty = confusion_matrix([], [])
    assert empty.precision() == 0.0 and empty.f1() == 0.0


def test_brier_score_bounds() -> None:
    assert brier_score([True, False], [1.0, 0.0]) == 0.0
    assert brier_score([True, False], [0.0, 1.0]) == 1.0


def test_reliability_bins_partition() -> None:
    y_true = [True, False, True, True]
    y_prob = [0.95, 0.05, 0.85, 0.9]
    bins = reliability_bins(y_true, y_prob, n_bins=10)
    counted = sum(b["count"] for b in bins)
    assert counted == len(y_true)
    ece = expected_calibration_error(y_true, y_prob, n_bins=10)
    assert 0.0 <= ece <= 1.0


def test_corpus_loads_and_is_consistent() -> None:
    cases = load_corpus()
    assert len(cases) >= 8
    # must_fix implies reachable in this seed corpus's labeling scheme.
    for c in cases:
        if c.must_fix:
            assert c.reachable


def test_reachability_aware_beats_baseline_precision() -> None:
    report = evaluate()
    strat = report["strategies"]
    ours = strat["reachability_aware"]
    sev = strat["severity_only"]
    # The core claim: reachability gating removes false positives without
    # sacrificing recall relative to severity-only triage.
    assert ours["precision"] >= sev["precision"]
    assert ours["fpr"] <= sev["fpr"]
    assert ours["recall"] >= sev["recall"]
    assert ours["alerts_raised"] <= sev["alerts_raised"]


def test_reachability_aware_has_no_false_positives_on_corpus() -> None:
    report = evaluate()
    ours = report["strategies"]["reachability_aware"]
    assert ours["fp"] == 0

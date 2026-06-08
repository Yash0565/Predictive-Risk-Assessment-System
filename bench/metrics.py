"""Classification and calibration metrics (pure functions, no I/O).

All functions take plain Python sequences so they are trivially unit-testable
and have no third-party dependency.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Sequence


@dataclass
class ConfusionMatrix:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    def recall(self) -> float:
        """Recall / true-positive rate / sensitivity."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def false_negative_rate(self) -> float:
        denom = self.fn + self.tp
        return self.fn / denom if denom else 0.0

    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def specificity(self) -> float:
        denom = self.tn + self.fp
        return self.tn / denom if denom else 0.0

    def as_dict(self) -> dict:
        d = asdict(self)
        d.update({
            "precision": round(self.precision(), 4),
            "recall": round(self.recall(), 4),
            "f1": round(self.f1(), 4),
            "fpr": round(self.false_positive_rate(), 4),
            "fnr": round(self.false_negative_rate(), 4),
            "accuracy": round(self.accuracy(), 4),
            "specificity": round(self.specificity(), 4),
        })
        return d


def confusion_matrix(y_true: Sequence[bool], y_pred: Sequence[bool]) -> ConfusionMatrix:
    """Binary confusion matrix where ``True`` is the positive (must-fix) class."""
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must be the same length")
    tp = fp = tn = fn = 0
    for actual, pred in zip(y_true, y_pred):
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and not actual:
            tn += 1
        else:
            fn += 1
    return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)


def brier_score(y_true: Sequence[bool], y_prob: Sequence[float]) -> float:
    """Mean squared error between predicted probabilities and outcomes.

    Lower is better (0 = perfect). Measures probability calibration quality.
    """
    if len(y_true) != len(y_prob):
        raise ValueError("y_true and y_prob must be the same length")
    if not y_true:
        return 0.0
    return sum((p - (1.0 if a else 0.0)) ** 2 for a, p in zip(y_true, y_prob)) / len(y_true)


def reliability_bins(
    y_true: Sequence[bool],
    y_prob: Sequence[float],
    n_bins: int = 10,
) -> list[dict]:
    """Group predictions into probability bins and compare predicted vs observed.

    A well-calibrated model has mean_predicted ~= observed_frequency per bin.
    """
    bins: list[dict] = []
    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        idx = [
            i for i, p in enumerate(y_prob)
            if (p >= lo and (p < hi or (b == n_bins - 1 and p <= hi)))
        ]
        if not idx:
            bins.append({
                "bin": b, "range": [round(lo, 2), round(hi, 2)],
                "count": 0, "mean_predicted": None, "observed_frequency": None,
            })
            continue
        mean_pred = sum(y_prob[i] for i in idx) / len(idx)
        observed = sum(1 for i in idx if y_true[i]) / len(idx)
        bins.append({
            "bin": b,
            "range": [round(lo, 2), round(hi, 2)],
            "count": len(idx),
            "mean_predicted": round(mean_pred, 4),
            "observed_frequency": round(observed, 4),
        })
    return bins


def expected_calibration_error(
    y_true: Sequence[bool],
    y_prob: Sequence[float],
    n_bins: int = 10,
) -> float:
    """Weighted average gap between confidence and accuracy across bins (ECE)."""
    n = len(y_true)
    if not n:
        return 0.0
    ece = 0.0
    for b in reliability_bins(y_true, y_prob, n_bins):
        if not b["count"] or b["mean_predicted"] is None:
            continue
        ece += (b["count"] / n) * abs(b["mean_predicted"] - b["observed_frequency"])
    return round(ece, 4)

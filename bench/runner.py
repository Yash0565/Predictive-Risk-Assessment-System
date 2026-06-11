"""Run every prioritization strategy over the labeled corpus and report metrics.

Usage:
    python -m bench.runner                # human-readable table
    python -m bench.runner --json out.json
"""

from __future__ import annotations

import argparse
import json
from typing import Optional

from bench.baselines import STRATEGIES
from bench.corpus import corpus_metadata, load_corpus
from bench.metrics import (
    brier_score,
    confusion_matrix,
    expected_calibration_error,
    reliability_bins,
)


def evaluate(corpus_path: Optional[str] = None) -> dict:
    cases = load_corpus(corpus_path)
    y_true = [c.must_fix for c in cases]

    results: dict[str, dict] = {}
    for name, strategy in STRATEGIES.items():
        preds = [strategy(c) for c in cases]
        y_pred = [p[0] for p in preds]
        y_prob = [p[1] for p in preds]
        cm = confusion_matrix(y_true, y_pred)
        results[name] = {
            **cm.as_dict(),
            "brier_score": round(brier_score(y_true, y_prob), 4),
            "ece": expected_calibration_error(y_true, y_prob, n_bins=5),
            "alerts_raised": sum(y_pred),
            "alerts_vs_total": f"{sum(y_pred)}/{len(cases)}",
        }

    # Noise-reduction: how many fewer alerts than the severity-only baseline,
    # while preserving recall (no missed true must-fix).
    base = results.get("severity_only", {})
    ours = results.get("reachability_aware", {})
    noise_reduction = None
    if base.get("alerts_raised") and ours.get("alerts_raised") is not None:
        noise_reduction = round(
            100 * (base["alerts_raised"] - ours["alerts_raised"]) / base["alerts_raised"], 1
        )

    return {
        "corpus": corpus_metadata(corpus_path),
        "n_cases": len(cases),
        "n_positive": sum(y_true),
        "strategies": results,
        "headline": {
            "reachability_aware_recall": ours.get("recall"),
            "reachability_aware_precision": ours.get("precision"),
            "severity_only_precision": base.get("precision"),
            "alert_noise_reduction_percent_vs_severity_only": noise_reduction,
        },
    }


def _print_table(report: dict) -> None:
    print(f"\nBenchmark: {report['n_cases']} cases, {report['n_positive']} must-fix\n")
    cols = ["precision", "recall", "f1", "fpr", "fnr", "brier_score", "alerts_vs_total"]
    header = f"{'strategy':<22}" + "".join(f"{c:>16}" for c in cols)
    print(header)
    print("-" * len(header))
    for name, m in report["strategies"].items():
        row = f"{name:<22}" + "".join(f"{str(m[c]):>16}" for c in cols)
        print(row)
    h = report["headline"]
    print(
        f"\nReachability-aware vs severity-only: "
        f"precision {h['severity_only_precision']} -> {h['reachability_aware_precision']}, "
        f"recall {h['reachability_aware_recall']}, "
        f"alert noise reduction {h['alert_noise_reduction_percent_vs_severity_only']}%\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run the prioritization benchmark.")
    ap.add_argument("--corpus", help="path to labeled corpus JSON")
    ap.add_argument("--json", help="write full report JSON to this path")
    args = ap.parse_args(argv)

    report = evaluate(args.corpus)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Wrote {args.json}")
    _print_table(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

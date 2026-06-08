"""Machine-learning components for predictive risk.

Currently ships a self-contained, dependency-free logistic-regression learner
plus feature extraction, temporal/random splitting, and calibration evaluation.

Honesty note: the bundled EPSS/KEV snapshots are tiny demo fixtures and are NOT
sufficient to train a production model. The learner and evaluation harness are
real and tested; production training requires the historical dataset described
in ``src/ml/exploit_model.py`` (the documented data dependency).
"""

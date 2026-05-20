#!/usr/bin/env python3
"""Populate data/depsdev/PyPI cache for offline TaskFlow upgrade demos."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.upgrade_simulator import fetch_depsdev  # noqa: E402

# (package, version) pairs needed for TaskFlow scenarios + transitive closure
PAIRS = [
    ("requests", "2.20.0"),
    ("requests", "2.31.0"),
    ("urllib3", "1.24.1"),
    ("urllib3", "1.24.3"),
    ("urllib3", "2.0.7"),
    ("urllib3", "2.7.0"),
    ("boto3", "1.10.0"),
    ("boto3", "1.26.0"),
    ("boto3", "1.28.0"),
    ("botocore", "1.13.50"),
    ("botocore", "1.29.165"),
    ("botocore", "1.31.0"),
    ("botocore", "1.31.85"),
    ("flask", "0.12"),
    ("flask", "2.3.0"),
    ("jinja2", "2.10"),
    ("jinja2", "3.1.2"),
    ("werkzeug", "2.3.7"),
    ("pillow", "6.0.0"),
    ("pyyaml", "5.1"),
    ("pyyaml", "5.4.0"),
    ("cryptography", "2.3"),
    ("sqlalchemy", "1.3.0"),
    ("certifi", "2024.8.30"),
    ("charset-normalizer", "3.3.2"),
    ("idna", "3.7"),
    ("s3transfer", "0.2.1"),
    ("s3transfer", "0.6.2"),
    ("jmespath", "0.10.0"),
    ("python-dateutil", "2.9.0.post0"),
    ("six", "1.16.0"),
    ("docutils", "0.15.2"),
    ("markupsafe", "2.1.3"),
    ("itsdangerous", "2.1.2"),
    ("click", "8.1.7"),
    ("blinker", "1.7.0"),
]


def main() -> None:
    ok = 0
    for pkg, ver in PAIRS:
        data = fetch_depsdev(pkg, ver, force_refresh=True)
        if data:
            ok += 1
            print(f"cached {pkg}=={ver}")
        else:
            print(f"FAILED {pkg}=={ver}")
    print(f"done: {ok}/{len(PAIRS)}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

import joblib


SCRIPT_DIR = Path(__file__).resolve().parent
CLOUD_DIR = SCRIPT_DIR.parent
ML_MODELS_DIR = CLOUD_DIR / "ml_models"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a trained network baseline bundle into cloud/ml_models."
    )
    parser.add_argument(
        "--source-bundle",
        default=None,
        help="Path to network_baseline_bundle.pkl. If omitted, auto-discovers latest run bundle.",
    )
    parser.add_argument(
        "--target-bundle",
        default=str(ML_MODELS_DIR / "network_baseline_bundle.pkl"),
        help="Target path for installed bundle.",
    )
    return parser.parse_args()


def discover_latest_bundle() -> Path | None:
    candidates = []

    search_roots = [
        Path("c:/Hamza/FYP/JA4/FYP/EDA JA$/network_baseline_pipeline/runs"),
        Path.cwd() / "network_baseline_pipeline" / "runs",
    ]

    for root in search_roots:
        if not root.exists():
            continue
        candidates.extend(root.glob("*/models/network_baseline_bundle.pkl"))

    if not candidates:
        return None

    candidates = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def validate_bundle(path: Path) -> None:
    bundle = joblib.load(path)
    required = [
        "iforest_model",
        "preprocessor",
        "scaler",
        "feature_columns",
        "selected_threshold",
    ]
    missing = [key for key in required if key not in bundle]
    if missing:
        raise ValueError(f"Invalid bundle at {path}. Missing keys: {missing}")


def main() -> None:
    args = parse_args()

    source = Path(args.source_bundle) if args.source_bundle else discover_latest_bundle()
    if source is None:
        raise FileNotFoundError(
            "No source bundle found. Provide --source-bundle or create a training run first."
        )
    if not source.exists():
        raise FileNotFoundError(f"Source bundle not found: {source}")

    validate_bundle(source)

    target = Path(args.target_bundle)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)

    print(f"Installed behavioral bundle: {target}")
    print(f"Source: {source}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)

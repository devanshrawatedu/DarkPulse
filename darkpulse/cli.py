"""DarkPulse command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import get_settings
from .pipeline import Pipeline
from .utils import configure_logging

DASHBOARD_APP = Path(__file__).resolve().parent / "dashboard" / "app.py"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="darkpulse",
        description="DarkPulse: automated threat intelligence & leak analytics platform",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    pipeline_cmd = subparsers.add_parser(
        "pipeline", help="run the full pipeline and export artifacts"
    )
    pipeline_cmd.add_argument(
        "--offline", action="store_true", help="use bundled fixtures, no network"
    )

    ingest_cmd = subparsers.add_parser("ingest", help="run ingestion only")
    ingest_cmd.add_argument(
        "--source", choices=["nvd", "cisa_kev", "feeds", "all"], default="all"
    )
    ingest_cmd.add_argument("--offline", action="store_true")

    demo_cmd = subparsers.add_parser(
        "demo", help="run the pipeline offline and print top alerts"
    )
    demo_cmd.add_argument("--top", type=int, default=10)

    subparsers.add_parser("dashboard", help="launch the Streamlit dashboard")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)

    if args.command == "dashboard":
        return _run_dashboard()

    pipeline = Pipeline(settings)

    if args.command == "pipeline":
        result = pipeline.run(offline=args.offline or settings.offline)
        print(result.summary())
        print("artifacts:", json.dumps(pipeline.export_artifacts(), indent=2))
        _print_top(pipeline, 10)
        return 0 if not result.errors else 1

    if args.command == "ingest":
        records = pipeline.ingest(offline=args.offline or settings.offline)
        print(
            f"ingested {len(records)} normalized records "
            f"({pipeline.store.count_raw()} raw / "
            f"{pipeline.store.count_normalized()} normalized)"
        )
        return 0

    result = pipeline.run(offline=True)  # demo
    print(result.summary())
    _print_top(pipeline, args.top)
    return 0


def _run_dashboard() -> int:
    from streamlit.web import cli as streamlit_cli

    sys.argv = ["streamlit", "run", str(DASHBOARD_APP)]
    streamlit_cli.main()
    return 0


def _print_top(pipeline: Pipeline, count: int) -> None:
    if not pipeline.last_alerts:
        print("no alerts produced")
        return
    shown = pipeline.last_alerts[: max(count, 0)]
    print(f"\nTop {len(shown)} prioritized threats:")
    for alert in shown:
        print(
            f"  #{alert.rank} [{alert.score:.3f}] "
            f"{alert.entity_type.value:14s} {alert.entity}"
        )
        for reason in alert.reasons[:3]:
            print(f"        - {reason}")


if __name__ == "__main__":
    raise SystemExit(main())

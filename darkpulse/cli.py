"""DarkPulse command-line interface."""

from __future__ import annotations

import argparse
import json

from .config import get_settings
from .pipeline import Pipeline
from .utils import configure_logging


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

    dashboard_cmd = subparsers.add_parser(
        "dashboard", help="launch the web dashboard (FastAPI + custom UI)"
    )
    dashboard_cmd.add_argument("--host", default="127.0.0.1")
    dashboard_cmd.add_argument("--port", type=int, default=8000)
    dashboard_cmd.add_argument(
        "--offline", action="store_true", help="load bundled fixtures instead of live sources"
    )
    dashboard_cmd.add_argument(
        "--live", action="store_true", help="force live collection even if DARKPULSE_OFFLINE is set"
    )
    dashboard_cmd.add_argument(
        "--no-browser", action="store_true", help="do not open a browser window"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)

    if args.command == "dashboard":
        return _run_dashboard(args, settings)

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


def _run_dashboard(args: argparse.Namespace, settings) -> int:
    try:
        from .web.server import serve
    except ImportError:
        print(
            "The dashboard needs FastAPI and uvicorn.\n"
            "Install them with:  pip install -e \".[web]\"",
        )
        return 1

    if args.live:
        settings.offline = False
    elif args.offline:
        settings.offline = True
    return serve(
        settings,
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
    )


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

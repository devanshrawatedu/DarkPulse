"""Local server launcher for the DarkPulse dashboard."""

from __future__ import annotations

import threading
import webbrowser

import uvicorn

from ..config import Settings
from .app import create_app


def serve(
    settings: Settings | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = True,
) -> int:
    """Run the dashboard on uvicorn; the pipeline loads in the background."""
    app = create_app(settings)
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    url = f"http://{display_host}:{port}"

    print(f"\n  DarkPulse v2 dashboard: {url}")
    print("  The first pipeline run happens in the background; the UI fills in as it completes.\n")

    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    try:
        uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
    except OSError as exc:
        print(f"  Could not bind {host}:{port} - {exc}")
        return 1
    return 0

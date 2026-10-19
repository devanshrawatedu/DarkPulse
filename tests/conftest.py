"""Pytest configuration: offline mode for all tests (no network access)."""

import os

os.environ.setdefault("DARKPULSE_OFFLINE", "1")

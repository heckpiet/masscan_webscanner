#!/usr/bin/env python3
"""Backward-compatible entry point; use ``masscan-webscanner`` for new installs."""
from masscan_webscanner import main

if __name__ == "__main__":
    raise SystemExit(main())

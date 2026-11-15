#!/usr/bin/env python3
"""
HexStrike AI - FastAPI Server Entrypoint
Delegates to the modular `src` package (`src.server`).
"""

from src.server import *  # noqa: F401,F403
from src.server import app, create_app, main

if __name__ == "__main__":
    main()

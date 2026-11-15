#!/usr/bin/env python3
"""
HexStrike AI - FastMCP Server Entrypoint
Delegates to the modular `src` package (`src.mcp_server`).
"""

from src.mcp_server import *  # noqa: F401,F403
from src.mcp_server import HexStrikeClient, setup_mcp_server, parse_args, main

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
HexStrike AI - FastAPI Server Entrypoint
"""

import argparse
import logging
from fastapi import FastAPI
import uvicorn

import src.config as config
from src.config import (
    logger,
    API_PORT,
    API_HOST,
    DEBUG_MODE,
    COMMAND_TIMEOUT,
    CACHE_SIZE,
    CACHE_TTL,
)
from src.core import *
from src.agents import *
from src.api import *
from src.api import OPENAPI_TAGS, register_routers


def create_app() -> FastAPI:
    """Create and configure the HexStrike AI FastAPI application."""
    application = FastAPI(
        title="HexStrike AI Tools API Server",
        description=(
            "AI-Powered Cybersecurity Automation & Multi-Domain Investigation Platform. "
            "Endpoints are organized by security domain categories compatible with README.md "
            "and support both single-domain and multi-domain investigations."
        ),
        version="6.0.0",
        openapi_tags=OPENAPI_TAGS,
    )
    register_routers(application)
    return application


app = create_app()


def main() -> None:
    """CLI entrypoint to start the FastAPI server with Uvicorn."""
    print(BANNER)

    parser = argparse.ArgumentParser(description="Run the HexStrike AI FastAPI Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=config.API_PORT, help=f"Port for the API server (default: {config.API_PORT})")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    args = parser.parse_args()

    if args.debug:
        config.DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port != config.API_PORT:
        config.API_PORT = args.port

    startup_info = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Starting HexStrike AI FastAPI Server{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}🌐 Port:{ModernVisualEngine.COLORS['RESET']} {config.API_PORT}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🔧 Debug Mode:{ModernVisualEngine.COLORS['RESET']} {config.DEBUG_MODE}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}💾 Cache Size:{ModernVisualEngine.COLORS['RESET']} {CACHE_SIZE} | TTL: {CACHE_TTL}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}⏱️  Command Timeout:{ModernVisualEngine.COLORS['RESET']} {COMMAND_TIMEOUT}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}✨ Multi-Domain Investigation & Visual Engine:{ModernVisualEngine.COLORS['RESET']} Active
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

    for line in startup_info.strip().split("\n"):
        if line.strip():
            logger.info(line)

    uvicorn.run(
        app,
        host=args.host,
        port=config.API_PORT,
        log_level="debug" if config.DEBUG_MODE else "info",
    )


if __name__ == "__main__":
    main()

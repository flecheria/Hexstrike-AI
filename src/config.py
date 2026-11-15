#!/usr/bin/env python3
"""
HexStrike AI - Configuration and Logging Setup
"""

import logging
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Storage & Volume Configuration (container-friendly defaults with fallback)
DATA_DIR = os.environ.get("HEXSTRIKE_DATA_DIR", "/tmp/hexstrike_data")
RESULTS_DIR = os.environ.get("HEXSTRIKE_RESULTS_DIR", os.path.join(DATA_DIR, "results"))
FILES_DIR = os.environ.get("HEXSTRIKE_FILES_DIR", "/tmp/hexstrike_files")
ENVS_DIR = os.environ.get("HEXSTRIKE_ENVS_DIR", "/tmp/hexstrike_envs")
LOG_FILE = os.environ.get("HEXSTRIKE_LOG_FILE", "hexstrike.log")

# Tool Manifest & Container Build State Configuration
TOOLS_MANIFEST_PATH = os.environ.get(
    "HEXSTRIKE_TOOLS_MANIFEST",
    str(PROJECT_ROOT / "config" / "tools_manifest.json"),
)
INSTALLED_TOOLS_STATE_PATH = os.environ.get(
    "HEXSTRIKE_INSTALLED_TOOLS_STATE",
    str(PROJECT_ROOT / "config" / "installed_tools.json"),
)

# Configure logging with fallback for permission issues
try:
    log_parent = os.path.dirname(LOG_FILE)
    if log_parent:
        os.makedirs(log_parent, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_FILE)
        ]
    )
except (PermissionError, OSError):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

logger = logging.getLogger("hexstrike")

# API Configuration
API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))
API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')

# Execution & Cache Configuration
DEBUG_MODE = False
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

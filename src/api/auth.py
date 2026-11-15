#!/usr/bin/env python3
"""
HexStrike AI - Authentication & Password Security API Endpoints
Supports both single-domain/target and multi-domain/target investigations.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import traceback
from typing import Dict, Any, List, Optional, Set, Tuple
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs

from fastapi import Body, Query
from fastapi.responses import JSONResponse
import psutil
import requests

from src.config import logger, DEBUG_MODE, COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL
from src.core import *
from src.agents import *

router = MultiTargetAPIRouter(tags=["Authentication & Password Security"])

@router.post("/api/tools/hydra")
def hydra(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute hydra with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            logger.warning("🎯 Hydra called without target or service parameter")
            return JSONResponse(content={
                "error": "Target and service parameters are required"
            }, status_code=400)

        if not (username or username_file) or not (password or password_file):
            logger.warning("🔑 Hydra called without username/password parameters")
            return JSONResponse(content={
                "error": "Username/username_file and password/password_file are required"
            }, status_code=400)

        command = f"hydra -t 4"

        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"

        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target} {service}"

        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = execute_command(command)
        logger.info(f"📊 Hydra attack completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in hydra endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/john")
def john(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute john with enhanced logging"""
    try:
        params = params or {}
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("🔐 John called without hash_file parameter")
            return JSONResponse(content={
                "error": "Hash file parameter is required"
            }, status_code=400)

        command = f"john"

        if format_type:
            command += f" --format={format_type}"

        if wordlist:
            command += f" --wordlist={wordlist}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {hash_file}"

        logger.info(f"🔐 Starting John the Ripper: {hash_file}")
        result = execute_command(command)
        logger.info(f"📊 John the Ripper completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in john endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/hashcat")
def hashcat(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Hashcat for password cracking with enhanced logging"""
    try:
        params = params or {}
        hash_file = params.get("hash_file", "")
        hash_type = params.get("hash_type", "")
        attack_mode = params.get("attack_mode", "0")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        mask = params.get("mask", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("🔐 Hashcat called without hash_file parameter")
            return JSONResponse(content={
                "error": "Hash file parameter is required"
            }, status_code=400)

        if not hash_type:
            logger.warning("🔐 Hashcat called without hash_type parameter")
            return JSONResponse(content={
                "error": "Hash type parameter is required"
            }, status_code=400)

        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"

        if attack_mode == "0" and wordlist:
            command += f" {wordlist}"
        elif attack_mode == "3" and mask:
            command += f" {mask}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
        result = execute_command(command)
        logger.info(f"📊 Hashcat attack completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in hashcat endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/hashpump")
def hashpump(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute HashPump for hash length extension attacks with enhanced logging"""
    try:
        params = params or {}
        signature = params.get("signature", "")
        data = params.get("data", "")
        key_length = params.get("key_length", "")
        append_data = params.get("append_data", "")
        additional_args = params.get("additional_args", "")

        if not all([signature, data, key_length, append_data]):
            logger.warning("🔐 HashPump called without required parameters")
            return JSONResponse(content={
                "error": "Signature, data, key_length, and append_data parameters are required"
            }, status_code=400)

        command = f"hashpump -s {signature} -d '{data}' -k {key_length} -a '{append_data}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting HashPump attack")
        result = execute_command(command)
        logger.info(f"📊 HashPump attack completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in hashpump endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)



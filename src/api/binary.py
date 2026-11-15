#!/usr/bin/env python3
"""
HexStrike AI - Binary Analysis & Reverse Engineering API Endpoints
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

router = MultiTargetAPIRouter(tags=["Binary Analysis & Reverse Engineering"])

@router.post("/api/tools/gdb")
def gdb(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute GDB for binary analysis and debugging with enhanced logging"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        script_file = params.get("script_file", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 GDB called without binary parameter")
            return JSONResponse(content={
                "error": "Binary parameter is required"
            }, status_code=400)

        command = f"gdb {binary}"

        if script_file:
            command += f" -x {script_file}"

        if commands:
            temp_script = "/tmp/gdb_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command += f" -x {temp_script}"

        if additional_args:
            command += f" {additional_args}"

        command += " -batch"

        logger.info(f"🔧 Starting GDB analysis: {binary}")
        result = execute_command(command)

        if commands and os.path.exists("/tmp/gdb_commands.txt"):
            try:
                os.remove("/tmp/gdb_commands.txt")
            except:
                pass

        logger.info(f"📊 GDB analysis completed for {binary}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in gdb endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/gdb-peda")
def gdb_peda(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute GDB with PEDA for enhanced debugging and exploitation"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        attach_pid = params.get("attach_pid", 0)
        core_file = params.get("core_file", "")
        additional_args = params.get("additional_args", "")

        if not binary and not attach_pid and not core_file:
            logger.warning("🔧 GDB-PEDA called without binary, PID, or core file")
            return JSONResponse(content={"error": "Binary, PID, or core file parameter is required"}, status_code=400)

        # Base GDB command with PEDA
        command = "gdb -q"

        if binary:
            command += f" {binary}"

        if core_file:
            command += f" {core_file}"

        if attach_pid:
            command += f" -p {attach_pid}"

        # Create command script
        if commands:
            temp_script = "/tmp/gdb_peda_commands.txt"
            peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
            with open(temp_script, "w") as f:
                f.write(peda_commands)
            command += f" -x {temp_script}"
        else:
            # Default PEDA initialization
            command += " -ex 'source ~/peda/peda.py' -ex 'quit'"

        if additional_args:
            command += f" {additional_args}"

        target_info = binary or f'PID {attach_pid}' or core_file
        logger.info(f"🔧 Starting GDB-PEDA analysis: {target_info}")
        result = execute_command(command)

        # Cleanup
        if commands and os.path.exists("/tmp/gdb_peda_commands.txt"):
            try:
                os.remove("/tmp/gdb_peda_commands.txt")
            except:
                pass

        logger.info(f"📊 GDB-PEDA analysis completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in gdb-peda endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/radare2")
def radare2(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Radare2 for binary analysis and reverse engineering with enhanced logging"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Radare2 called without binary parameter")
            return JSONResponse(content={
                "error": "Binary parameter is required"
            }, status_code=400)

        if commands:
            temp_script = "/tmp/r2_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command = f"r2 -i {temp_script} -q {binary}"
        else:
            command = f"r2 -q {binary}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = execute_command(command)

        if commands and os.path.exists("/tmp/r2_commands.txt"):
            try:
                os.remove("/tmp/r2_commands.txt")
            except:
                pass

        logger.info(f"📊 Radare2 analysis completed for {binary}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in radare2 endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/ghidra")
def ghidra(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Ghidra for advanced binary analysis and reverse engineering"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        project_name = params.get("project_name", "hexstrike_analysis")
        script_file = params.get("script_file", "")
        analysis_timeout = params.get("analysis_timeout", 300)
        output_format = params.get("output_format", "xml")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Ghidra called without binary parameter")
            return JSONResponse(content={"error": "Binary parameter is required"}, status_code=400)

        # Create Ghidra project directory
        project_dir = f"/tmp/ghidra_projects/{project_name}"
        os.makedirs(project_dir, exist_ok=True)

        # Base Ghidra command for headless analysis
        command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"

        if script_file:
            command += f" -postScript {script_file}"

        if output_format == "xml":
            command += f" -postScript ExportXml.java {project_dir}/analysis.xml"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Ghidra analysis: {binary}")
        result = execute_command(command, timeout=analysis_timeout)
        logger.info(f"📊 Ghidra analysis completed for {binary}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in ghidra endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/binwalk")
def binwalk(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Binwalk for firmware and file analysis with enhanced logging"""
    try:
        params = params or {}
        file_path = params.get("file_path", "")
        extract = params.get("extract", False)
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 Binwalk called without file_path parameter")
            return JSONResponse(content={
                "error": "File path parameter is required"
            }, status_code=400)

        command = f"binwalk"

        if extract:
            command += " -e"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting Binwalk analysis: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 Binwalk analysis completed for {file_path}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in binwalk endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/ropgadget")
def ropgadget(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Search for ROP gadgets in a binary using ROPgadget with enhanced logging"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 ROPgadget called without binary parameter")
            return JSONResponse(content={
                "error": "Binary parameter is required"
            }, status_code=400)

        command = f"ROPgadget --binary {binary}"

        if gadget_type:
            command += f" --only '{gadget_type}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting ROPgadget search: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ROPgadget search completed for {binary}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in ropgadget endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/ropper")
def ropper(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute ropper for advanced ROP/JOP gadget searching"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "rop")  # rop, jop, sys, all
        quality = params.get("quality", 1)  # 1-5, higher = better quality
        arch = params.get("arch", "")  # x86, x86_64, arm, etc.
        search_string = params.get("search_string", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 ropper called without binary parameter")
            return JSONResponse(content={"error": "Binary parameter is required"}, status_code=400)

        command = f"ropper --file {binary}"

        if gadget_type == "rop":
            command += " --rop"
        elif gadget_type == "jop":
            command += " --jop"
        elif gadget_type == "sys":
            command += " --sys"
        elif gadget_type == "all":
            command += " --all"

        if quality > 1:
            command += f" --quality {quality}"

        if arch:
            command += f" --arch {arch}"

        if search_string:
            command += f" --search '{search_string}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting ropper analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ropper analysis completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in ropper endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/one-gadget")
def one_gadget(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute one_gadget to find one-shot RCE gadgets in libc"""
    try:
        params = params or {}
        libc_path = params.get("libc_path", "")
        level = params.get("level", 1)  # 0, 1, 2 for different constraint levels
        additional_args = params.get("additional_args", "")

        if not libc_path:
            logger.warning("🔧 one_gadget called without libc_path parameter")
            return JSONResponse(content={"error": "libc_path parameter is required"}, status_code=400)

        command = f"one_gadget {libc_path} --level {level}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
        result = execute_command(command)
        logger.info(f"📊 one_gadget analysis completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in one_gadget endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/checksec")
def checksec(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Check security features of a binary with enhanced logging"""
    try:
        params = params or {}
        binary = params.get("binary", "")

        if not binary:
            logger.warning("🔧 Checksec called without binary parameter")
            return JSONResponse(content={
                "error": "Binary parameter is required"
            }, status_code=400)

        command = f"checksec --file={binary}"

        logger.info(f"🔧 Starting Checksec analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Checksec analysis completed for {binary}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in checksec endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/strings")
def strings(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Extract strings from a binary file with enhanced logging"""
    try:
        params = params or {}
        file_path = params.get("file_path", "")
        min_len = params.get("min_len", 4)
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 Strings called without file_path parameter")
            return JSONResponse(content={
                "error": "File path parameter is required"
            }, status_code=400)

        command = f"strings -n {min_len}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting Strings extraction: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 Strings extraction completed for {file_path}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in strings endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/objdump")
def objdump(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Analyze a binary using objdump with enhanced logging"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        disassemble = params.get("disassemble", True)
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Objdump called without binary parameter")
            return JSONResponse(content={
                "error": "Binary parameter is required"
            }, status_code=400)

        command = f"objdump"

        if disassemble:
            command += " -d"
        else:
            command += " -x"

        if additional_args:
            command += f" {additional_args}"

        command += f" {binary}"

        logger.info(f"🔧 Starting Objdump analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Objdump analysis completed for {binary}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in objdump endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/xxd")
def xxd(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Create a hex dump of a file using xxd with enhanced logging"""
    try:
        params = params or {}
        file_path = params.get("file_path", "")
        offset = params.get("offset", "0")
        length = params.get("length", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 XXD called without file_path parameter")
            return JSONResponse(content={
                "error": "File path parameter is required"
            }, status_code=400)

        command = f"xxd -s {offset}"

        if length:
            command += f" -l {length}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting XXD hex dump: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 XXD hex dump completed for {file_path}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in xxd endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/pwntools")
def pwntools(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Pwntools for exploit development and automation"""
    try:
        params = params or {}
        script_content = params.get("script_content", "")
        target_binary = params.get("target_binary", "")
        target_host = params.get("target_host", "")
        target_port = params.get("target_port", 0)
        exploit_type = params.get("exploit_type", "local")  # local, remote, format_string, rop
        additional_args = params.get("additional_args", "")

        if not script_content and not target_binary:
            logger.warning("🔧 Pwntools called without script content or target binary")
            return JSONResponse(content={"error": "Script content or target binary is required"}, status_code=400)

        # Create temporary Python script
        script_file = "/tmp/pwntools_exploit.py"

        if script_content:
            # Use provided script content
            with open(script_file, "w") as f:
                f.write(script_content)
        else:
            # Generate basic exploit template
            template = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
            with open(script_file, "w") as f:
                f.write(template)

        command = f"python3 {script_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Pwntools exploit: {exploit_type}")
        result = execute_command(command)

        # Cleanup
        try:
            os.remove(script_file)
        except:
            pass

        logger.info(f"📊 Pwntools exploit completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in pwntools endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/angr")
def angr(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute angr for symbolic execution and binary analysis"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        script_content = params.get("script_content", "")
        find_address = params.get("find_address", "")
        avoid_addresses = params.get("avoid_addresses", "")
        analysis_type = params.get("analysis_type", "symbolic")  # symbolic, cfg, static
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 angr called without binary parameter")
            return JSONResponse(content={"error": "Binary parameter is required"}, status_code=400)

        # Create angr script
        script_file = "/tmp/angr_analysis.py"

        if script_content:
            with open(script_file, "w") as f:
                f.write(script_content)
        else:
            # Generate basic angr template
            template = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
            if analysis_type == "symbolic":
                template += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
            elif analysis_type == "cfg":
                template += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""

            with open(script_file, "w") as f:
                f.write(template)

        command = f"python3 {script_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting angr analysis: {binary}")
        result = execute_command(command, timeout=600)  # Longer timeout for symbolic execution

        # Cleanup
        try:
            os.remove(script_file)
        except:
            pass

        logger.info(f"📊 angr analysis completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in angr endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/libc-database")
def libc_database(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute libc-database for libc identification and offset lookup"""
    try:
        params = params or {}
        action = params.get("action", "find")  # find, dump, download
        symbols = params.get("symbols", "")  # format: "symbol1:offset1 symbol2:offset2"
        libc_id = params.get("libc_id", "")
        additional_args = params.get("additional_args", "")

        if action == "find" and not symbols:
            logger.warning("🔧 libc-database find called without symbols")
            return JSONResponse(content={"error": "Symbols parameter is required for find action"}, status_code=400)

        if action in ["dump", "download"] and not libc_id:
            logger.warning("🔧 libc-database called without libc_id for dump/download")
            return JSONResponse(content={"error": "libc_id parameter is required for dump/download actions"}, status_code=400)

        # Navigate to libc-database directory (assuming it's installed)
        base_command = "cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo 'libc-database not found'"

        if action == "find":
            command = f"{base_command} && ./find {symbols}"
        elif action == "dump":
            command = f"{base_command} && ./dump {libc_id}"
        elif action == "download":
            command = f"{base_command} && ./download {libc_id}"
        else:
            return JSONResponse(content={"error": f"Invalid action: {action}"}, status_code=400)

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting libc-database {action}: {symbols or libc_id}")
        result = execute_command(command)
        logger.info(f"📊 libc-database {action} completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in libc-database endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/pwninit")
def pwninit(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute pwninit for CTF binary exploitation setup"""
    try:
        params = params or {}
        binary = params.get("binary", "")
        libc = params.get("libc", "")
        ld = params.get("ld", "")
        template_type = params.get("template_type", "python")  # python, c
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 pwninit called without binary parameter")
            return JSONResponse(content={"error": "Binary parameter is required"}, status_code=400)

        command = f"pwninit --bin {binary}"

        if libc:
            command += f" --libc {libc}"

        if ld:
            command += f" --ld {ld}"

        if template_type:
            command += f" --template {template_type}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting pwninit setup: {binary}")
        result = execute_command(command)
        logger.info(f"📊 pwninit setup completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in pwninit endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/msfvenom")
def msfvenom(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute MSFVenom to generate payloads with enhanced logging"""
    try:
        params = params or {}
        payload = params.get("payload", "")
        format_type = params.get("format", "")
        output_file = params.get("output_file", "")
        encoder = params.get("encoder", "")
        iterations = params.get("iterations", "")
        additional_args = params.get("additional_args", "")

        if not payload:
            logger.warning("🚀 MSFVenom called without payload parameter")
            return JSONResponse(content={
                "error": "Payload parameter is required"
            }, status_code=400)

        command = f"msfvenom -p {payload}"

        if format_type:
            command += f" -f {format_type}"

        if output_file:
            command += f" -o {output_file}"

        if encoder:
            command += f" -e {encoder}"

        if iterations:
            command += f" -i {iterations}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
        result = execute_command(command)
        logger.info(f"📊 MSFVenom payload generated")
        return result
    except Exception as e:
        logger.error(f"💥 Error in msfvenom endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/metasploit")
def metasploit(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute metasploit module with enhanced logging"""
    try:
        params = params or {}
        module = params.get("module", "")
        options = params.get("options", {})

        if not module:
            logger.warning("🚀 Metasploit called without module parameter")
            return JSONResponse(content={
                "error": "Module parameter is required"
            }, status_code=400)

        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = f"msfconsole -q -r {resource_file}"

        logger.info(f"🚀 Starting Metasploit module: {module}")
        result = execute_command(command)

        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")

        logger.info(f"📊 Metasploit module completed: {module}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in metasploit endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)



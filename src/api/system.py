#!/usr/bin/env python3
"""
HexStrike AI - Core System, Cache, Files & Visual Engine API Endpoints
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

router = MultiTargetAPIRouter(tags=["Core System, Cache, Files & Visual Engine"])

@router.get("/health")
def health_check():
    """Health check endpoint with comprehensive tool detection"""

    essential_tools = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "hashcat"
    ]

    network_tools = [
        "rustscan", "masscan", "autorecon", "nbtscan", "arp-scan", "responder",
        "nxc", "enum4linux-ng", "rpcclient", "enum4linux"
    ]

    web_security_tools = [
        "ffuf", "feroxbuster", "dirsearch", "dotdotpwn", "xsser", "wfuzz",
        "gau", "waybackurls", "arjun", "paramspider", "x8", "jaeles", "dalfox",
        "httpx", "wafw00f", "burpsuite", "zaproxy", "katana", "hakrawler"
    ]

    vuln_scanning_tools = [
        "nuclei", "wpscan", "graphql-scanner", "jwt-analyzer"
    ]

    password_tools = [
        "medusa", "patator", "hash-identifier", "ophcrack", "hashcat-utils"
    ]

    binary_tools = [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "ghidra", "pwntools", "one-gadget", "ropper", "angr", "libc-database",
        "pwninit"
    ]

    forensics_tools = [
        "volatility3", "vol", "steghide", "hashpump", "foremost", "exiftool",
        "strings", "xxd", "file", "photorec", "testdisk", "scalpel", "bulk-extractor",
        "stegsolve", "zsteg", "outguess"
    ]

    cloud_tools = [
        "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
        "docker-bench-security", "checkov", "terrascan", "falco", "clair"
    ]

    osint_tools = [
        "amass", "subfinder", "fierce", "dnsenum", "theharvester", "sherlock",
        "social-analyzer", "recon-ng", "maltego", "spiderfoot", "shodan-cli",
        "censys-cli", "have-i-been-pwned"
    ]

    exploitation_tools = [
        "metasploit", "exploit-db", "searchsploit"
    ]

    api_tools = [
        "api-schema-analyzer", "postman", "insomnia", "curl", "httpie", "anew", "qsreplace", "uro"
    ]

    wireless_tools = [
        "kismet", "wireshark", "tshark", "tcpdump"
    ]

    additional_tools = [
        "smbmap", "volatility", "sleuthkit", "autopsy", "evil-winrm",
        "paramspider", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
        "msfvenom", "msfconsole", "graphql-scanner", "jwt-analyzer"
    ]

    all_tools = (
        essential_tools + network_tools + web_security_tools + vuln_scanning_tools +
        password_tools + binary_tools + forensics_tools + cloud_tools +
        osint_tools + exploitation_tools + api_tools + wireless_tools + additional_tools
    )
    tools_status = {}

    for tool in all_tools:
        try:
            tools_status[tool] = tool_registry.is_tool_installed(tool)
        except Exception:
            tools_status[tool] = False

    registry_report = tool_registry.get_registry_report()
    manifest_summary = registry_report.get("summary", {})
    all_essential_tools_available = manifest_summary.get(
        "all_essential_installed",
        all(tools_status.get(tool, False) for tool in essential_tools),
    )

    category_stats = {
        "essential": {"total": len(essential_tools), "available": sum(1 for tool in essential_tools if tools_status.get(tool, False))},
        "network": {"total": len(network_tools), "available": sum(1 for tool in network_tools if tools_status.get(tool, False))},
        "web_security": {"total": len(web_security_tools), "available": sum(1 for tool in web_security_tools if tools_status.get(tool, False))},
        "vuln_scanning": {"total": len(vuln_scanning_tools), "available": sum(1 for tool in vuln_scanning_tools if tools_status.get(tool, False))},
        "password": {"total": len(password_tools), "available": sum(1 for tool in password_tools if tools_status.get(tool, False))},
        "binary": {"total": len(binary_tools), "available": sum(1 for tool in binary_tools if tools_status.get(tool, False))},
        "forensics": {"total": len(forensics_tools), "available": sum(1 for tool in forensics_tools if tools_status.get(tool, False))},
        "cloud": {"total": len(cloud_tools), "available": sum(1 for tool in cloud_tools if tools_status.get(tool, False))},
        "osint": {"total": len(osint_tools), "available": sum(1 for tool in osint_tools if tools_status.get(tool, False))},
        "exploitation": {"total": len(exploitation_tools), "available": sum(1 for tool in exploitation_tools if tools_status.get(tool, False))},
        "api": {"total": len(api_tools), "available": sum(1 for tool in api_tools if tools_status.get(tool, False))},
        "wireless": {"total": len(wireless_tools), "available": sum(1 for tool in wireless_tools if tools_status.get(tool, False))},
        "additional": {"total": len(additional_tools), "available": sum(1 for tool in additional_tools if tools_status.get(tool, False))}
    }

    return {
        "status": "healthy",
        "message": "HexStrike AI Tools API Server is operational",
        "version": "6.0.0",
        "active_profile": registry_report.get("active_profile", "recon_network_scan"),
        "manifest_summary": manifest_summary,
        "storage_volumes": registry_report.get("storage_volumes", {}),
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "total_tools_available": sum(1 for tool, available in tools_status.items() if available),
        "total_tools_count": len(all_tools),
        "category_stats": category_stats,
        "cache_stats": cache.get_stats(),
        "telemetry": telemetry.get_stats(),
        "uptime": time.time() - telemetry.stats["start_time"]
    }


@router.get("/api/tools/available")
def list_available_tools(
    category: str = Query(default="", description="Filter by category (network, reconnaissance, scanning, web, auth, binary, forensics, cloud)"),
    installed_only: bool = Query(default=False, description="Return only installed tools"),
    enabled_only: bool = Query(default=False, description="Return only tools enabled in config/tools_manifest.json"),
    profile: str = Query(default="", description="Filter by container build profile"),
    refresh: bool = Query(default=False, description="Force rescan of system binaries"),
):
    """Get the list of configured and installed tools from the manifest along with MCP tool mappings."""
    try:
        return tool_registry.get_registry_report(
            category=category or None,
            installed_only=installed_only,
            enabled_only=enabled_only,
            profile=profile or None,
            refresh=refresh,
        )
    except Exception as e:
        logger.error(f"💥 Error listing available tools: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/tools/profiles")
def list_tool_profiles(refresh: bool = Query(default=False)):
    """List container build profiles (minimal, recon_network_scan, web_security, full, etc.) and their tools."""
    try:
        return tool_registry.get_profiles(refresh=refresh)
    except Exception as e:
        logger.error(f"💥 Error listing tool profiles: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/tools/check/{tool_name}")
@router.get("/api/tools/check")
def check_tool_availability_endpoint(
    tool_name: str = "",
    refresh: bool = Query(default=False),
):
    """Check whether a specific CLI tool or MCP tool is installed and return available alternatives."""
    try:
        if not tool_name:
            return JSONResponse(content={"error": "tool_name is required"}, status_code=400)
        return tool_registry.check_tool(tool_name, refresh=refresh)
    except Exception as e:
        logger.error(f"💥 Error checking tool availability: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/command")
def generic_command(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute any command provided in the request with enhanced logging"""
    try:
        params = params or {}
        command = params.get("command", "")
        use_cache = params.get("use_cache", True)

        if not command:
            logger.warning("⚠️  Command endpoint called without command parameter")
            return JSONResponse(content={
                "error": "Command parameter is required"
            }, status_code=400)

        result = execute_command(command, use_cache=use_cache)
        return result
    except Exception as e:
        logger.error(f"💥 Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/files/create")
def create_file(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Create a new file"""
    try:
        params = params or {}
        filename = params.get("filename", "")
        content = params.get("content", "")
        binary = params.get("binary", False)

        if not filename:
            return JSONResponse(content={"error": "Filename is required"}, status_code=400)

        result = file_manager.create_file(filename, content, binary)
        return result
    except Exception as e:
        logger.error(f"💥 Error creating file: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/files/modify")
def modify_file(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Modify an existing file"""
    try:
        params = params or {}
        filename = params.get("filename", "")
        content = params.get("content", "")
        append = params.get("append", False)

        if not filename:
            return JSONResponse(content={"error": "Filename is required"}, status_code=400)

        result = file_manager.modify_file(filename, content, append)
        return result
    except Exception as e:
        logger.error(f"💥 Error modifying file: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.delete("/api/files/delete")
@router.post("/api/files/delete")
def delete_file(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Delete a file or directory"""
    try:
        params = params or {}
        filename = params.get("filename", "")

        if not filename:
            return JSONResponse(content={"error": "Filename is required"}, status_code=400)

        result = file_manager.delete_file(filename)
        return result
    except Exception as e:
        logger.error(f"💥 Error deleting file: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/files/list")
def list_files(directory: str = Query(default=".")):
    """List files in a directory"""
    try:
        result = file_manager.list_files(directory)
        return result
    except Exception as e:
        logger.error(f"💥 Error listing files: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/payloads/generate")
def generate_payload(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Generate large payloads for testing"""
    try:
        params = params or {}
        payload_type = params.get("type", "buffer")
        size = params.get("size", 1024)
        pattern = params.get("pattern", "A")
        filename = params.get("filename", f"payload_{int(time.time())}")

        if size > 100 * 1024 * 1024:  # 100MB limit
            return JSONResponse(content={"error": "Payload size too large (max 100MB)"}, status_code=400)

        if payload_type == "buffer":
            content = pattern * (size // len(pattern))
        elif payload_type == "cyclic":
            # Generate cyclic pattern
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            content = ""
            for i in range(size):
                content += alphabet[i % len(alphabet)]
        elif payload_type == "random":
            import random
            import string
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        else:
            return JSONResponse(content={"error": "Invalid payload type"}, status_code=400)

        result = file_manager.create_file(filename, content)
        result["payload_info"] = {
            "type": payload_type,
            "size": size,
            "pattern": pattern
        }

        logger.info(f"🎯 Generated {payload_type} payload: {filename} ({size} bytes)")
        return result
    except Exception as e:
        logger.error(f"💥 Error generating payload: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/cache/stats")
def cache_stats():
    """Get cache statistics"""
    return cache.get_stats()


@router.post("/api/cache/clear")
def clear_cache():
    """Clear the cache"""
    cache.cache.clear()
    cache.stats = {"hits": 0, "misses": 0, "evictions": 0}
    logger.info("🧹 Cache cleared")
    return {"success": True, "message": "Cache cleared"}


@router.get("/api/telemetry")
def get_telemetry():
    """Get system telemetry"""
    return telemetry.get_stats()


@router.post("/api/visual/vulnerability-card")
def create_vulnerability_card(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create a beautiful vulnerability card using ModernVisualEngine"""
    try:
        if not data:
            return JSONResponse(content={"error": "No data provided"}, status_code=400)

        # Create vulnerability card
        card = ModernVisualEngine.render_vulnerability_card(data)

        return {
            "success": True,
            "vulnerability_card": card,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability card: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/visual/summary-report")
def create_summary_report(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create a beautiful summary report using ModernVisualEngine"""
    try:
        if not data:
            return JSONResponse(content={"error": "No data provided"}, status_code=400)

        # Create summary report
        visual_engine = ModernVisualEngine()
        report = visual_engine.create_summary_report(data)

        return {
            "success": True,
            "summary_report": report,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating summary report: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/visual/tool-output")
def format_tool_output(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Format tool output using ModernVisualEngine"""
    try:
        if not data or 'tool' not in data or 'output' not in data:
            return JSONResponse(content={"error": "Tool and output data required"}, status_code=400)

        tool = data['tool']
        output = data['output']
        success = data.get('success', True)

        # Format tool output
        formatted_output = ModernVisualEngine.format_tool_output(tool, output, success)

        return {
            "success": True,
            "formatted_output": formatted_output,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error formatting tool output: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/python/install")
def install_python_package(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Install a Python package in a virtual environment"""
    try:
        params = params or {}
        package = params.get("package", "")
        env_name = params.get("env_name", "default")

        if not package:
            return JSONResponse(content={"error": "Package name is required"}, status_code=400)

        logger.info(f"📦 Installing Python package: {package} in env {env_name}")
        success = env_manager.install_package(env_name, package)

        if success:
            return {
                "success": True,
                "message": f"Package {package} installed successfully",
                "env_name": env_name
            }
        else:
            return JSONResponse(content={
                "success": False,
                "error": f"Failed to install package {package}"
            }, status_code=500)

    except Exception as e:
        logger.error(f"💥 Error installing Python package: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/python/execute")
def execute_python_script(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute a Python script in a virtual environment"""
    try:
        params = params or {}
        script = params.get("script", "")
        env_name = params.get("env_name", "default")
        filename = params.get("filename", f"script_{int(time.time())}.py")

        if not script:
            return JSONResponse(content={"error": "Script content is required"}, status_code=400)

        # Create script file
        script_result = file_manager.create_file(filename, script)
        if not script_result["success"]:
            return JSONResponse(content=script_result, status_code=500)

        # Get Python path for environment
        python_path = env_manager.get_python_path(env_name)
        script_path = script_result["path"]

        # Execute script
        command = f"{python_path} {script_path}"
        logger.info(f"🐍 Executing Python script in env {env_name}: {filename}")
        result = execute_command(command, use_cache=False)

        # Clean up script file
        file_manager.delete_file(filename)

        result["env_name"] = env_name
        result["script_filename"] = filename
        logger.info(f"📊 Python script execution completed")
        return result

    except Exception as e:
        logger.error(f"💥 Error executing Python script: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/error-handling/statistics")
def get_error_statistics():
    """Get error handling statistics"""
    try:
        stats = error_handler.get_error_statistics()
        return {
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting error statistics: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/error-handling/test-recovery")
def test_error_recovery(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Test error recovery system with simulated failures"""
    try:
        data = data or {}
        tool_name = data.get("tool_name", "nmap")
        error_type = data.get("error_type", "timeout")
        target = data.get("target", "example.com")

        # Simulate an error for testing
        if error_type == "timeout":
            exception = TimeoutError("Simulated timeout error")
        elif error_type == "permission_denied":
            exception = PermissionError("Simulated permission error")
        elif error_type == "network_unreachable":
            exception = ConnectionError("Simulated network error")
        else:
            exception = Exception(f"Simulated {error_type} error")

        context = {
            "target": target,
            "parameters": data.get("parameters", {}),
            "attempt_count": 1
        }

        # Get recovery strategy
        recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)

        return {
            "success": True,
            "recovery_strategy": {
                "action": recovery_strategy.action.value,
                "parameters": recovery_strategy.parameters,
                "max_attempts": recovery_strategy.max_attempts,
                "success_probability": recovery_strategy.success_probability,
                "estimated_time": recovery_strategy.estimated_time
            },
            "error_classification": error_handler.classify_error(str(exception), exception).value,
            "alternative_tools": error_handler.tool_alternatives.get(tool_name, []),
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error testing recovery system: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/error-handling/fallback-chains")
def get_fallback_chains(operation: str = Query(default=""), failed_tools: List[str] = Query(default=[])):
    """Get available fallback tool chains"""
    try:

        if operation:
            fallback_chain = degradation_manager.create_fallback_chain(operation, failed_tools)
            return {
                "success": True,
                "operation": operation,
                "fallback_chain": fallback_chain,
                "is_critical": degradation_manager.is_critical_operation(operation),
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": True,
                "available_operations": list(degradation_manager.fallback_chains.keys()),
                "critical_operations": list(degradation_manager.critical_operations),
                "timestamp": datetime.now().isoformat()
            }

    except Exception as e:
        logger.error(f"Error getting fallback chains: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/error-handling/execute-with-recovery")
def execute_with_recovery_endpoint(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute a command with intelligent error handling and recovery"""
    try:
        data = data or {}
        tool_name = data.get("tool_name", "")
        command = data.get("command", "")
        parameters = data.get("parameters", {})
        max_attempts = data.get("max_attempts", 3)
        use_cache = data.get("use_cache", True)

        if not tool_name or not command:
            return JSONResponse(content={"error": "tool_name and command are required"}, status_code=400)

        # Execute command with recovery
        result = execute_command_with_recovery(
            tool_name=tool_name,
            command=command,
            parameters=parameters,
            use_cache=use_cache,
            max_attempts=max_attempts
        )

        return {
            "success": result.get("success", False),
            "result": result,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error executing command with recovery: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/error-handling/classify-error")
def classify_error_endpoint(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Classify an error message"""
    try:
        data = data or {}
        error_message = data.get("error_message", "")

        if not error_message:
            return JSONResponse(content={"error": "error_message is required"}, status_code=400)

        error_type = error_handler.classify_error(error_message)
        recovery_strategies = error_handler.recovery_strategies.get(error_type, [])

        return {
            "success": True,
            "error_type": error_type.value,
            "recovery_strategies": [
                {
                    "action": strategy.action.value,
                    "parameters": strategy.parameters,
                    "success_probability": strategy.success_probability,
                    "estimated_time": strategy.estimated_time
                }
                for strategy in recovery_strategies
            ],
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error classifying error: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/error-handling/parameter-adjustments")
def get_parameter_adjustments(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Get parameter adjustments for a tool and error type"""
    try:
        data = data or {}
        tool_name = data.get("tool_name", "")
        error_type_str = data.get("error_type", "")
        original_params = data.get("original_params", {})

        if not tool_name or not error_type_str:
            return JSONResponse(content={"error": "tool_name and error_type are required"}, status_code=400)

        # Convert string to ErrorType enum
        try:
            error_type = ErrorType(error_type_str)
        except ValueError:
            return JSONResponse(content={"error": f"Invalid error_type: {error_type_str}"}, status_code=400)

        adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, original_params)

        return {
            "success": True,
            "tool_name": tool_name,
            "error_type": error_type.value,
            "original_params": original_params,
            "adjusted_params": adjusted_params,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error getting parameter adjustments: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.get("/api/error-handling/alternative-tools")
def get_alternative_tools(tool_name: str = Query(default="")):
    """Get alternative tools for a given tool"""
    try:

        if not tool_name:
            return JSONResponse(content={"error": "tool_name parameter is required"}, status_code=400)

        alternatives = error_handler.tool_alternatives.get(tool_name, [])

        return {
            "success": True,
            "tool_name": tool_name,
            "alternatives": alternatives,
            "has_alternatives": len(alternatives) > 0,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error getting alternative tools: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)



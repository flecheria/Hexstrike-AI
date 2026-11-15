#!/usr/bin/env python3
"""
HexStrike AI - Network Reconnaissance & Scanning API Endpoints
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

router = MultiTargetAPIRouter(tags=["Network Reconnaissance & Scanning"])

@router.post("/api/tools/nmap")
def nmap(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute nmap scan with enhanced logging, caching, and intelligent error handling"""
    try:
        params = params or {}
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        use_recovery = params.get("use_recovery", True)

        if not target:
            logger.warning("🎯 Nmap called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"nmap {scan_type}"

        if ports:
            command += f" -p {ports}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        logger.info(f"🔍 Starting Nmap scan: {target}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "scan_type": scan_type,
                "ports": ports,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nmap", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Nmap scan completed for {target}")
        return result

    except Exception as e:
        logger.error(f"💥 Error in nmap endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/nmap-advanced")
def nmap_advanced(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute advanced Nmap scans with custom NSE scripts and optimized timing"""
    try:
        params = params or {}
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sS")
        ports = params.get("ports", "")
        timing = params.get("timing", "T4")
        nse_scripts = params.get("nse_scripts", "")
        os_detection = params.get("os_detection", False)
        version_detection = params.get("version_detection", False)
        aggressive = params.get("aggressive", False)
        stealth = params.get("stealth", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Advanced Nmap called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"nmap {scan_type} {target}"

        if ports:
            command += f" -p {ports}"

        if stealth:
            command += " -T2 -f --mtu 24"
        else:
            command += f" -{timing}"

        if os_detection:
            command += " -O"

        if version_detection:
            command += " -sV"

        if aggressive:
            command += " -A"

        if nse_scripts:
            command += f" --script={nse_scripts}"
        elif not aggressive:  # Default useful scripts if not aggressive
            command += " --script=default,discovery,safe"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Advanced Nmap: {target}")
        result = execute_command(command)
        logger.info(f"📊 Advanced Nmap completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in advanced nmap endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/rustscan")
def rustscan(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Rustscan for ultra-fast port scanning with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        ports = params.get("ports", "")
        ulimit = params.get("ulimit", 5000)
        batch_size = params.get("batch_size", 4500)
        timeout = params.get("timeout", 1500)
        scripts = params.get("scripts", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Rustscan called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"rustscan -a {target} --ulimit {ulimit} -b {batch_size} -t {timeout}"

        if ports:
            command += f" -p {ports}"

        if scripts:
            command += f" -- -sC -sV"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚡ Starting Rustscan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Rustscan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in rustscan endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/masscan")
def masscan(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting"""
    try:
        params = params or {}
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        rate = params.get("rate", 1000)
        interface = params.get("interface", "")
        router_mac = params.get("router_mac", "")
        source_ip = params.get("source_ip", "")
        banners = params.get("banners", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Masscan called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"masscan {target} -p{ports} --rate={rate}"

        if interface:
            command += f" -e {interface}"

        if router_mac:
            command += f" --router-mac {router_mac}"

        if source_ip:
            command += f" --source-ip {source_ip}"

        if banners:
            command += " --banners"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
        result = execute_command(command)
        logger.info(f"📊 Masscan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in masscan endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/autorecon")
def autorecon(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute AutoRecon for comprehensive automated reconnaissance"""
    try:
        params = params or {}
        target = params.get("target", "")
        output_dir = params.get("output_dir", "/tmp/autorecon")
        port_scans = params.get("port_scans", "top-100-ports")
        service_scans = params.get("service_scans", "default")
        heartbeat = params.get("heartbeat", 60)
        timeout = params.get("timeout", 300)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 AutoRecon called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"autorecon {target} -o {output_dir} --heartbeat {heartbeat} --timeout {timeout}"

        if port_scans != "default":
            command += f" --port-scans {port_scans}"

        if service_scans != "default":
            command += f" --service-scans {service_scans}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔄 Starting AutoRecon: {target}")
        result = execute_command(command)
        logger.info(f"📊 AutoRecon completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in autorecon endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/amass")
def amass(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Amass for subdomain enumeration with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        mode = params.get("mode", "enum")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Amass called without domain parameter")
            return JSONResponse(content={
                "error": "Domain parameter is required"
            }, status_code=400)

        command = f"amass {mode}"

        if mode == "enum":
            command += f" -d {domain}"
        else:
            command += f" -d {domain}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Amass completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in amass endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/subfinder")
def subfinder(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Subfinder for passive subdomain enumeration with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        silent = params.get("silent", True)
        all_sources = params.get("all_sources", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Subfinder called without domain parameter")
            return JSONResponse(content={
                "error": "Domain parameter is required"
            }, status_code=400)

        command = f"subfinder -d {domain}"

        if silent:
            command += " -silent"

        if all_sources:
            command += " -all"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Subfinder: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Subfinder completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in subfinder endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/fierce")
def fierce(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute fierce for DNS reconnaissance with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Fierce called without domain parameter")
            return JSONResponse(content={
                "error": "Domain parameter is required"
            }, status_code=400)

        command = f"fierce --domain {domain}"

        if dns_server:
            command += f" --dns-servers {dns_server}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Fierce completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in fierce endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/dnsenum")
def dnsenum(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute dnsenum for DNS enumeration with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 DNSenum called without domain parameter")
            return JSONResponse(content={
                "error": "Domain parameter is required"
            }, status_code=400)

        command = f"dnsenum {domain}"

        if dns_server:
            command += f" --dnsserver {dns_server}"

        if wordlist:
            command += f" --file {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting DNSenum: {domain}")
        result = execute_command(command)
        logger.info(f"📊 DNSenum completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in dnsenum endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/arp-scan")
def arp_scan(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute arp-scan for network discovery with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        interface = params.get("interface", "")
        local_network = params.get("local_network", False)
        timeout = params.get("timeout", 500)
        retry = params.get("retry", 3)
        additional_args = params.get("additional_args", "")

        if not target and not local_network:
            logger.warning("🎯 arp-scan called without target parameter")
            return JSONResponse(content={"error": "Target parameter or local_network flag is required"}, status_code=400)

        command = f"arp-scan -t {timeout} -r {retry}"

        if interface:
            command += f" -I {interface}"

        if local_network:
            command += " -l"
        else:
            command += f" {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = execute_command(command)
        logger.info(f"📊 arp-scan completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in arp-scan endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/nbtscan")
def nbtscan(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute nbtscan for NetBIOS name scanning with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        verbose = params.get("verbose", False)
        timeout = params.get("timeout", 2)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 nbtscan called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"nbtscan -t {timeout}"

        if verbose:
            command += " -v"

        command += f" {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting nbtscan: {target}")
        result = execute_command(command)
        logger.info(f"📊 nbtscan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in nbtscan endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/rpcclient")
def rpcclient(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute rpcclient for RPC enumeration with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        commands = params.get("commands", "enumdomusers;enumdomgroups;querydominfo")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 rpcclient called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        # Build authentication string
        auth_string = ""
        if username and password:
            auth_string = f"-U {username}%{password}"
        elif username:
            auth_string = f"-U {username}"
        else:
            auth_string = "-U ''"  # Anonymous

        if domain:
            auth_string += f" -W {domain}"

        # Create command sequence
        command_sequence = commands.replace(";", "\n")

        command = f"echo -e '{command_sequence}' | rpcclient {auth_string} {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting rpcclient: {target}")
        result = execute_command(command)
        logger.info(f"📊 rpcclient completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in rpcclient endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/enum4linux")
def enum4linux(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute enum4linux with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("🎯 Enum4linux called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"enum4linux {additional_args} {target}"

        logger.info(f"🔍 Starting Enum4linux: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in enum4linux endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/enum4linux-ng")
def enum4linux_ng(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        shares = params.get("shares", True)
        users = params.get("users", True)
        groups = params.get("groups", True)
        policy = params.get("policy", True)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Enum4linux-ng called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"enum4linux-ng {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if domain:
            command += f" -d {domain}"

        # Add specific enumeration options
        enum_options = []
        if shares:
            enum_options.append("S")
        if users:
            enum_options.append("U")
        if groups:
            enum_options.append("G")
        if policy:
            enum_options.append("P")

        if enum_options:
            command += f" -A {','.join(enum_options)}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Enum4linux-ng: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux-ng completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in enum4linux-ng endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/smbmap")
def smbmap(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute SMBMap for SMB share enumeration with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 SMBMap called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"smbmap -H {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if domain:
            command += f" -d {domain}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting SMBMap: {target}")
        result = execute_command(command)
        logger.info(f"📊 SMBMap completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in smbmap endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/responder")
def responder(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Responder for credential harvesting with enhanced logging"""
    try:
        params = params or {}
        interface = params.get("interface", "eth0")
        analyze = params.get("analyze", False)
        wpad = params.get("wpad", True)
        force_wpad_auth = params.get("force_wpad_auth", False)
        fingerprint = params.get("fingerprint", False)
        duration = params.get("duration", 300)  # 5 minutes default
        additional_args = params.get("additional_args", "")

        if not interface:
            logger.warning("🎯 Responder called without interface parameter")
            return JSONResponse(content={"error": "Interface parameter is required"}, status_code=400)

        command = f"timeout {duration} responder -I {interface}"

        if analyze:
            command += " -A"

        if wpad:
            command += " -w"

        if force_wpad_auth:
            command += " -F"

        if fingerprint:
            command += " -f"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Responder on interface: {interface}")
        result = execute_command(command)
        logger.info(f"📊 Responder completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in responder endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/netexec")
def netexec(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute NetExec (formerly CrackMapExec) with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        protocol = params.get("protocol", "smb")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_value = params.get("hash", "")
        module = params.get("module", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 NetExec called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"nxc {protocol} {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if hash_value:
            command += f" -H {hash_value}"

        if module:
            command += f" -M {module}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting NetExec {protocol} scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 NetExec scan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in netexec endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)



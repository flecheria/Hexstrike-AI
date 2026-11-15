#!/usr/bin/env python3
"""
HexStrike AI - Web Application Security Testing API Endpoints
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

router = MultiTargetAPIRouter(tags=["Web Application Security Testing"])

@router.post("/api/tools/gobuster")
def gobuster(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute gobuster with enhanced logging and intelligent error handling"""
    try:
        params = params or {}
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)

        if not url:
            logger.warning("🌐 Gobuster called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"❌ Invalid gobuster mode: {mode}")
            return JSONResponse(content={
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }, status_code=400)

        command = f"gobuster {mode} -u {url} -w {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Gobuster {mode} scan: {url}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": url,
                "mode": mode,
                "wordlist": wordlist,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("gobuster", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Gobuster scan completed for {url}")
        return result

    except Exception as e:
        logger.error(f"💥 Error in gobuster endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/dirsearch")
def dirsearch(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Dirsearch for advanced directory and file discovery with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        extensions = params.get("extensions", "php,html,js,txt,xml,json")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirsearch/common.txt")
        threads = params.get("threads", 30)
        recursive = params.get("recursive", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirsearch called without URL parameter")
            return JSONResponse(content={"error": "URL parameter is required"}, status_code=400)

        command = f"dirsearch -u {url} -e {extensions} -w {wordlist} -t {threads}"

        if recursive:
            command += " -r"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirsearch scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in dirsearch endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/feroxbuster")
def feroxbuster(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Feroxbuster called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"feroxbuster -u {url} -w {wordlist} -t {threads}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Feroxbuster scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Feroxbuster scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in feroxbuster endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/ffuf")
def ffuf(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute FFuf web fuzzer with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = params.get("mode", "directory")
        match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 FFuf called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"ffuf"

        if mode == "directory":
            command += f" -u {url}/FUZZ -w {wordlist}"
        elif mode == "vhost":
            command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
        elif mode == "parameter":
            command += f" -u {url}?FUZZ=value -w {wordlist}"
        else:
            command += f" -u {url} -w {wordlist}"

        command += f" -mc {match_codes}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = execute_command(command)
        logger.info(f"📊 FFuf fuzzing completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in ffuf endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/dirb")
def dirb(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute dirb with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirb called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"dirb {url} {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirb scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirb scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in dirb endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/httpx")
def httpx(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute httpx for fast HTTP probing and technology detection"""
    try:
        params = params or {}
        target = params.get("target", "")
        probe = params.get("probe", True)
        tech_detect = params.get("tech_detect", False)
        status_code = params.get("status_code", False)
        content_length = params.get("content_length", False)
        title = params.get("title", False)
        web_server = params.get("web_server", False)
        threads = params.get("threads", 50)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🌐 httpx called without target parameter")
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        command = f"httpx -l {target} -t {threads}"

        if probe:
            command += " -probe"

        if tech_detect:
            command += " -tech-detect"

        if status_code:
            command += " -sc"

        if content_length:
            command += " -cl"

        if title:
            command += " -title"

        if web_server:
            command += " -server"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🌍 Starting httpx probe: {target}")
        result = execute_command(command)
        logger.info(f"📊 httpx probe completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in httpx endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/katana")
def katana(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Katana for next-generation crawling and spidering with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        depth = params.get("depth", 3)
        js_crawl = params.get("js_crawl", True)
        form_extraction = params.get("form_extraction", True)
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Katana called without URL parameter")
            return JSONResponse(content={"error": "URL parameter is required"}, status_code=400)

        command = f"katana -u {url} -d {depth}"

        if js_crawl:
            command += " -jc"

        if form_extraction:
            command += " -fx"

        if output_format == "json":
            command += " -jsonl"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚔️  Starting Katana crawl: {url}")
        result = execute_command(command)
        logger.info(f"📊 Katana crawl completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in katana endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/hakrawler")
def hakrawler(params: Optional[Dict[str, Any]] = Body(default=None)):
    """
    Execute Hakrawler for web endpoint discovery with enhanced logging

    Note: This implementation uses the standard Kali Linux hakrawler (hakluke/hakrawler)
    command line arguments, NOT the Elsfa7-110 fork. The standard version uses:
    - echo URL | hakrawler (stdin input)
    - -d for depth (not -depth)
    - -s for showing sources (not -forms)
    - -u for unique URLs
    - -subs for subdomain inclusion
    """
    try:
        params = params or {}
        url = params.get("url", "")
        depth = params.get("depth", 2)
        forms = params.get("forms", True)
        robots = params.get("robots", True)
        sitemap = params.get("sitemap", True)
        wayback = params.get("wayback", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🕷️ Hakrawler called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        # Build command for standard Kali Linux hakrawler (hakluke version)
        command = f"echo '{url}' | hakrawler -d {depth}"

        if forms:
            command += " -s"  # Show sources (includes forms)
        if robots or sitemap or wayback:
            command += " -subs"  # Include subdomains for better coverage

        # Add unique URLs flag for cleaner output
        command += " -u"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = execute_command(command)
        logger.info(f"📊 Hakrawler crawling completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in hakrawler endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/gau")
def gau(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        providers = params.get("providers", "wayback,commoncrawl,otx,urlscan")
        include_subs = params.get("include_subs", True)
        blacklist = params.get("blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Gau called without domain parameter")
            return JSONResponse(content={"error": "Domain parameter is required"}, status_code=400)

        command = f"gau {domain}"

        if providers != "wayback,commoncrawl,otx,urlscan":
            command += f" --providers {providers}"

        if include_subs:
            command += " --subs"

        if blacklist:
            command += f" --blacklist {blacklist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📡 Starting Gau URL discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Gau URL discovery completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in gau endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/waybackurls")
def waybackurls(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Waybackurls for historical URL discovery with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        get_versions = params.get("get_versions", False)
        no_subs = params.get("no_subs", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Waybackurls called without domain parameter")
            return JSONResponse(content={"error": "Domain parameter is required"}, status_code=400)

        command = f"waybackurls {domain}"

        if get_versions:
            command += " --get-versions"

        if no_subs:
            command += " --no-subs"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Waybackurls discovery completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in waybackurls endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/nuclei")
def nuclei(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling"""
    try:
        params = params or {}
        target = params.get("target", "")
        severity = params.get("severity", "")
        tags = params.get("tags", "")
        template = params.get("template", "")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)

        if not target:
            logger.warning("🎯 Nuclei called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"nuclei -u {target}"

        if severity:
            command += f" -severity {severity}"

        if tags:
            command += f" -tags {tags}"

        if template:
            command += f" -t {template}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nuclei vulnerability scan: {target}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nuclei", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Nuclei scan completed for {target}")
        return result

    except Exception as e:
        logger.error(f"💥 Error in nuclei endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/nikto")
def nikto(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute nikto with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Nikto called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"nikto -h {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Nikto scan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in nikto endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/sqlmap")
def sqlmap(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute sqlmap with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"sqlmap -u {url} --batch"

        if data:
            command += f" --data=\"{data}\""

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/wpscan")
def wpscan(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute wpscan with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 WPScan called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"wpscan --url {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting WPScan: {url}")
        result = execute_command(command)
        logger.info(f"📊 WPScan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in wpscan endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/arjun")
def arjun(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Arjun for HTTP parameter discovery with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        method = params.get("method", "GET")
        wordlist = params.get("wordlist", "")
        delay = params.get("delay", 0)
        threads = params.get("threads", 25)
        stable = params.get("stable", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Arjun called without URL parameter")
            return JSONResponse(content={"error": "URL parameter is required"}, status_code=400)

        command = f"arjun -u {url} -m {method} -t {threads}"

        if wordlist:
            command += f" -w {wordlist}"

        if delay > 0:
            command += f" -d {delay}"

        if stable:
            command += " --stable"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🎯 Starting Arjun parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 Arjun parameter discovery completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in arjun endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/paramspider")
def paramspider(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute ParamSpider for parameter mining from web archives with enhanced logging"""
    try:
        params = params or {}
        domain = params.get("domain", "")
        level = params.get("level", 2)
        exclude = params.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        output = params.get("output", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 ParamSpider called without domain parameter")
            return JSONResponse(content={"error": "Domain parameter is required"}, status_code=400)

        command = f"paramspider -d {domain} -l {level}"

        if exclude:
            command += f" --exclude {exclude}"

        if output:
            command += f" -o {output}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = execute_command(command)
        logger.info(f"📊 ParamSpider mining completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in paramspider endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/x8")
def x8(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute x8 for hidden parameter discovery with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/x8/params.txt")
        method = params.get("method", "GET")
        body = params.get("body", "")
        headers = params.get("headers", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 x8 called without URL parameter")
            return JSONResponse(content={"error": "URL parameter is required"}, status_code=400)

        command = f"x8 -u {url} -w {wordlist} -X {method}"

        if body:
            command += f" -b '{body}'"

        if headers:
            command += f" -H '{headers}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 x8 parameter discovery completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in x8 endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/jaeles")
def jaeles(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Jaeles for advanced vulnerability scanning with custom signatures"""
    try:
        params = params or {}
        url = params.get("url", "")
        signatures = params.get("signatures", "")
        config = params.get("config", "")
        threads = params.get("threads", 20)
        timeout = params.get("timeout", 20)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Jaeles called without URL parameter")
            return JSONResponse(content={"error": "URL parameter is required"}, status_code=400)

        command = f"jaeles scan -u {url} -c {threads} --timeout {timeout}"

        if signatures:
            command += f" -s {signatures}"

        if config:
            command += f" --config {config}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Jaeles vulnerability scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in jaeles endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/dalfox")
def dalfox(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        pipe_mode = params.get("pipe_mode", False)
        blind = params.get("blind", False)
        mining_dom = params.get("mining_dom", True)
        mining_dict = params.get("mining_dict", True)
        custom_payload = params.get("custom_payload", "")
        additional_args = params.get("additional_args", "")

        if not url and not pipe_mode:
            logger.warning("🌐 Dalfox called without URL parameter")
            return JSONResponse(content={"error": "URL parameter is required"}, status_code=400)

        if pipe_mode:
            command = "dalfox pipe"
        else:
            command = f"dalfox url {url}"

        if blind:
            command += " --blind"

        if mining_dom:
            command += " --mining-dom"

        if mining_dict:
            command += " --mining-dict"

        if custom_payload:
            command += f" --custom-payload '{custom_payload}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🎯 Starting Dalfox XSS scan: {url if url else 'pipe mode'}")
        result = execute_command(command)
        logger.info(f"📊 Dalfox XSS scan completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in dalfox endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/wafw00f")
def wafw00f(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🛡️ Wafw00f called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"wafw00f {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = execute_command(command)
        logger.info(f"📊 Wafw00f completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in wafw00f endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/zap")
def zap(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute OWASP ZAP with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        scan_type = params.get("scan_type", "baseline")
        api_key = params.get("api_key", "")
        daemon = params.get("daemon", False)
        port = params.get("port", "8090")
        host = params.get("host", "0.0.0.0")
        format_type = params.get("format", "xml")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target and scan_type != "daemon":
            logger.warning("🎯 ZAP called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required for scans"
            }, status_code=400)

        if daemon:
            command = f"zaproxy -daemon -host {host} -port {port}"
            if api_key:
                command += f" -config api.key={api_key}"
        else:
            command = f"zaproxy -cmd -quickurl {target}"

            if format_type:
                command += f" -quickout {format_type}"

            if output_file:
                command += f" -quickprogress -dir \"{output_file}\""

            if api_key:
                command += f" -config api.key={api_key}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 ZAP scan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in zap endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/burpsuite-alternative")
def burpsuite_alternative(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Comprehensive Burp Suite alternative combining HTTP framework and browser agent"""
    try:
        params = params or {}
        target = params.get("target", "")
        scan_type = params.get("scan_type", "comprehensive")  # comprehensive, spider, passive, active
        headless = params.get("headless", True)
        max_depth = params.get("max_depth", 3)
        max_pages = params.get("max_pages", 50)

        if not target:
            return JSONResponse(content={"error": "Target parameter is required"}, status_code=400)

        logger.info(f"{ModernVisualEngine.create_section_header('BURP SUITE ALTERNATIVE', '🔥', 'BLOOD_RED')}")
        scan_message = f'Starting {scan_type} scan of {target}'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(scan_message, 'RED')}")

        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }

        # Phase 1: Browser-based reconnaissance
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Reconnaissance Phase')}")

            if not browser_agent.driver:
                browser_agent.setup_browser(headless)

            browser_result = browser_agent.navigate_and_inspect(target)
            results['browser_analysis'] = browser_result

        # Phase 2: HTTP spidering
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'RUNNING', 'Discovery Phase')}")

            spider_result = http_framework.spider_website(target, max_depth, max_pages)
            results['spider_analysis'] = spider_result

        # Phase 3: Vulnerability analysis
        if scan_type in ['comprehensive', 'active']:
            logger.info(f"{ModernVisualEngine.format_tool_status('VulnScanner', 'RUNNING', 'Analysis Phase')}")

            # Test discovered endpoints
            discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
            vuln_results = []

            for url in discovered_urls[:20]:  # Limit to 20 URLs
                test_result = http_framework.intercept_request(url)
                if test_result.get('success'):
                    vuln_results.append(test_result)

            results['vulnerability_analysis'] = {
                'tested_urls': len(vuln_results),
                'total_vulnerabilities': len(http_framework.vulnerabilities),
                'recent_vulnerabilities': http_framework._get_recent_vulns(20)
            }

        # Generate summary
        total_vulns = len(http_framework.vulnerabilities)
        vuln_summary = {}
        for vuln in http_framework.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'vulnerability_breakdown': vuln_summary,
            'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
            'security_score': max(0, 100 - (total_vulns * 5))
        }

        # Display summary with enhanced colors
        logger.info(f"{ModernVisualEngine.create_section_header('SCAN COMPLETE', '✅', 'SUCCESS')}")
        vuln_message = f'Found {total_vulns} vulnerabilities'
        color_choice = 'YELLOW' if total_vulns > 0 else 'GREEN'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(vuln_message, color_choice)}")

        for severity, count in vuln_summary.items():
            logger.info(f"  {ModernVisualEngine.format_vulnerability_severity(severity, count)}")

        return results

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('CRITICAL', 'BurpAlternative', str(e))}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)
        logger.error(f"💥 Error in burpsuite endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/wfuzz")
def wfuzz(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Wfuzz for web application fuzzing with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Wfuzz called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"wfuzz -w {wordlist} '{url}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Wfuzz scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Wfuzz scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in wfuzz endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/dotdotpwn")
def dotdotpwn(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute DotDotPwn for directory traversal testing with enhanced logging"""
    try:
        params = params or {}
        target = params.get("target", "")
        module = params.get("module", "http")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 DotDotPwn called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"dotdotpwn -m {module} -h {target}"

        if additional_args:
            command += f" {additional_args}"

        command += " -b"

        logger.info(f"🔍 Starting DotDotPwn scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 DotDotPwn scan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in dotdotpwn endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/xsser")
def xsser(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute XSSer for XSS vulnerability testing with enhanced logging"""
    try:
        params = params or {}
        url = params.get("url", "")
        params_str = params.get("params", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 XSSer called without URL parameter")
            return JSONResponse(content={
                "error": "URL parameter is required"
            }, status_code=400)

        command = f"xsser --url '{url}'"

        if params_str:
            command += f" --param='{params_str}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 XSSer scan completed for {url}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in xsser endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/anew")
def anew(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute anew for appending new lines to files (useful for data processing)"""
    try:
        params = params or {}
        input_data = params.get("input_data", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not input_data:
            logger.warning("📝 Anew called without input data")
            return JSONResponse(content={"error": "Input data is required"}, status_code=400)

        if output_file:
            command = f"echo '{input_data}' | anew {output_file}"
        else:
            command = f"echo '{input_data}' | anew"

        if additional_args:
            command += f" {additional_args}"

        logger.info("📝 Starting anew data processing")
        result = execute_command(command)
        logger.info("📊 anew data processing completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in anew endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/qsreplace")
def qsreplace(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute qsreplace for query string parameter replacement"""
    try:
        params = params or {}
        urls = params.get("urls", "")
        replacement = params.get("replacement", "FUZZ")
        additional_args = params.get("additional_args", "")

        if not urls:
            logger.warning("🌐 qsreplace called without URLs")
            return JSONResponse(content={"error": "URLs parameter is required"}, status_code=400)

        command = f"echo '{urls}' | qsreplace '{replacement}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔄 Starting qsreplace parameter replacement")
        result = execute_command(command)
        logger.info("📊 qsreplace parameter replacement completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in qsreplace endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/uro")
def uro(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute uro for filtering out similar URLs"""
    try:
        params = params or {}
        urls = params.get("urls", "")
        whitelist = params.get("whitelist", "")
        blacklist = params.get("blacklist", "")
        additional_args = params.get("additional_args", "")

        if not urls:
            logger.warning("🌐 uro called without URLs")
            return JSONResponse(content={"error": "URLs parameter is required"}, status_code=400)

        command = f"echo '{urls}' | uro"

        if whitelist:
            command += f" --whitelist {whitelist}"

        if blacklist:
            command += f" --blacklist {blacklist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔍 Starting uro URL filtering")
        result = execute_command(command)
        logger.info("📊 uro URL filtering completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in uro endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/http-framework")
def http_framework_endpoint(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Enhanced HTTP testing framework (Burp Suite alternative)"""
    try:
        params = params or {}
        action = params.get("action", "request")  # request, spider, proxy_history, set_rules, set_scope, repeater, intruder
        url = params.get("url", "")
        method = params.get("method", "GET")
        data = params.get("data", {})
        headers = params.get("headers", {})
        cookies = params.get("cookies", {})

        logger.info(f"{ModernVisualEngine.create_section_header('HTTP FRAMEWORK', '🔥', 'FIRE_RED')}")

        if action == "request":
            if not url:
                return JSONResponse(content={"error": "URL parameter is required for request action"}, status_code=400)

            request_command = f"{method} {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(request_command, 'STARTING')}")
            result = http_framework.intercept_request(url, method, data, headers, cookies)

            if result.get("success"):
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SUCCESS', url)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'FAILED', url)}")

            return result

        elif action == "spider":
            if not url:
                return JSONResponse(content={"error": "URL parameter is required for spider action"}, status_code=400)

            max_depth = params.get("max_depth", 3)
            max_pages = params.get("max_pages", 100)

            spider_command = f"Spider {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(spider_command, 'STARTING')}")
            result = http_framework.spider_website(url, max_depth, max_pages)

            if result.get("success"):
                total_pages = result.get("total_pages", 0)
                pages_info = f"{total_pages} pages"
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'SUCCESS', pages_info)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'FAILED', url)}")

            return result

        elif action == "proxy_history":
            return {
                "success": True,
                "history": http_framework.proxy_history[-100:],  # Last 100 requests
                "total_requests": len(http_framework.proxy_history),
                "vulnerabilities": http_framework.vulnerabilities,
            }

        elif action == "set_rules":
            rules = params.get("rules", [])
            http_framework.set_match_replace_rules(rules)
            return {"success": True, "rules_set": len(rules)}

        elif action == "set_scope":
            scope_host = params.get("host")
            include_sub = params.get("include_subdomains", True)
            if not scope_host:
                return JSONResponse(content={"error": "host parameter required"}, status_code=400)
            http_framework.set_scope(scope_host, include_sub)
            return {"success": True, "scope": http_framework.scope}

        elif action == "repeater":
            request_spec = params.get("request") or {}
            result = http_framework.send_custom_request(request_spec)
            return result

        elif action == "intruder":
            if not url:
                return JSONResponse(content={"error": "URL parameter required"}, status_code=400)
            method = params.get("method", "GET")
            location = params.get("location", "query")
            fuzz_params = params.get("params", [])
            payloads = params.get("payloads", [])
            base_data = params.get("base_data", {})
            max_requests = params.get("max_requests", 100)
            result = http_framework.intruder_sniper(
                url, method, location, fuzz_params, payloads, base_data, max_requests
            )
            return result

        else:
            return JSONResponse(content={"error": f"Unknown action: {action}"}, status_code=400)

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/browser-agent")
def browser_agent_endpoint(params: Optional[Dict[str, Any]] = Body(default=None)):
    """AI-powered browser agent for web application inspection"""
    try:
        params = params or {}
        action = params.get("action", "navigate")  # navigate, screenshot, close
        url = params.get("url", "")
        headless = params.get("headless", True)
        wait_time = params.get("wait_time", 5)
        proxy_port = params.get("proxy_port")
        active_tests = params.get("active_tests", False)

        logger.info(
            f"{ModernVisualEngine.create_section_header('BROWSER AGENT', '🌐', 'CRIMSON')}"
        )

        if action == "navigate":
            if not url:
                return JSONResponse(content={"error": "URL parameter is required for navigate action"}, status_code=400)

            # Setup browser if not already done
            if not browser_agent.driver:
                setup_success = browser_agent.setup_browser(headless, proxy_port)
                if not setup_success:
                    return JSONResponse(content={"error": "Failed to setup browser"}, status_code=500)

            result = browser_agent.navigate_and_inspect(url, wait_time)
            if result.get("success") and active_tests:
                active_results = browser_agent.run_active_tests(
                    result.get("page_info", {})
                )
                result["active_tests"] = active_results
                if active_results["active_findings"]:
                    logger.warning(
                        ModernVisualEngine.format_error_card(
                            "WARNING",
                            "BrowserAgent",
                            f"Active findings: {len(active_results['active_findings'])}",
                        )
                    )
            return result

        elif action == "screenshot":
            if not browser_agent.driver:
                return JSONResponse(content={"error": "Browser not initialized. Use navigate action first."}, status_code=400)

            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            browser_agent.driver.save_screenshot(screenshot_path)

            return {
                    "success": True,
                    "screenshot": screenshot_path,
                    "current_url": browser_agent.driver.current_url,
                    "timestamp": datetime.now().isoformat(),
                }

        elif action == "close":
            browser_agent.close_browser()
            return {"success": True, "message": "Browser closed successfully"}

        elif action == "status":
            return {
                    "success": True,
                    "browser_active": browser_agent.driver is not None,
                    "screenshots_taken": len(browser_agent.screenshots),
                    "pages_visited": len(browser_agent.page_sources),
                }

        else:
            return JSONResponse(content={"error": f"Unknown action: {action}"}, status_code=400)

    except Exception as e:
        logger.error(
            f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}"
        )
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/api_fuzzer")
def api_fuzzer(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Advanced API endpoint fuzzing with intelligent parameter discovery"""
    try:
        params = params or {}
        base_url = params.get("base_url", "")
        endpoints = params.get("endpoints", [])
        methods = params.get("methods", ["GET", "POST", "PUT", "DELETE"])
        wordlist = params.get("wordlist", "/usr/share/wordlists/api/api-endpoints.txt")

        if not base_url:
            logger.warning("🌐 API Fuzzer called without base_url parameter")
            return JSONResponse(content={
                "error": "Base URL parameter is required"
            }, status_code=400)

        # Create comprehensive API fuzzing command
        if endpoints:
            # Test specific endpoints
            results = []
            for endpoint in endpoints:
                for method in methods:
                    test_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
                    command = f"curl -s -X {method} -w '%{{http_code}}|%{{size_download}}' '{test_url}'"
                    result = execute_command(command, use_cache=False)
                    results.append({
                        "endpoint": endpoint,
                        "method": method,
                        "result": result
                    })

            logger.info(f"🔍 API endpoint testing completed for {len(endpoints)} endpoints")
            return {
                "success": True,
                "fuzzing_type": "endpoint_testing",
                "results": results
            }
        else:
            # Discover endpoints using wordlist
            command = f"ffuf -u {base_url}/FUZZ -w {wordlist} -mc 200,201,202,204,301,302,307,401,403,405 -t 50"

            logger.info(f"🔍 Starting API endpoint discovery: {base_url}")
            result = execute_command(command)
            logger.info(f"📊 API endpoint discovery completed")

            return {
                "success": True,
                "fuzzing_type": "endpoint_discovery",
                "result": result
            }

    except Exception as e:
        logger.error(f"💥 Error in API fuzzer: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/graphql_scanner")
def graphql_scanner(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Advanced GraphQL security scanning and introspection"""
    try:
        params = params or {}
        endpoint = params.get("endpoint", "")
        introspection = params.get("introspection", True)
        query_depth = params.get("query_depth", 10)
        mutations = params.get("test_mutations", True)

        if not endpoint:
            logger.warning("🌐 GraphQL Scanner called without endpoint parameter")
            return JSONResponse(content={
                "error": "GraphQL endpoint parameter is required"
            }, status_code=400)

        logger.info(f"🔍 Starting GraphQL security scan: {endpoint}")

        results = {
            "endpoint": endpoint,
            "tests_performed": [],
            "vulnerabilities": [],
            "recommendations": []
        }

        # Test 1: Introspection query
        if introspection:
            introspection_query = '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            '''

            clean_query = introspection_query.replace('\n', ' ').replace('  ', ' ').strip()
            command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{clean_query}\"}}' '{endpoint}'"
            result = execute_command(command, use_cache=False)

            results["tests_performed"].append("introspection_query")

            if "data" in result.get("stdout", ""):
                results["vulnerabilities"].append({
                    "type": "introspection_enabled",
                    "severity": "MEDIUM",
                    "description": "GraphQL introspection is enabled"
                })

        # Test 2: Query depth analysis
        deep_query = "{ " * query_depth + "field" + " }" * query_depth
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{deep_query}\"}}' {endpoint}"
        depth_result = execute_command(command, use_cache=False)

        results["tests_performed"].append("query_depth_analysis")

        if "error" not in depth_result.get("stdout", "").lower():
            results["vulnerabilities"].append({
                "type": "no_query_depth_limit",
                "severity": "HIGH",
                "description": f"No query depth limiting detected (tested depth: {query_depth})"
            })

        # Test 3: Batch query testing
        batch_query = '[' + ','.join(['{\"query\":\"{field}\"}' for _ in range(10)]) + ']'
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{batch_query}' {endpoint}"
        batch_result = execute_command(command, use_cache=False)

        results["tests_performed"].append("batch_query_testing")

        if "data" in batch_result.get("stdout", "") and batch_result.get("success"):
            results["vulnerabilities"].append({
                "type": "batch_queries_allowed",
                "severity": "MEDIUM",
                "description": "Batch queries are allowed without rate limiting"
            })

        # Generate recommendations
        if results["vulnerabilities"]:
            results["recommendations"] = [
                "Disable introspection in production",
                "Implement query depth limiting",
                "Add rate limiting for batch queries",
                "Implement query complexity analysis",
                "Add authentication for sensitive operations"
            ]

        logger.info(f"📊 GraphQL scan completed | Vulnerabilities found: {len(results['vulnerabilities'])}")

        return {
            "success": True,
            "graphql_scan_results": results
        }

    except Exception as e:
        logger.error(f"💥 Error in GraphQL scanner: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/jwt_analyzer")
def jwt_analyzer(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Advanced JWT token analysis and vulnerability testing"""
    try:
        params = params or {}
        jwt_token = params.get("jwt_token", "")
        target_url = params.get("target_url", "")

        if not jwt_token:
            logger.warning("🔐 JWT Analyzer called without jwt_token parameter")
            return JSONResponse(content={
                "error": "JWT token parameter is required"
            }, status_code=400)

        logger.info(f"🔍 Starting JWT security analysis")

        results = {
            "token": jwt_token[:50] + "..." if len(jwt_token) > 50 else jwt_token,
            "vulnerabilities": [],
            "token_info": {},
            "attack_vectors": []
        }

        # Decode JWT header and payload (basic analysis)
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                # Decode header
                import base64
                import json

                # Add padding if needed
                header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)

                try:
                    header = json.loads(base64.b64decode(header_b64))
                    payload = json.loads(base64.b64decode(payload_b64))

                    results["token_info"] = {
                        "header": header,
                        "payload": payload,
                        "algorithm": header.get("alg", "unknown")
                    }

                    # Check for vulnerabilities
                    algorithm = header.get("alg", "").lower()

                    if algorithm == "none":
                        results["vulnerabilities"].append({
                            "type": "none_algorithm",
                            "severity": "CRITICAL",
                            "description": "JWT uses 'none' algorithm - no signature verification"
                        })

                    if algorithm in ["hs256", "hs384", "hs512"]:
                        results["attack_vectors"].append("hmac_key_confusion")
                        results["vulnerabilities"].append({
                            "type": "hmac_algorithm",
                            "severity": "MEDIUM",
                            "description": "HMAC algorithm detected - vulnerable to key confusion attacks"
                        })

                    # Check token expiration
                    exp = payload.get("exp")
                    if not exp:
                        results["vulnerabilities"].append({
                            "type": "no_expiration",
                            "severity": "HIGH",
                            "description": "JWT token has no expiration time"
                        })

                except Exception as decode_error:
                    results["vulnerabilities"].append({
                        "type": "malformed_token",
                        "severity": "HIGH",
                        "description": f"Token decoding failed: {str(decode_error)}"
                    })

        except Exception as e:
            results["vulnerabilities"].append({
                "type": "invalid_format",
                "severity": "HIGH",
                "description": "Invalid JWT token format"
            })

        # Test token manipulation if target URL provided
        if target_url:
            # Test none algorithm attack
            none_token_parts = jwt_token.split('.')
            if len(none_token_parts) >= 2:
                # Create none algorithm token
                none_header = base64.b64encode('{"alg":"none","typ":"JWT"}'.encode()).decode().rstrip('=')
                none_token = f"{none_header}.{none_token_parts[1]}."

                command = f"curl -s -H 'Authorization: Bearer {none_token}' '{target_url}'"
                none_result = execute_command(command, use_cache=False)

                if "200" in none_result.get("stdout", "") or "success" in none_result.get("stdout", "").lower():
                    results["vulnerabilities"].append({
                        "type": "none_algorithm_accepted",
                        "severity": "CRITICAL",
                        "description": "Server accepts tokens with 'none' algorithm"
                    })

        logger.info(f"📊 JWT analysis completed | Vulnerabilities found: {len(results['vulnerabilities'])}")

        return {
            "success": True,
            "jwt_analysis_results": results
        }

    except Exception as e:
        logger.error(f"💥 Error in JWT analyzer: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/api_schema_analyzer")
def api_schema_analyzer(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Analyze API schemas and identify potential security issues"""
    try:
        params = params or {}
        schema_url = params.get("schema_url", "")
        schema_type = params.get("schema_type", "openapi")  # openapi, swagger, graphql

        if not schema_url:
            logger.warning("📋 API Schema Analyzer called without schema_url parameter")
            return JSONResponse(content={
                "error": "Schema URL parameter is required"
            }, status_code=400)

        logger.info(f"🔍 Starting API schema analysis: {schema_url}")

        # Fetch schema
        command = f"curl -s '{schema_url}'"
        result = execute_command(command, use_cache=True)

        if not result.get("success"):
            return JSONResponse(content={
                "error": "Failed to fetch API schema"
            }, status_code=400)

        schema_content = result.get("stdout", "")

        analysis_results = {
            "schema_url": schema_url,
            "schema_type": schema_type,
            "endpoints_found": [],
            "security_issues": [],
            "recommendations": []
        }

        # Parse schema based on type
        try:
            import json
            schema_data = json.loads(schema_content)

            if schema_type.lower() in ["openapi", "swagger"]:
                # OpenAPI/Swagger analysis
                paths = schema_data.get("paths", {})

                for path, methods in paths.items():
                    for method, details in methods.items():
                        if isinstance(details, dict):
                            endpoint_info = {
                                "path": path,
                                "method": method.upper(),
                                "summary": details.get("summary", ""),
                                "parameters": details.get("parameters", []),
                                "security": details.get("security", [])
                            }
                            analysis_results["endpoints_found"].append(endpoint_info)

                            # Check for security issues
                            if not endpoint_info["security"]:
                                analysis_results["security_issues"].append({
                                    "endpoint": f"{method.upper()} {path}",
                                    "issue": "no_authentication",
                                    "severity": "MEDIUM",
                                    "description": "Endpoint has no authentication requirements"
                                })

                            # Check for sensitive data in parameters
                            for param in endpoint_info["parameters"]:
                                param_name = param.get("name", "").lower()
                                if any(sensitive in param_name for sensitive in ["password", "token", "key", "secret"]):
                                    analysis_results["security_issues"].append({
                                        "endpoint": f"{method.upper()} {path}",
                                        "issue": "sensitive_parameter",
                                        "severity": "HIGH",
                                        "description": f"Sensitive parameter detected: {param_name}"
                                    })

            # Generate recommendations
            if analysis_results["security_issues"]:
                analysis_results["recommendations"] = [
                    "Implement authentication for all endpoints",
                    "Use HTTPS for all API communications",
                    "Validate and sanitize all input parameters",
                    "Implement rate limiting",
                    "Add proper error handling",
                    "Use secure headers (CORS, CSP, etc.)"
                ]

        except json.JSONDecodeError:
            analysis_results["security_issues"].append({
                "endpoint": "schema",
                "issue": "invalid_json",
                "severity": "HIGH",
                "description": "Schema is not valid JSON"
            })

        logger.info(f"📊 Schema analysis completed | Issues found: {len(analysis_results['security_issues'])}")

        return {
            "success": True,
            "schema_analysis_results": analysis_results
        }

    except Exception as e:
        logger.error(f"💥 Error in API schema analyzer: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/burpsuite")
def burpsuite(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Burp Suite scan or fallback to burpsuite-alternative assessment"""
    try:
        params = params or {}
        target = params.get("target", "")
        project_file = params.get("project_file", "")
        config_file = params.get("config_file", "")
        headless = params.get("headless", True)
        scan_type = params.get("scan_type", "comprehensive")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target and not project_file:
            return JSONResponse(content={"error": "Target or project_file parameter is required"}, status_code=400)

        if shutil.which("burpsuite"):
            cmd_parts = ["burpsuite"]
            if headless:
                cmd_parts.append("-Djava.awt.headless=true")
            if project_file:
                cmd_parts.append(f"--project-file={project_file}")
            if config_file:
                cmd_parts.append(f"--config-file={config_file}")
            if additional_args:
                cmd_parts.append(additional_args)
            result = execute_command(" ".join(cmd_parts))
            result["target"] = target
            result["scan_type"] = scan_type
            return result

        # Fallback to built-in HTTP framework + browser agent assessment
        return burpsuite_alternative({"target": target, "scan_type": scan_type, "headless": headless, "output_file": output_file})
    except Exception as e:
        logger.error(f"💥 Error in burpsuite endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)

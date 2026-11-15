#!/usr/bin/env python3
"""
HexStrike AI - Cloud & Container Security API Endpoints
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

router = MultiTargetAPIRouter(tags=["Cloud & Container Security"])

@router.post("/api/tools/prowler")
def prowler(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Prowler for AWS security assessment"""
    try:
        params = params or {}
        provider = params.get("provider", "aws")
        profile = params.get("profile", "default")
        region = params.get("region", "")
        checks = params.get("checks", "")
        output_dir = params.get("output_dir", "/tmp/prowler_output")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        command = f"prowler {provider}"

        if profile:
            command += f" --profile {profile}"

        if region:
            command += f" --region {region}"

        if checks:
            command += f" --checks {checks}"

        command += f" --output-directory {output_dir}"
        command += f" --output-format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = execute_command(command)
        result["output_directory"] = output_dir
        logger.info(f"📊 Prowler assessment completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in prowler endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/scout-suite")
def scout_suite(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Scout Suite for multi-cloud security assessment"""
    try:
        params = params or {}
        provider = params.get("provider", "aws")  # aws, azure, gcp, aliyun, oci
        profile = params.get("profile", "default")
        report_dir = params.get("report_dir", "/tmp/scout-suite")
        services = params.get("services", "")
        exceptions = params.get("exceptions", "")
        additional_args = params.get("additional_args", "")

        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)

        command = f"scout {provider}"

        if profile and provider == "aws":
            command += f" --profile {profile}"

        if services:
            command += f" --services {services}"

        if exceptions:
            command += f" --exceptions {exceptions}"

        command += f" --report-dir {report_dir}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Scout Suite {provider} assessment")
        result = execute_command(command)
        result["report_directory"] = report_dir
        logger.info(f"📊 Scout Suite assessment completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in scout-suite endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/cloudmapper")
def cloudmapper(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute CloudMapper for AWS network visualization and security analysis"""
    try:
        params = params or {}
        action = params.get("action", "collect")  # collect, prepare, webserver, find_admins, etc.
        account = params.get("account", "")
        config = params.get("config", "config.json")
        additional_args = params.get("additional_args", "")

        if not account and action != "webserver":
            logger.warning("☁️  CloudMapper called without account parameter")
            return JSONResponse(content={"error": "Account parameter is required for most actions"}, status_code=400)

        command = f"cloudmapper {action}"

        if account:
            command += f" --account {account}"

        if config:
            command += f" --config {config}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting CloudMapper {action}")
        result = execute_command(command)
        logger.info(f"📊 CloudMapper {action} completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in cloudmapper endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/pacu")
def pacu(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Pacu for AWS exploitation framework"""
    try:
        params = params or {}
        session_name = params.get("session_name", "hexstrike_session")
        modules = params.get("modules", "")
        data_services = params.get("data_services", "")
        regions = params.get("regions", "")
        additional_args = params.get("additional_args", "")

        # Create Pacu command sequence
        commands = []
        commands.append(f"set_session {session_name}")

        if data_services:
            commands.append(f"data {data_services}")

        if regions:
            commands.append(f"set_regions {regions}")

        if modules:
            for module in modules.split(","):
                commands.append(f"run {module.strip()}")

        commands.append("exit")

        # Create command file
        command_file = "/tmp/pacu_commands.txt"
        with open(command_file, "w") as f:
            f.write("\n".join(commands))

        command = f"pacu < {command_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Pacu AWS exploitation")
        result = execute_command(command)

        # Cleanup
        try:
            os.remove(command_file)
        except:
            pass

        logger.info(f"📊 Pacu exploitation completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in pacu endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/trivy")
def trivy(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Trivy for container/filesystem vulnerability scanning"""
    try:
        params = params or {}
        scan_type = params.get("scan_type", "image")  # image, fs, repo
        target = params.get("target", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Trivy called without target parameter")
            return JSONResponse(content={
                "error": "Target parameter is required"
            }, status_code=400)

        command = f"trivy {scan_type} {target}"

        if output_format:
            command += f" --format {output_format}"

        if severity:
            command += f" --severity {severity}"

        if output_file:
            command += f" --output {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = execute_command(command)
        if output_file:
            result["output_file"] = output_file
        logger.info(f"📊 Trivy scan completed for {target}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in trivy endpoint: {str(e)}")
        return JSONResponse(content={
            "error": f"Server error: {str(e)}"
        }, status_code=500)


@router.post("/api/tools/clair")
def clair(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Clair for container vulnerability analysis"""
    try:
        params = params or {}
        image = params.get("image", "")
        config = params.get("config", "/etc/clair/config.yaml")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not image:
            logger.warning("🐳 Clair called without image parameter")
            return JSONResponse(content={"error": "Image parameter is required"}, status_code=400)

        # Use clairctl for scanning
        command = f"clairctl analyze {image}"

        if config:
            command += f" --config {config}"

        if output_format:
            command += f" --format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🐳 Starting Clair vulnerability scan: {image}")
        result = execute_command(command)
        logger.info(f"📊 Clair scan completed for {image}")
        return result
    except Exception as e:
        logger.error(f"💥 Error in clair endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/kube-hunter")
def kube_hunter(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute kube-hunter for Kubernetes penetration testing"""
    try:
        params = params or {}
        target = params.get("target", "")
        remote = params.get("remote", "")
        cidr = params.get("cidr", "")
        interface = params.get("interface", "")
        active = params.get("active", False)
        report = params.get("report", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-hunter"

        if target:
            command += f" --remote {target}"
        elif remote:
            command += f" --remote {remote}"
        elif cidr:
            command += f" --cidr {cidr}"
        elif interface:
            command += f" --interface {interface}"
        else:
            # Default to pod scanning
            command += " --pod"

        if active:
            command += " --active"

        if report:
            command += f" --report {report}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-hunter Kubernetes scan")
        result = execute_command(command)
        logger.info(f"📊 kube-hunter scan completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in kube-hunter endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/kube-bench")
def kube_bench(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute kube-bench for CIS Kubernetes benchmark checks"""
    try:
        params = params or {}
        targets = params.get("targets", "")  # master, node, etcd, policies
        version = params.get("version", "")
        config_dir = params.get("config_dir", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-bench"

        if targets:
            command += f" --targets {targets}"

        if version:
            command += f" --version {version}"

        if config_dir:
            command += f" --config-dir {config_dir}"

        if output_format:
            command += f" --outputfile /tmp/kube-bench-results.{output_format} --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = execute_command(command)
        logger.info(f"📊 kube-bench benchmark completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in kube-bench endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/docker-bench-security")
def docker_bench_security(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Docker Bench for Security for Docker security assessment"""
    try:
        params = params or {}
        checks = params.get("checks", "")  # Specific checks to run
        exclude = params.get("exclude", "")  # Checks to exclude
        output_file = params.get("output_file", "/tmp/docker-bench-results.json")
        additional_args = params.get("additional_args", "")

        command = "docker-bench-security"

        if checks:
            command += f" -c {checks}"

        if exclude:
            command += f" -e {exclude}"

        if output_file:
            command += f" -l {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🐳 Starting Docker Bench Security assessment")
        result = execute_command(command)
        result["output_file"] = output_file
        logger.info(f"📊 Docker Bench Security completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in docker-bench-security endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/falco")
def falco(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Falco for runtime security monitoring"""
    try:
        params = params or {}
        config_file = params.get("config_file", "/etc/falco/falco.yaml")
        rules_file = params.get("rules_file", "")
        output_format = params.get("output_format", "json")
        duration = params.get("duration", 60)  # seconds
        additional_args = params.get("additional_args", "")

        command = f"timeout {duration} falco"

        if config_file:
            command += f" --config {config_file}"

        if rules_file:
            command += f" --rules {rules_file}"

        if output_format == "json":
            command += " --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = execute_command(command)
        logger.info(f"📊 Falco monitoring completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in falco endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/checkov")
def checkov(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Checkov for infrastructure as code security scanning"""
    try:
        params = params or {}
        directory = params.get("directory", ".")
        framework = params.get("framework", "")  # terraform, cloudformation, kubernetes, etc.
        check = params.get("check", "")
        skip_check = params.get("skip_check", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = f"checkov -d {directory}"

        if framework:
            command += f" --framework {framework}"

        if check:
            command += f" --check {check}"

        if skip_check:
            command += f" --skip-check {skip_check}"

        if output_format:
            command += f" --output {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Checkov IaC scan: {directory}")
        result = execute_command(command)
        logger.info(f"📊 Checkov scan completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in checkov endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/tools/terrascan")
def terrascan(params: Optional[Dict[str, Any]] = Body(default=None)):
    """Execute Terrascan for infrastructure as code security scanning"""
    try:
        params = params or {}
        scan_type = params.get("scan_type", "all")  # all, terraform, k8s, etc.
        iac_dir = params.get("iac_dir", ".")
        policy_type = params.get("policy_type", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")

        command = f"terrascan scan -t {scan_type} -d {iac_dir}"

        if policy_type:
            command += f" -p {policy_type}"

        if output_format:
            command += f" -o {output_format}"

        if severity:
            command += f" --severity {severity}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Terrascan IaC scan: {iac_dir}")
        result = execute_command(command)
        logger.info(f"📊 Terrascan scan completed")
        return result
    except Exception as e:
        logger.error(f"💥 Error in terrascan endpoint: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)



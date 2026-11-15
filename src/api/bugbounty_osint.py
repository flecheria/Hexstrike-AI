#!/usr/bin/env python3
"""
HexStrike AI - Bug Bounty & OSINT Arsenal API Endpoints
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

router = MultiTargetAPIRouter(tags=["Bug Bounty & OSINT Arsenal"])

@router.post("/api/bugbounty/reconnaissance-workflow")
def create_reconnaissance_workflow(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create comprehensive reconnaissance workflow for bug bounty hunting"""
    try:
        if not data or 'domain' not in data:
            return JSONResponse(content={"error": "Domain is required"}, status_code=400)

        domain = data['domain']
        scope = data.get('scope', [])
        out_of_scope = data.get('out_of_scope', [])
        program_type = data.get('program_type', 'web')

        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            out_of_scope=out_of_scope,
            program_type=program_type
        )

        # Generate reconnaissance workflow
        workflow = bugbounty_manager.create_reconnaissance_workflow(target)

        logger.info(f"✅ Reconnaissance workflow created for {domain}")

        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating reconnaissance workflow: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/bugbounty/vulnerability-hunting-workflow")
def create_vulnerability_hunting_workflow(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create vulnerability hunting workflow prioritized by impact"""
    try:
        if not data or 'domain' not in data:
            return JSONResponse(content={"error": "Domain is required"}, status_code=400)

        domain = data['domain']
        priority_vulns = data.get('priority_vulns', ["rce", "sqli", "xss", "idor", "ssrf"])
        bounty_range = data.get('bounty_range', 'unknown')

        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            priority_vulns=priority_vulns,
            bounty_range=bounty_range
        )

        # Generate vulnerability hunting workflow
        workflow = bugbounty_manager.create_vulnerability_hunting_workflow(target)

        logger.info(f"✅ Vulnerability hunting workflow created for {domain}")

        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability hunting workflow: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/bugbounty/business-logic-workflow")
def create_business_logic_workflow(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create business logic testing workflow"""
    try:
        if not data or 'domain' not in data:
            return JSONResponse(content={"error": "Domain is required"}, status_code=400)

        domain = data['domain']
        program_type = data.get('program_type', 'web')

        logger.info(f"🎯 Creating business logic testing workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(domain=domain, program_type=program_type)

        # Generate business logic testing workflow
        workflow = bugbounty_manager.create_business_logic_testing_workflow(target)

        logger.info(f"✅ Business logic testing workflow created for {domain}")

        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating business logic workflow: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/bugbounty/osint-workflow")
def create_osint_workflow(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create OSINT gathering workflow"""
    try:
        if not data or 'domain' not in data:
            return JSONResponse(content={"error": "Domain is required"}, status_code=400)

        domain = data['domain']

        logger.info(f"🎯 Creating OSINT workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(domain=domain)

        # Generate OSINT workflow
        workflow = bugbounty_manager.create_osint_workflow(target)

        logger.info(f"✅ OSINT workflow created for {domain}")

        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating OSINT workflow: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/bugbounty/file-upload-testing")
def create_file_upload_testing(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create file upload vulnerability testing workflow"""
    try:
        if not data or 'target_url' not in data:
            return JSONResponse(content={"error": "Target URL is required"}, status_code=400)

        target_url = data['target_url']

        logger.info(f"🎯 Creating file upload testing workflow for {target_url}")

        # Generate file upload testing workflow
        workflow = fileupload_framework.create_upload_testing_workflow(target_url)

        # Generate test files
        test_files = fileupload_framework.generate_test_files()
        workflow["test_files"] = test_files

        logger.info(f"✅ File upload testing workflow created for {target_url}")

        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating file upload testing workflow: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)


@router.post("/api/bugbounty/comprehensive-assessment")
def create_comprehensive_bugbounty_assessment(data: Optional[Dict[str, Any]] = Body(default=None)):
    """Create comprehensive bug bounty assessment combining all workflows"""
    try:
        if not data or 'domain' not in data:
            return JSONResponse(content={"error": "Domain is required"}, status_code=400)

        domain = data['domain']
        scope = data.get('scope', [])
        priority_vulns = data.get('priority_vulns', ["rce", "sqli", "xss", "idor", "ssrf"])
        include_osint = data.get('include_osint', True)
        include_business_logic = data.get('include_business_logic', True)

        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            priority_vulns=priority_vulns
        )

        # Generate all workflows
        assessment = {
            "target": domain,
            "reconnaissance": bugbounty_manager.create_reconnaissance_workflow(target),
            "vulnerability_hunting": bugbounty_manager.create_vulnerability_hunting_workflow(target)
        }

        if include_osint:
            assessment["osint"] = bugbounty_manager.create_osint_workflow(target)

        if include_business_logic:
            assessment["business_logic"] = bugbounty_manager.create_business_logic_testing_workflow(target)

        # Calculate total estimates
        total_time = sum(workflow.get("estimated_time", 0) for workflow in assessment.values() if isinstance(workflow, dict))
        total_tools = sum(workflow.get("tools_count", 0) for workflow in assessment.values() if isinstance(workflow, dict))

        assessment["summary"] = {
            "total_estimated_time": total_time,
            "total_tools": total_tools,
            "workflow_count": len([k for k in assessment.keys() if k != "target"]),
            "priority_score": assessment["vulnerability_hunting"].get("priority_score", 0)
        }

        logger.info(f"✅ Comprehensive bug bounty assessment created for {domain}")

        return {
            "success": True,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error creating comprehensive assessment: {str(e)}")
        return JSONResponse(content={"error": f"Server error: {str(e)}"}, status_code=500)



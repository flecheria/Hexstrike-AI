#!/usr/bin/env python3
"""
HexStrike AI - Single & Multi-Domain Investigation API Endpoints

Provides dedicated endpoints to coordinate reconnaissance, target profiling,
workflow generation, cross-domain comparison, and batch tool execution across
single or multiple domains.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

from src.config import logger
from src.core.domain_utils import normalize_targets
from src.agents.domain_investigator import domain_investigator

router = APIRouter(tags=["Single & Multi-Domain Investigation"])


def _extract_domains_from_body(data: Optional[Dict[str, Any]]) -> List[str]:
    if not data:
        return []
    for key in ("domains", "domain", "targets", "target", "urls", "url"):
        if key in data and data[key]:
            return normalize_targets(data[key])
    return []


@router.post("/api/investigation/domains")
@router.post("/api/investigation/investigate")
def investigate_domains_endpoint(data: Optional[Dict[str, Any]] = Body(default=None)):
    """
    Investigate a single domain or multiple domains with AI target profiling,
    optimal tool selection, attack chain creation, bug bounty/OSINT workflows,
    cross-domain correlation, and optional live tool execution.
    """
    try:
        data = data or {}
        domains = _extract_domains_from_body(data)
        if not domains:
            return JSONResponse(
                content={"error": "Parameter 'domain' or 'domains' (string or list of strings) is required"},
                status_code=400,
            )

        objective = data.get("objective", "comprehensive")
        include_workflows = data.get("include_workflows", True)
        execute_tools = data.get("execute_tools", False)
        tools = data.get("tools")
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]
        max_tools = int(data.get("max_tools", 5))
        parallel = data.get("parallel", True)
        max_workers = int(data.get("max_workers", 5))

        return domain_investigator.investigate_domains(
            domains_input=domains,
            objective=objective,
            include_workflows=include_workflows,
            execute_tools=execute_tools,
            tools=tools,
            max_tools=max_tools,
            parallel=parallel,
            max_workers=max_workers,
        )
    except Exception as exc:
        logger.error(f"💥 Error in domain investigation: {exc}")
        return JSONResponse(content={"error": f"Server error: {exc}"}, status_code=500)


@router.post("/api/investigation/recon")
def recon_domains_endpoint(data: Optional[Dict[str, Any]] = Body(default=None)):
    """
    Execute or plan reconnaissance across a single domain or multiple domains
    using subdomain, DNS, HTTP, and port discovery tools.
    """
    try:
        data = data or {}
        domains = _extract_domains_from_body(data)
        if not domains:
            return JSONResponse(
                content={"error": "Parameter 'domain' or 'domains' (string or list of strings) is required"},
                status_code=400,
            )

        tools = data.get("tools")
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]
        execute_tools = data.get("execute_tools", False)
        parallel = data.get("parallel", True)

        return domain_investigator.recon_domains(
            domains_input=domains,
            tools=tools,
            execute_tools=execute_tools,
            parallel=parallel,
        )
    except Exception as exc:
        logger.error(f"💥 Error in domain reconnaissance: {exc}")
        return JSONResponse(content={"error": f"Server error: {exc}"}, status_code=500)


@router.post("/api/investigation/compare")
def compare_domains_endpoint(data: Optional[Dict[str, Any]] = Body(default=None)):
    """
    Compare security posture, technologies, attack surface scores, and prioritized
    rankings across single or multiple domains.
    """
    try:
        data = data or {}
        domains = _extract_domains_from_body(data)
        if not domains:
            return JSONResponse(
                content={"error": "Parameter 'domain' or 'domains' (string or list of strings) is required"},
                status_code=400,
            )

        objective = data.get("objective", "comprehensive")
        return domain_investigator.compare_domains(domains_input=domains, objective=objective)
    except Exception as exc:
        logger.error(f"💥 Error comparing domains: {exc}")
        return JSONResponse(content={"error": f"Server error: {exc}"}, status_code=500)


@router.post("/api/investigation/batch-tool")
def batch_domain_tool_endpoint(data: Optional[Dict[str, Any]] = Body(default=None)):
    """
    Execute one or more specific security tools across single or multiple domains.
    """
    try:
        data = data or {}
        domains = _extract_domains_from_body(data)
        tools = data.get("tools") or data.get("tool")
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]

        if not domains or not tools:
            return JSONResponse(
                content={"error": "Parameters 'domains' (or 'domain') and 'tools' (or 'tool') are required"},
                status_code=400,
            )

        execute_tools = data.get("execute_tools", True)
        parallel = data.get("parallel", True)

        return domain_investigator.investigate_domains(
            domains_input=domains,
            objective=data.get("objective", "comprehensive"),
            include_workflows=data.get("include_workflows", False),
            execute_tools=execute_tools,
            tools=tools,
            max_tools=len(tools),
            parallel=parallel,
        )
    except Exception as exc:
        logger.error(f"💥 Error in batch domain tool execution: {exc}")
        return JSONResponse(content={"error": f"Server error: {exc}"}, status_code=500)

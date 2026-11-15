"""
HexStrike AI - Categorized API Routers Package
Compatible with the security tool & agent categories defined in README.md.
"""

from fastapi import FastAPI

from src.api.system import *  # noqa: F401,F403
from src.api.processes import *  # noqa: F401,F403
from src.api.network import *  # noqa: F401,F403
from src.api.web import *  # noqa: F401,F403
from src.api.auth import *  # noqa: F401,F403
from src.api.binary import *  # noqa: F401,F403
from src.api.cloud import *  # noqa: F401,F403
from src.api.ctf_forensics import *  # noqa: F401,F403
from src.api.bugbounty_osint import *  # noqa: F401,F403
from src.api.intelligence import *  # noqa: F401,F403
from src.api.investigation import *  # noqa: F401,F403

from src.api.system import router as system_router
from src.api.processes import router as processes_router
from src.api.network import router as network_router
from src.api.web import router as web_router
from src.api.auth import router as auth_router
from src.api.binary import router as binary_router
from src.api.cloud import router as cloud_router
from src.api.ctf_forensics import router as ctf_forensics_router
from src.api.bugbounty_osint import router as bugbounty_osint_router
from src.api.intelligence import router as intelligence_router
from src.api.investigation import router as investigation_router

OPENAPI_TAGS = [
    {
        "name": "Single & Multi-Domain Investigation",
        "description": "Coordinated reconnaissance, profiling, comparison, and batch tool execution across single or multiple domains.",
    },
    {
        "name": "Network Reconnaissance & Scanning",
        "description": "Port scanning, DNS reconnaissance, subdomain enumeration, and network service enumeration (Nmap, Rustscan, Masscan, AutoRecon, Amass, Subfinder, Fierce, DNSEnum, SMB/RPC/ARP tools).",
    },
    {
        "name": "Web Application Security Testing",
        "description": "Web directory fuzzing, crawling, vulnerability scanning, WAF detection, API/GraphQL/JWT testing, and Browser Agent automation.",
    },
    {
        "name": "Authentication & Password Security",
        "description": "Network login cracking, password hash recovery, and hash length extension tools (Hydra, John, Hashcat, Hashpump).",
    },
    {
        "name": "Binary Analysis & Reverse Engineering",
        "description": "Debugging, disassembly, firmware extraction, ROP gadget discovery, and symbolic execution (GDB, Radare2, Ghidra, Binwalk, Pwntools, Angr, MSFVenom, Metasploit).",
    },
    {
        "name": "Cloud & Container Security",
        "description": "Multi-cloud auditing, Kubernetes penetration testing, container vulnerability scanning, and IaC security (Prowler, Scout Suite, CloudMapper, Pacu, Trivy, Clair, Kube-Hunter, Kube-Bench, Falco, Checkov, Terrascan).",
    },
    {
        "name": "CTF & Forensics Tools",
        "description": "Memory forensics, file carving, steganography, metadata analysis, and automated CTF solving workflows (Volatility, Foremost, Steghide, ExifTool, CTF Agents).",
    },
    {
        "name": "Bug Bounty & OSINT Arsenal",
        "description": "Automated reconnaissance, vulnerability hunting, business logic, OSINT, file upload testing, and comprehensive bug bounty assessment workflows.",
    },
    {
        "name": "AI Intelligence & Vulnerability Intelligence",
        "description": "Intelligent Decision Engine target analysis, tool selection, parameter optimization, smart scanning, CVE monitoring, exploit generation, and AI payload generation.",
    },
    {
        "name": "Process Management",
        "description": "Real-time process control, asynchronous task execution, process pooling, resource monitoring, and auto-scaling.",
    },
    {
        "name": "Core System, Cache, Files & Visual Engine",
        "description": "Health check, command execution, smart caching, telemetry, file operations, Python environment management, visual rendering, and error recovery.",
    },
]

ALL_ROUTERS = [
    investigation_router,
    network_router,
    web_router,
    auth_router,
    binary_router,
    cloud_router,
    ctf_forensics_router,
    bugbounty_osint_router,
    intelligence_router,
    processes_router,
    system_router,
]


def register_routers(app: FastAPI) -> None:
    """Include all categorized routers in the FastAPI application."""
    for r in ALL_ROUTERS:
        app.include_router(r)

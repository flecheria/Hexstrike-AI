#!/usr/bin/env python3
"""
HexStrike AI - Configurable Tool Registry & MCP Capability Mapper

Maintains the list of configured and installed security tools from
`config/tools_manifest.json` (and optional container build state
`config/installed_tools.json`), maps CLI binaries to FastAPI endpoints
and MCP tool functions, and provides real-time availability discovery
for both the server and MCP clients.
"""

from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import time
from typing import Any, Dict, List, Optional

from src.config import (
    logger,
    TOOLS_MANIFEST_PATH,
    INSTALLED_TOOLS_STATE_PATH,
    DATA_DIR,
    RESULTS_DIR,
    FILES_DIR,
    ENVS_DIR,
)


# Native Python / Agent-driven MCP tools that do not require an external CLI binary
BUILTIN_MCP_TOOLS: List[Dict[str, str]] = [
    {"mcp_tool": "server_health", "category": "system", "description": "Check HexStrike server health and tool status"},
    {"mcp_tool": "get_available_tools", "category": "system", "description": "List available and installed tools for MCP"},
    {"mcp_tool": "check_tool_availability", "category": "system", "description": "Check if a specific CLI or MCP tool is installed and get alternatives"},
    {"mcp_tool": "get_tool_profiles", "category": "system", "description": "List container build profiles and included tools"},
    {"mcp_tool": "investigate_domains", "category": "investigation", "description": "AI target profiling, attack chains, and multi-domain investigation"},
    {"mcp_tool": "recon_domains", "category": "reconnaissance", "description": "Multi-domain reconnaissance workflow planning and execution"},
    {"mcp_tool": "compare_domains", "category": "investigation", "description": "Cross-domain security posture and tech stack comparison"},
    {"mcp_tool": "batch_domain_tool", "category": "investigation", "description": "Batch execution of available tools across multiple domains"},
    {"mcp_tool": "analyze_target_intelligence", "category": "intelligence", "description": "AI target profiling and attack surface scoring"},
    {"mcp_tool": "select_optimal_tools_ai", "category": "intelligence", "description": "AI-driven tool selection for a target"},
    {"mcp_tool": "optimize_tool_parameters_ai", "category": "intelligence", "description": "Context-aware tool parameter optimization"},
    {"mcp_tool": "create_attack_chain_ai", "category": "intelligence", "description": "Multi-step attack chain generation"},
    {"mcp_tool": "http_framework_test", "category": "web", "description": "Built-in HTTP testing framework (spider, request, repeater, intruder)"},
    {"mcp_tool": "http_set_rules", "category": "web", "description": "Set HTTP match/replace rules"},
    {"mcp_tool": "http_set_scope", "category": "web", "description": "Define in-scope host for HTTP testing"},
    {"mcp_tool": "http_repeater", "category": "web", "description": "Send custom HTTP requests (Burp Repeater equivalent)"},
    {"mcp_tool": "http_intruder", "category": "web", "description": "Fuzz HTTP parameters with payloads (Burp Intruder equivalent)"},
    {"mcp_tool": "jwt_analyzer", "category": "web", "description": "Analyze JWT tokens for cryptographic and claim weaknesses"},
    {"mcp_tool": "graphql_scanner", "category": "web", "description": "Audit GraphQL endpoints for introspection and depth issues"},
    {"mcp_tool": "api_schema_analyzer", "category": "web", "description": "Parse and audit OpenAPI/Swagger and GraphQL schemas"},
    {"mcp_tool": "create_file", "category": "files", "description": "Create files in persistent workspace/volume"},
    {"mcp_tool": "modify_file", "category": "files", "description": "Modify files in persistent workspace/volume"},
    {"mcp_tool": "delete_file", "category": "files", "description": "Delete files in persistent workspace/volume"},
    {"mcp_tool": "list_files", "category": "files", "description": "List files in persistent workspace/volume"},
]


class ToolRegistry:
    """
    Central registry that loads `config/tools_manifest.json` and detects which
    CLI security tools are currently installed and ready for MCP execution.
    """

    def __init__(
        self,
        manifest_path: Optional[str] = None,
        state_path: Optional[str] = None,
        cache_ttl: int = 120,
    ) -> None:
        self.manifest_path = Path(manifest_path or TOOLS_MANIFEST_PATH)
        self.state_path = Path(state_path or INSTALLED_TOOLS_STATE_PATH)
        self.cache_ttl = cache_ttl
        self._last_scan_time: float = 0.0
        self._manifest_data: Dict[str, Any] = {}
        self._build_state: Dict[str, Any] = {}
        self._status_cache: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        """Reload the manifest file, container build state, and live binary status."""
        self._manifest_data = self._load_json(self.manifest_path, default={
            "version": "6.0.0",
            "default_profile": "recon_network_scan",
            "profiles": {},
            "tools": {},
        })
        self._build_state = self._load_json(self.state_path, default={})
        self._scan_installed_tools()

    @staticmethod
    def _load_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"⚠️  Failed to load JSON from {path}: {e}")
        return default

    @staticmethod
    def _probe_binary(tool_name: str, binary_spec: str) -> Dict[str, Any]:
        """Check if a tool binary or Python module is available in the environment."""
        if not binary_spec:
            binary_spec = tool_name

        # Special handling for Python-library tools (like angr or pwntools)
        if tool_name == "angr" or "import angr" in binary_spec:
            spec = importlib.util.find_spec("angr")
            return {
                "installed": spec is not None,
                "binary_path": spec.origin if spec else None,
            }
        if tool_name == "pwntools":
            path = shutil.which("pwn")
            if path:
                return {"installed": True, "binary_path": path}
            spec = importlib.util.find_spec("pwn")
            return {
                "installed": spec is not None,
                "binary_path": spec.origin if spec else None,
            }

        # Standard CLI binary lookup in PATH
        binary_name = binary_spec.split()[0]
        path = shutil.which(binary_name)
        if not path and tool_name != binary_name:
            path = shutil.which(tool_name)

        return {
            "installed": path is not None,
            "binary_path": path,
        }

    def _scan_installed_tools(self) -> None:
        """Scan all tools in the manifest and update cached installation status."""
        tools_cfg = self._manifest_data.get("tools", {})
        status_map: Dict[str, Dict[str, Any]] = {}

        for tool_name, meta in tools_cfg.items():
            binary_spec = meta.get("binary", tool_name)
            probe = self._probe_binary(tool_name, binary_spec)
            status_map[tool_name] = {
                "name": tool_name,
                "binary": binary_spec,
                "binary_path": probe["binary_path"],
                "category": meta.get("category", "additional"),
                "enabled": bool(meta.get("enabled", False)),
                "essential": bool(meta.get("essential", False)),
                "installed": probe["installed"],
                "profiles": meta.get("profiles", []),
                "description": meta.get("description", ""),
                "mcp_tools": meta.get("mcp_tools", []),
                "api_endpoints": meta.get("api_endpoints", []),
                "install_method": meta.get("install", {}).get("method", "manual"),
            }

        self._status_cache = status_map
        self._last_scan_time = time.time()

    def _ensure_fresh(self, refresh: bool = False) -> None:
        if refresh or (time.time() - self._last_scan_time) > self.cache_ttl:
            self.reload()

    def get_active_profile(self) -> str:
        """Return the active container build profile or configured default profile."""
        return (
            os.environ.get("HEXSTRIKE_TOOL_PROFILE")
            or self._build_state.get("profile")
            or self._manifest_data.get("default_profile", "recon_network_scan")
        )

    def is_tool_installed(self, tool_name: str, refresh: bool = False) -> bool:
        """Return True if a tool is installed on the system."""
        self._ensure_fresh(refresh=refresh)
        if tool_name in self._status_cache:
            return bool(self._status_cache[tool_name]["installed"])
        return shutil.which(tool_name) is not None

    def get_installed_tools(self, category: Optional[str] = None, refresh: bool = False) -> List[str]:
        """Return list of installed tool names, optionally filtered by category."""
        self._ensure_fresh(refresh=refresh)
        names: List[str] = []
        for name, info in self._status_cache.items():
            if info["installed"]:
                if not category or info["category"].lower() == category.lower():
                    names.append(name)
        return names

    def get_profiles(self, refresh: bool = False) -> Dict[str, Any]:
        """Return all configured build profiles and their tool installation statistics."""
        self._ensure_fresh(refresh=refresh)
        profiles_cfg = self._manifest_data.get("profiles", {})
        profiles_out: Dict[str, Any] = {}

        for profile_name, pmeta in profiles_cfg.items():
            included_tools = [
                tname
                for tname, tinfo in self._status_cache.items()
                if profile_name in tinfo.get("profiles", [])
            ]
            installed_in_profile = [
                tname for tname in included_tools if self._status_cache[tname]["installed"]
            ]
            profiles_out[profile_name] = {
                "description": pmeta.get("description", ""),
                "categories": pmeta.get("categories", []),
                "total_tools": len(included_tools),
                "installed_count": len(installed_in_profile),
                "tools": included_tools,
                "installed_tools": installed_in_profile,
                "missing_tools": [t for t in included_tools if t not in installed_in_profile],
            }

        return {
            "success": True,
            "active_profile": self.get_active_profile(),
            "manifest_path": str(self.manifest_path),
            "profiles": profiles_out,
            "build_instructions": {
                "docker": "docker build --build-arg TOOL_PROFILE=<profile_name> -t hexstrike-ai:latest .",
                "podman": "podman build --build-arg TOOL_PROFILE=<profile_name> -t hexstrike-ai:latest -f Containerfile .",
                "extra_tools_example": "docker build --build-arg TOOL_PROFILE=recon_network_scan --build-arg EXTRA_TOOLS=hydra,john,trivy -t hexstrike-ai:latest .",
            },
        }

    def check_tool(self, tool_or_mcp_name: str, refresh: bool = False) -> Dict[str, Any]:
        """
        Check availability of a specific CLI tool name (e.g. 'nmap') or MCP tool
        name (e.g. 'nmap_scan') and suggest installed alternatives if missing.
        """
        self._ensure_fresh(refresh=refresh)
        query = (tool_or_mcp_name or "").strip()

        # 1. Check if it matches a built-in native MCP tool
        for builtin in BUILTIN_MCP_TOOLS:
            if builtin["mcp_tool"] == query:
                return {
                    "success": True,
                    "query": query,
                    "type": "builtin_mcp_tool",
                    "installed": True,
                    "category": builtin["category"],
                    "description": builtin["description"],
                    "message": f"'{query}' is a built-in HexStrike AI MCP tool and is always available.",
                }

        # 2. Check if it matches a CLI tool name directly, or an MCP tool mapped to a CLI tool
        matched_tool: Optional[Dict[str, Any]] = None
        if query in self._status_cache:
            matched_tool = self._status_cache[query]
        else:
            for tinfo in self._status_cache.values():
                if query in tinfo.get("mcp_tools", []) or query == tinfo.get("binary"):
                    matched_tool = tinfo
                    break

        if matched_tool:
            cat = matched_tool["category"]
            alternatives = [
                {
                    "tool": other["name"],
                    "mcp_tools": other["mcp_tools"],
                    "api_endpoints": other["api_endpoints"],
                    "description": other["description"],
                }
                for other in self._status_cache.values()
                if other["category"] == cat and other["name"] != matched_tool["name"] and other["installed"]
            ]
            name = matched_tool["name"]
            return {
                "success": True,
                "query": query,
                "tool": name,
                "binary": matched_tool["binary"],
                "binary_path": matched_tool["binary_path"],
                "category": cat,
                "enabled_in_manifest": matched_tool["enabled"],
                "installed": matched_tool["installed"],
                "profiles": matched_tool["profiles"],
                "mcp_tools": matched_tool["mcp_tools"],
                "api_endpoints": matched_tool["api_endpoints"],
                "description": matched_tool["description"],
                "installed_alternatives_in_category": alternatives,
                "install_hint": (
                    None
                    if matched_tool["installed"]
                    else (
                        f"Enable '{name}' in config/tools_manifest.json or rebuild container with "
                        f"--build-arg EXTRA_TOOLS={name} (or run: python3 /app/docker/install_tools.py --extra-tools {name})"
                    )
                ),
            }

        # 3. Fallback: probe arbitrary binary on system PATH
        path = shutil.which(query)
        return {
            "success": True,
            "query": query,
            "tool": query,
            "binary": query,
            "binary_path": path,
            "category": "unmanaged",
            "enabled_in_manifest": False,
            "installed": path is not None,
            "mcp_tools": ["execute_command"] if path else [],
            "api_endpoints": ["/api/command"] if path else [],
            "description": "System binary outside config/tools_manifest.json",
            "installed_alternatives_in_category": [],
        }

    def get_registry_report(
        self,
        category: Optional[str] = None,
        installed_only: bool = False,
        enabled_only: bool = False,
        profile: Optional[str] = None,
        refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        Build a structured report of available tools, categories, and MCP tool mappings
        so MCP clients and AI agents know exactly what can be executed.
        """
        self._ensure_fresh(refresh=refresh)

        filtered_tools: Dict[str, Dict[str, Any]] = {}
        for name, info in self._status_cache.items():
            if category and info["category"].lower() != category.lower():
                continue
            if installed_only and not info["installed"]:
                continue
            if enabled_only and not info["enabled"]:
                continue
            if profile and profile not in info.get("profiles", []):
                continue
            filtered_tools[name] = info

        # Category statistics across all manifest tools
        categories_summary: Dict[str, Dict[str, Any]] = {}
        for name, info in self._status_cache.items():
            cat = info["category"]
            if cat not in categories_summary:
                categories_summary[cat] = {
                    "total_in_manifest": 0,
                    "enabled_in_manifest": 0,
                    "installed": 0,
                    "installed_tools": [],
                    "missing_enabled_tools": [],
                }
            categories_summary[cat]["total_in_manifest"] += 1
            if info["enabled"]:
                categories_summary[cat]["enabled_in_manifest"] += 1
            if info["installed"]:
                categories_summary[cat]["installed"] += 1
                categories_summary[cat]["installed_tools"].append(name)
            elif info["enabled"]:
                categories_summary[cat]["missing_enabled_tools"].append(name)

        # Build MCP tool availability map
        available_mcp_tools: Dict[str, Dict[str, Any]] = {}
        unavailable_mcp_tools: Dict[str, Dict[str, Any]] = {}

        for name, info in self._status_cache.items():
            for mcp_fn in info.get("mcp_tools", []):
                if mcp_fn == "execute_command":
                    continue
                if info["installed"]:
                    available_mcp_tools[mcp_fn] = {
                        "cli_tool": name,
                        "binary_path": info["binary_path"],
                        "category": info["category"],
                        "api_endpoints": info["api_endpoints"],
                        "description": info["description"],
                    }
                elif mcp_fn not in available_mcp_tools:
                    unavailable_mcp_tools[mcp_fn] = {
                        "missing_cli_tool": name,
                        "category": info["category"],
                        "profiles": info["profiles"],
                        "how_to_enable": f"--build-arg EXTRA_TOOLS={name}",
                    }

        total_manifest = len(self._status_cache)
        total_enabled = sum(1 for i in self._status_cache.values() if i["enabled"])
        total_installed = sum(1 for i in self._status_cache.values() if i["installed"])
        essential_tools = [n for n, i in self._status_cache.items() if i["essential"]]
        essential_installed = [n for n in essential_tools if self._status_cache[n]["installed"]]

        return {
            "success": True,
            "active_profile": self.get_active_profile(),
            "manifest_version": self._manifest_data.get("version", "6.0.0"),
            "manifest_path": str(self.manifest_path),
            "container_build_state": self._build_state or None,
            "storage_volumes": {
                "data_dir": DATA_DIR,
                "results_dir": RESULTS_DIR,
                "files_dir": FILES_DIR,
                "envs_dir": ENVS_DIR,
            },
            "summary": {
                "total_manifest_tools": total_manifest,
                "enabled_in_manifest": total_enabled,
                "installed_count": total_installed,
                "essential_tools_total": len(essential_tools),
                "essential_tools_installed": len(essential_installed),
                "all_essential_installed": len(essential_installed) == len(essential_tools),
                "available_cli_mcp_tools_count": len(available_mcp_tools),
                "builtin_mcp_tools_count": len(BUILTIN_MCP_TOOLS),
            },
            "categories": categories_summary,
            "tools": filtered_tools,
            "mcp_capabilities": {
                "available_cli_mcp_tools": available_mcp_tools,
                "unavailable_cli_mcp_tools": unavailable_mcp_tools,
                "builtin_mcp_tools": BUILTIN_MCP_TOOLS,
            },
            "timestamp": datetime.now().isoformat(),
        }


# Global singleton instance
tool_registry = ToolRegistry()

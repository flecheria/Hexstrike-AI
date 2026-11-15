#!/usr/bin/env python3
"""
HexStrike AI - Intelligent Decision Engine, Target Profiling & Parameter Optimization
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import ipaddress
import json
import re
import socket
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse
import psutil

from src.config import logger
from src.core.error_handler import FailureRecoverySystem, failure_recovery

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert TargetProfile to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)

class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"

    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate

    def calculate_success_probability(self):
        """Calculate overall success probability of the attack chain"""
        if not self.steps:
            self.success_probability = 0.0
            return

        # Use compound probability for sequential steps
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability

        self.success_probability = prob

    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }


class TechnologyDetector:
    """Advanced technology detection system for context-aware parameter selection"""

    def __init__(self):
        self.detection_patterns = {
            "web_servers": {
                "apache": ["Apache", "apache", "httpd"],
                "nginx": ["nginx", "Nginx"],
                "iis": ["Microsoft-IIS", "IIS"],
                "tomcat": ["Tomcat", "Apache-Coyote"],
                "jetty": ["Jetty"],
                "lighttpd": ["lighttpd"]
            },
            "frameworks": {
                "django": ["Django", "django", "csrftoken"],
                "flask": ["Flask", "Werkzeug"],
                "express": ["Express", "X-Powered-By: Express"],
                "laravel": ["Laravel", "laravel_session"],
                "symfony": ["Symfony", "symfony"],
                "rails": ["Ruby on Rails", "rails", "_session_id"],
                "spring": ["Spring", "JSESSIONID"],
                "struts": ["Struts", "struts"]
            },
            "cms": {
                "wordpress": ["wp-content", "wp-includes", "WordPress", "/wp-admin/"],
                "drupal": ["Drupal", "drupal", "/sites/default/", "X-Drupal-Cache"],
                "joomla": ["Joomla", "joomla", "/administrator/", "com_content"],
                "magento": ["Magento", "magento", "Mage.Cookies"],
                "prestashop": ["PrestaShop", "prestashop"],
                "opencart": ["OpenCart", "opencart"]
            },
            "databases": {
                "mysql": ["MySQL", "mysql", "phpMyAdmin"],
                "postgresql": ["PostgreSQL", "postgres"],
                "mssql": ["Microsoft SQL Server", "MSSQL"],
                "oracle": ["Oracle", "oracle"],
                "mongodb": ["MongoDB", "mongo"],
                "redis": ["Redis", "redis"]
            },
            "languages": {
                "php": ["PHP", "php", ".php", "X-Powered-By: PHP"],
                "python": ["Python", "python", ".py"],
                "java": ["Java", "java", ".jsp", ".do"],
                "dotnet": ["ASP.NET", ".aspx", ".asp", "X-AspNet-Version"],
                "nodejs": ["Node.js", "node", ".js"],
                "ruby": ["Ruby", "ruby", ".rb"],
                "go": ["Go", "golang"],
                "rust": ["Rust", "rust"]
            },
            "security": {
                "waf": ["cloudflare", "CloudFlare", "X-CF-Ray", "incapsula", "Incapsula", "sucuri", "Sucuri"],
                "load_balancer": ["F5", "BigIP", "HAProxy", "nginx", "AWS-ALB"],
                "cdn": ["CloudFront", "Fastly", "KeyCDN", "MaxCDN", "Cloudflare"]
            }
        }

        self.port_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
            8080: "http-alt",
            8443: "https-alt",
            9200: "elasticsearch",
            11211: "memcached"
        }

    def detect_technologies(self, target: str, headers: Dict[str, str] = None, content: str = "", ports: List[int] = None) -> Dict[str, List[str]]:
        """Comprehensive technology detection"""
        detected = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "databases": [],
            "languages": [],
            "security": [],
            "services": []
        }

        # Header-based detection
        if headers:
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for header_name, header_value in headers.items():
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower() or pattern.lower() in header_name.lower():
                                if tech not in detected[category]:
                                    detected[category].append(tech)

        # Content-based detection
        if content:
            content_lower = content.lower()
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in content_lower:
                            if tech not in detected[category]:
                                detected[category].append(tech)

        # Port-based service detection
        if ports:
            for port in ports:
                if port in self.port_services:
                    service = self.port_services[port]
                    if service not in detected["services"]:
                        detected["services"].append(service)

        return detected

class RateLimitDetector:
    """Intelligent rate limiting detection and automatic timing adjustment"""

    def __init__(self):
        self.rate_limit_indicators = [
            "rate limit",
            "too many requests",
            "429",
            "throttle",
            "slow down",
            "retry after",
            "quota exceeded",
            "api limit",
            "request limit"
        ]

        self.timing_profiles = {
            "aggressive": {"delay": 0.1, "threads": 50, "timeout": 5},
            "normal": {"delay": 0.5, "threads": 20, "timeout": 10},
            "conservative": {"delay": 1.0, "threads": 10, "timeout": 15},
            "stealth": {"delay": 2.0, "threads": 5, "timeout": 30}
        }

    def detect_rate_limiting(self, response_text: str, status_code: int, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Detect rate limiting from response"""
        rate_limit_detected = False
        confidence = 0.0
        indicators_found = []

        # Status code check
        if status_code == 429:
            rate_limit_detected = True
            confidence += 0.8
            indicators_found.append("HTTP 429 status")

        # Response text check
        response_lower = response_text.lower()
        for indicator in self.rate_limit_indicators:
            if indicator in response_lower:
                rate_limit_detected = True
                confidence += 0.2
                indicators_found.append(f"Text: '{indicator}'")

        # Header check
        if headers:
            rate_limit_headers = ["x-ratelimit", "retry-after", "x-rate-limit"]
            for header_name in headers.keys():
                for rl_header in rate_limit_headers:
                    if rl_header.lower() in header_name.lower():
                        rate_limit_detected = True
                        confidence += 0.3
                        indicators_found.append(f"Header: {header_name}")

        confidence = min(1.0, confidence)

        return {
            "detected": rate_limit_detected,
            "confidence": confidence,
            "indicators": indicators_found,
            "recommended_profile": self._recommend_timing_profile(confidence)
        }

    def _recommend_timing_profile(self, confidence: float) -> str:
        """Recommend timing profile based on rate limit confidence"""
        if confidence >= 0.8:
            return "stealth"
        elif confidence >= 0.5:
            return "conservative"
        elif confidence >= 0.2:
            return "normal"
        else:
            return "aggressive"

    def adjust_timing(self, current_params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Adjust timing parameters based on profile"""
        timing = self.timing_profiles.get(profile, self.timing_profiles["normal"])

        adjusted_params = current_params.copy()

        # Adjust common parameters
        if "threads" in adjusted_params:
            adjusted_params["threads"] = timing["threads"]
        if "delay" in adjusted_params:
            adjusted_params["delay"] = timing["delay"]
        if "timeout" in adjusted_params:
            adjusted_params["timeout"] = timing["timeout"]

        # Tool-specific adjustments
        if "additional_args" in adjusted_params:
            args = adjusted_params["additional_args"]

            # Remove existing timing arguments
            args = re.sub(r'-t\s+\d+', '', args)
            args = re.sub(r'--threads\s+\d+', '', args)
            args = re.sub(r'--delay\s+[\d.]+', '', args)

            # Add new timing arguments
            args += f" -t {timing['threads']}"
            if timing["delay"] > 0:
                args += f" --delay {timing['delay']}"

            adjusted_params["additional_args"] = args.strip()

        return adjusted_params


class PerformanceMonitor:
    """Advanced performance monitoring with automatic resource allocation"""

    def __init__(self):
        self.performance_metrics = {}
        self.resource_thresholds = {
            "cpu_high": 80.0,
            "memory_high": 85.0,
            "disk_high": 90.0,
            "network_high": 80.0
        }

        self.optimization_rules = {
            "high_cpu": {
                "reduce_threads": 0.5,
                "increase_delay": 2.0,
                "enable_nice": True
            },
            "high_memory": {
                "reduce_batch_size": 0.6,
                "enable_streaming": True,
                "clear_cache": True
            },
            "high_disk": {
                "reduce_output_verbosity": True,
                "enable_compression": True,
                "cleanup_temp_files": True
            },
            "high_network": {
                "reduce_concurrent_connections": 0.7,
                "increase_timeout": 1.5,
                "enable_connection_pooling": True
            }
        }

    def monitor_system_resources(self) -> Dict[str, float]:
        """Monitor current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"Error monitoring system resources: {str(e)}")
            return {}

    def optimize_based_on_resources(self, current_params: Dict[str, Any], resource_usage: Dict[str, float]) -> Dict[str, Any]:
        """Optimize parameters based on current resource usage"""
        optimized_params = current_params.copy()
        optimizations_applied = []

        # CPU optimization
        if resource_usage.get("cpu_percent", 0) > self.resource_thresholds["cpu_high"]:
            if "threads" in optimized_params:
                original_threads = optimized_params["threads"]
                optimized_params["threads"] = max(1, int(original_threads * self.optimization_rules["high_cpu"]["reduce_threads"]))
                optimizations_applied.append(f"Reduced threads from {original_threads} to {optimized_params['threads']}")

            if "delay" in optimized_params:
                original_delay = optimized_params.get("delay", 0)
                optimized_params["delay"] = original_delay * self.optimization_rules["high_cpu"]["increase_delay"]
                optimizations_applied.append(f"Increased delay to {optimized_params['delay']}")

        # Memory optimization
        if resource_usage.get("memory_percent", 0) > self.resource_thresholds["memory_high"]:
            if "batch_size" in optimized_params:
                original_batch = optimized_params["batch_size"]
                optimized_params["batch_size"] = max(1, int(original_batch * self.optimization_rules["high_memory"]["reduce_batch_size"]))
                optimizations_applied.append(f"Reduced batch size from {original_batch} to {optimized_params['batch_size']}")

        # Network optimization
        if "network_bytes_sent" in resource_usage:
            # Simple heuristic for high network usage
            if resource_usage["network_bytes_sent"] > 1000000:  # 1MB/s
                if "concurrent_connections" in optimized_params:
                    original_conn = optimized_params["concurrent_connections"]
                    optimized_params["concurrent_connections"] = max(1, int(original_conn * self.optimization_rules["high_network"]["reduce_concurrent_connections"]))
                    optimizations_applied.append(f"Reduced concurrent connections to {optimized_params['concurrent_connections']}")

        optimized_params["_optimizations_applied"] = optimizations_applied
        return optimized_params

class ParameterOptimizer:
    """Advanced parameter optimization system with intelligent context-aware selection"""

    def __init__(self):
        self.tech_detector = TechnologyDetector()
        self.rate_limiter = RateLimitDetector()
        self.failure_recovery = FailureRecoverySystem()
        self.performance_monitor = PerformanceMonitor()

        # Tool-specific optimization profiles
        self.optimization_profiles = {
            "nmap": {
                "stealth": {
                    "scan_type": "-sS",
                    "timing": "-T2",
                    "additional_args": "--max-retries 1 --host-timeout 300s"
                },
                "normal": {
                    "scan_type": "-sS -sV",
                    "timing": "-T4",
                    "additional_args": "--max-retries 2"
                },
                "aggressive": {
                    "scan_type": "-sS -sV -sC -O",
                    "timing": "-T5",
                    "additional_args": "--max-retries 3 --min-rate 1000"
                }
            },
            "gobuster": {
                "stealth": {
                    "threads": 5,
                    "delay": "1s",
                    "timeout": "30s"
                },
                "normal": {
                    "threads": 20,
                    "delay": "0s",
                    "timeout": "10s"
                },
                "aggressive": {
                    "threads": 50,
                    "delay": "0s",
                    "timeout": "5s"
                }
            },
            "sqlmap": {
                "stealth": {
                    "level": 1,
                    "risk": 1,
                    "threads": 1,
                    "delay": 1
                },
                "normal": {
                    "level": 2,
                    "risk": 2,
                    "threads": 5,
                    "delay": 0
                },
                "aggressive": {
                    "level": 3,
                    "risk": 3,
                    "threads": 10,
                    "delay": 0
                }
            }
        }

    def optimize_parameters_advanced(self, tool: str, target_profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Advanced parameter optimization with full intelligence"""
        if context is None:
            context = {}

        # Get base parameters
        base_params = self._get_base_parameters(tool, target_profile)

        # Detect technologies for context-aware optimization
        detected_tech = self.tech_detector.detect_technologies(
            target_profile.target,
            headers=context.get("headers", {}),
            content=context.get("content", ""),
            ports=target_profile.open_ports
        )

        # Apply technology-specific optimizations
        tech_optimized_params = self._apply_technology_optimizations(tool, base_params, detected_tech)

        # Monitor system resources and optimize accordingly
        resource_usage = self.performance_monitor.monitor_system_resources()
        resource_optimized_params = self.performance_monitor.optimize_based_on_resources(tech_optimized_params, resource_usage)

        # Apply profile-based optimizations
        profile = context.get("optimization_profile", "normal")
        profile_optimized_params = self._apply_profile_optimizations(tool, resource_optimized_params, profile)

        # Add metadata
        profile_optimized_params["_optimization_metadata"] = {
            "detected_technologies": detected_tech,
            "resource_usage": resource_usage,
            "optimization_profile": profile,
            "optimizations_applied": resource_optimized_params.get("_optimizations_applied", []),
            "timestamp": datetime.now().isoformat()
        }

        return profile_optimized_params

    def _get_base_parameters(self, tool: str, profile: TargetProfile) -> Dict[str, Any]:
        """Get base parameters for a tool"""
        base_params = {"target": profile.target}

        # Tool-specific base parameters
        if tool == "nmap":
            base_params.update({
                "scan_type": "-sS",
                "ports": "1-1000",
                "timing": "-T4"
            })
        elif tool == "gobuster":
            base_params.update({
                "mode": "dir",
                "threads": 20,
                "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            })
        elif tool == "sqlmap":
            base_params.update({
                "batch": True,
                "level": 1,
                "risk": 1
            })
        elif tool == "nuclei":
            base_params.update({
                "severity": "critical,high,medium",
                "threads": 25
            })

        return base_params

    def _apply_technology_optimizations(self, tool: str, params: Dict[str, Any], detected_tech: Dict[str, List[str]]) -> Dict[str, Any]:
        """Apply technology-specific optimizations"""
        optimized_params = params.copy()

        # Web server optimizations
        if "apache" in detected_tech.get("web_servers", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,xml,conf"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",apache"

        elif "nginx" in detected_tech.get("web_servers", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,json,conf"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",nginx"

        # CMS optimizations
        if "wordpress" in detected_tech.get("cms", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,xml"
                optimized_params["additional_paths"] = "/wp-content/,/wp-admin/,/wp-includes/"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",wordpress"
            elif tool == "wpscan":
                optimized_params["enumerate"] = "ap,at,cb,dbe"

        # Language-specific optimizations
        if "php" in detected_tech.get("languages", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,php3,php4,php5,phtml,html"
            elif tool == "sqlmap":
                optimized_params["dbms"] = "mysql"

        elif "dotnet" in detected_tech.get("languages", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "aspx,asp,html,txt"
            elif tool == "sqlmap":
                optimized_params["dbms"] = "mssql"

        # Security feature adaptations
        if detected_tech.get("security", []):
            # WAF detected - use stealth mode
            if any(waf in detected_tech["security"] for waf in ["cloudflare", "incapsula", "sucuri"]):
                optimized_params["_stealth_mode"] = True
                if tool == "gobuster":
                    optimized_params["threads"] = min(optimized_params.get("threads", 20), 5)
                    optimized_params["delay"] = "2s"
                elif tool == "sqlmap":
                    optimized_params["delay"] = 2
                    optimized_params["randomize"] = True

        return optimized_params

    def _apply_profile_optimizations(self, tool: str, params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Apply optimization profile settings"""
        if tool not in self.optimization_profiles:
            return params

        profile_settings = self.optimization_profiles[tool].get(profile, {})
        optimized_params = params.copy()

        # Apply profile-specific settings
        for key, value in profile_settings.items():
            optimized_params[key] = value

        # Handle stealth mode flag
        if params.get("_stealth_mode", False) and profile != "stealth":
            # Force stealth settings even if different profile requested
            stealth_settings = self.optimization_profiles[tool].get("stealth", {})
            for key, value in stealth_settings.items():
                optimized_params[key] = value

        return optimized_params

    def handle_tool_failure(self, tool: str, error_output: str, exit_code: int, current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool failure and suggest recovery"""
        failure_analysis = self.failure_recovery.analyze_failure(error_output, exit_code)

        recovery_plan = {
            "original_tool": tool,
            "failure_analysis": failure_analysis,
            "recovery_actions": [],
            "alternative_tools": failure_analysis["alternative_tools"],
            "adjusted_parameters": current_params.copy()
        }

        # Apply automatic parameter adjustments based on failure type
        if failure_analysis["failure_type"] == "timeout":
            if "timeout" in recovery_plan["adjusted_parameters"]:
                recovery_plan["adjusted_parameters"]["timeout"] *= 2
            if "threads" in recovery_plan["adjusted_parameters"]:
                recovery_plan["adjusted_parameters"]["threads"] = max(1, recovery_plan["adjusted_parameters"]["threads"] // 2)
            recovery_plan["recovery_actions"].append("Increased timeout and reduced threads")

        elif failure_analysis["failure_type"] == "rate_limited":
            timing_profile = self.rate_limiter.adjust_timing(recovery_plan["adjusted_parameters"], "stealth")
            recovery_plan["adjusted_parameters"].update(timing_profile)
            recovery_plan["recovery_actions"].append("Applied stealth timing profile")

        return recovery_plan


tech_detector = TechnologyDetector()
rate_limiter = RateLimitDetector()
performance_monitor = PerformanceMonitor()
parameter_optimizer = ParameterOptimizer()

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine"""

    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
        self._use_advanced_optimizer = True  # Enable advanced optimization by default

    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness ratings for different target types"""
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8,
                "gobuster": 0.9,
                "nuclei": 0.95,
                "nikto": 0.85,
                "sqlmap": 0.9,
                "ffuf": 0.9,
                "feroxbuster": 0.85,
                "katana": 0.88,
                "httpx": 0.85,
                "wpscan": 0.95,  # High for WordPress sites
                "burpsuite": 0.9,
                "dirsearch": 0.87,
                "gau": 0.82,
                "waybackurls": 0.8,
                "arjun": 0.9,
                "paramspider": 0.85,
                "x8": 0.88,
                "jaeles": 0.92,
                "dalfox": 0.93,  # High for XSS detection
                "anew": 0.7,  # Utility tool
                "qsreplace": 0.75,  # Utility tool
                "uro": 0.7  # Utility tool
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95,
                "nmap-advanced": 0.97,  # Enhanced Nmap with NSE scripts
                "masscan": 0.92,  # Enhanced with intelligent rate limiting
                "rustscan": 0.9,  # Ultra-fast scanning
                "autorecon": 0.95,  # Comprehensive automated recon
                "enum4linux": 0.8,
                "enum4linux-ng": 0.88,  # Enhanced version
                "smbmap": 0.85,
                "rpcclient": 0.82,
                "nbtscan": 0.75,
                "arp-scan": 0.85,  # Great for network discovery
                "responder": 0.88,  # Excellent for credential harvesting
                "hydra": 0.8,
                "netexec": 0.85,
                "amass": 0.7
            },
            TargetType.API_ENDPOINT.value: {
                "nuclei": 0.9,
                "ffuf": 0.85,
                "arjun": 0.95,  # Excellent for API parameter discovery
                "paramspider": 0.88,
                "httpx": 0.9,  # Great for API probing
                "x8": 0.92,  # Excellent for hidden parameters
                "katana": 0.85,  # Good for API endpoint discovery
                "jaeles": 0.88,
                "postman": 0.8
            },
            TargetType.CLOUD_SERVICE.value: {
                "prowler": 0.95,  # Excellent for AWS security assessment
                "scout-suite": 0.92,  # Great for multi-cloud assessment
                "cloudmapper": 0.88,  # Good for AWS network visualization
                "pacu": 0.85,  # AWS exploitation framework
                "trivy": 0.9,  # Excellent for container scanning
                "clair": 0.85,  # Good for container vulnerability analysis
                "kube-hunter": 0.9,  # Excellent for Kubernetes penetration testing
                "kube-bench": 0.88,  # Great for CIS benchmarks
                "docker-bench-security": 0.85,  # Good for Docker security
                "falco": 0.87,  # Great for runtime monitoring
                "checkov": 0.9,  # Excellent for IaC scanning
                "terrascan": 0.88  # Great for IaC security
            },
            TargetType.BINARY_FILE.value: {
                "ghidra": 0.95,  # Excellent for comprehensive analysis
                "radare2": 0.9,  # Great for reverse engineering
                "gdb": 0.85,
                "gdb-peda": 0.92,  # Enhanced debugging
                "angr": 0.88,  # Excellent for symbolic execution
                "pwntools": 0.9,  # Great for exploit development
                "ropgadget": 0.85,
                "ropper": 0.88,  # Enhanced gadget searching
                "one-gadget": 0.82,  # Specific to libc
                "libc-database": 0.8,  # Specific to libc identification
                "checksec": 0.75,
                "strings": 0.7,
                "objdump": 0.75,
                "binwalk": 0.8,
                "pwninit": 0.85  # Great for CTF setup
            }
        }

    def _initialize_technology_signatures(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize technology detection signatures"""
        return {
            "headers": {
                TechnologyStack.APACHE.value: ["Apache", "apache"],
                TechnologyStack.NGINX.value: ["nginx", "Nginx"],
                TechnologyStack.IIS.value: ["Microsoft-IIS", "IIS"],
                TechnologyStack.PHP.value: ["PHP", "X-Powered-By: PHP"],
                TechnologyStack.NODEJS.value: ["Express", "X-Powered-By: Express"],
                TechnologyStack.PYTHON.value: ["Django", "Flask", "Werkzeug"],
                TechnologyStack.JAVA.value: ["Tomcat", "JBoss", "WebLogic"],
                TechnologyStack.DOTNET.value: ["ASP.NET", "X-AspNet-Version"]
            },
            "content": {
                TechnologyStack.WORDPRESS.value: ["wp-content", "wp-includes", "WordPress"],
                TechnologyStack.DRUPAL.value: ["Drupal", "drupal", "/sites/default"],
                TechnologyStack.JOOMLA.value: ["Joomla", "joomla", "/administrator"],
                TechnologyStack.REACT.value: ["React", "react", "__REACT_DEVTOOLS"],
                TechnologyStack.ANGULAR.value: ["Angular", "angular", "ng-version"],
                TechnologyStack.VUE.value: ["Vue", "vue", "__VUE__"]
            },
            "ports": {
                TechnologyStack.APACHE.value: [80, 443, 8080, 8443],
                TechnologyStack.NGINX.value: [80, 443, 8080],
                TechnologyStack.IIS.value: [80, 443, 8080],
                TechnologyStack.NODEJS.value: [3000, 8000, 8080, 9000]
            }
        }

    def _initialize_attack_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize common attack patterns for different scenarios"""
        return {
            "web_reconnaissance": [
                {"tool": "nmap", "priority": 1, "params": {"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}},
                {"tool": "httpx", "priority": 2, "params": {"probe": True, "tech_detect": True}},
                {"tool": "katana", "priority": 3, "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "priority": 4, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 5, "params": {"get_versions": False}},
                {"tool": "nuclei", "priority": 6, "params": {"severity": "critical,high", "tags": "tech"}},
                {"tool": "dirsearch", "priority": 7, "params": {"extensions": "php,html,js,txt", "threads": 30}},
                {"tool": "gobuster", "priority": 8, "params": {"mode": "dir", "extensions": "php,html,js,txt"}}
            ],
            "api_testing": [
                {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True}},
                {"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": True}},
                {"tool": "x8", "priority": 3, "params": {"method": "GET", "wordlist": "/usr/share/wordlists/x8/params.txt"}},
                {"tool": "paramspider", "priority": 4, "params": {"level": 2}},
                {"tool": "nuclei", "priority": 5, "params": {"tags": "api,graphql,jwt", "severity": "high,critical"}},
                {"tool": "ffuf", "priority": 6, "params": {"mode": "parameter", "method": "POST"}}
            ],
            "network_discovery": [
                {"tool": "arp-scan", "priority": 1, "params": {"local_network": True}},
                {"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "nmap-advanced", "priority": 3, "params": {"scan_type": "-sS", "os_detection": True, "version_detection": True}},
                {"tool": "masscan", "priority": 4, "params": {"rate": 1000, "ports": "1-65535", "banners": True}},
                {"tool": "enum4linux-ng", "priority": 5, "params": {"shares": True, "users": True, "groups": True}},
                {"tool": "nbtscan", "priority": 6, "params": {"verbose": True}},
                {"tool": "smbmap", "priority": 7, "params": {"recursive": True}},
                {"tool": "rpcclient", "priority": 8, "params": {"commands": "enumdomusers;enumdomgroups;querydominfo"}}
            ],
            "vulnerability_assessment": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high,medium", "update": True}},
                {"tool": "jaeles", "priority": 2, "params": {"threads": 20, "timeout": 20}},
                {"tool": "dalfox", "priority": 3, "params": {"mining_dom": True, "mining_dict": True}},
                {"tool": "nikto", "priority": 4, "params": {"comprehensive": True}},
                {"tool": "sqlmap", "priority": 5, "params": {"crawl": 2, "batch": True}}
            ],
            "comprehensive_network_pentest": [
                {"tool": "autorecon", "priority": 1, "params": {"port_scans": "top-1000-ports", "service_scans": "default"}},
                {"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "nmap-advanced", "priority": 3, "params": {"aggressive": True, "nse_scripts": "vuln,exploit"}},
                {"tool": "enum4linux-ng", "priority": 4, "params": {"shares": True, "users": True, "groups": True, "policy": True}},
                {"tool": "responder", "priority": 5, "params": {"wpad": True, "duration": 180}}
            ],
            "binary_exploitation": [
                {"tool": "checksec", "priority": 1, "params": {}},
                {"tool": "ghidra", "priority": 2, "params": {"analysis_timeout": 300, "output_format": "xml"}},
                {"tool": "ropper", "priority": 3, "params": {"gadget_type": "rop", "quality": 2}},
                {"tool": "one-gadget", "priority": 4, "params": {"level": 1}},
                {"tool": "pwntools", "priority": 5, "params": {"exploit_type": "local"}},
                {"tool": "gdb-peda", "priority": 6, "params": {"commands": "checksec\ninfo functions\nquit"}}
            ],
            "ctf_pwn_challenge": [
                {"tool": "pwninit", "priority": 1, "params": {"template_type": "python"}},
                {"tool": "checksec", "priority": 2, "params": {}},
                {"tool": "ghidra", "priority": 3, "params": {"analysis_timeout": 180}},
                {"tool": "ropper", "priority": 4, "params": {"gadget_type": "all", "quality": 3}},
                {"tool": "angr", "priority": 5, "params": {"analysis_type": "symbolic"}},
                {"tool": "one-gadget", "priority": 6, "params": {"level": 2}}
            ],
            "aws_security_assessment": [
                {"tool": "prowler", "priority": 1, "params": {"provider": "aws", "output_format": "json"}},
                {"tool": "scout-suite", "priority": 2, "params": {"provider": "aws"}},
                {"tool": "cloudmapper", "priority": 3, "params": {"action": "collect"}},
                {"tool": "pacu", "priority": 4, "params": {"modules": "iam__enum_users_roles_policies_groups"}}
            ],
            "kubernetes_security_assessment": [
                {"tool": "kube-bench", "priority": 1, "params": {"output_format": "json"}},
                {"tool": "kube-hunter", "priority": 2, "params": {"report": "json"}},
                {"tool": "falco", "priority": 3, "params": {"duration": 120, "output_format": "json"}}
            ],
            "container_security_assessment": [
                {"tool": "trivy", "priority": 1, "params": {"scan_type": "image", "severity": "HIGH,CRITICAL"}},
                {"tool": "clair", "priority": 2, "params": {"output_format": "json"}},
                {"tool": "docker-bench-security", "priority": 3, "params": {}}
            ],
            "iac_security_assessment": [
                {"tool": "checkov", "priority": 1, "params": {"output_format": "json"}},
                {"tool": "terrascan", "priority": 2, "params": {"scan_type": "all", "output_format": "json"}},
                {"tool": "trivy", "priority": 3, "params": {"scan_type": "config", "severity": "HIGH,CRITICAL"}}
            ],
            "multi_cloud_assessment": [
                {"tool": "scout-suite", "priority": 1, "params": {"provider": "aws"}},
                {"tool": "prowler", "priority": 2, "params": {"provider": "aws"}},
                {"tool": "checkov", "priority": 3, "params": {"framework": "terraform"}},
                {"tool": "terrascan", "priority": 4, "params": {"scan_type": "all"}}
            ],
            "bug_bounty_reconnaissance": [
                {"tool": "amass", "priority": 1, "params": {"mode": "enum", "passive": False}},
                {"tool": "subfinder", "priority": 2, "params": {"silent": True, "all_sources": True}},
                {"tool": "httpx", "priority": 3, "params": {"probe": True, "tech_detect": True, "status_code": True}},
                {"tool": "katana", "priority": 4, "params": {"depth": 3, "js_crawl": True, "form_extraction": True}},
                {"tool": "gau", "priority": 5, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 6, "params": {"get_versions": False}},
                {"tool": "paramspider", "priority": 7, "params": {"level": 2}},
                {"tool": "arjun", "priority": 8, "params": {"method": "GET,POST", "stable": True}}
            ],
            "bug_bounty_vulnerability_hunting": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high", "tags": "rce,sqli,xss,ssrf"}},
                {"tool": "dalfox", "priority": 2, "params": {"mining_dom": True, "mining_dict": True}},
                {"tool": "sqlmap", "priority": 3, "params": {"batch": True, "level": 2, "risk": 2}},
                {"tool": "jaeles", "priority": 4, "params": {"threads": 20, "timeout": 20}},
                {"tool": "ffuf", "priority": 5, "params": {"match_codes": "200,204,301,302,307,401,403", "threads": 40}}
            ],
            "bug_bounty_high_impact": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical", "tags": "rce,sqli,ssrf,lfi,xxe"}},
                {"tool": "sqlmap", "priority": 2, "params": {"batch": True, "level": 3, "risk": 3, "tamper": "space2comment"}},
                {"tool": "jaeles", "priority": 3, "params": {"signatures": "rce,sqli,ssrf", "threads": 30}},
                {"tool": "dalfox", "priority": 4, "params": {"blind": True, "mining_dom": True, "custom_payload": "alert(document.domain)"}}
            ]
        }

    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        profile = TargetProfile(target=target)

        # Determine target type
        profile.target_type = self._determine_target_type(target)

        # Basic network analysis
        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            profile.ip_addresses = self._resolve_domain(target)

        # Technology detection (basic heuristics)
        if profile.target_type == TargetType.WEB_APPLICATION:
            profile.technologies = self._detect_technologies(target)
            profile.cms_type = self._detect_cms(target)

        # Calculate attack surface score
        profile.attack_surface_score = self._calculate_attack_surface(profile)

        # Determine risk level
        profile.risk_level = self._determine_risk_level(profile)

        # Set confidence score
        profile.confidence_score = self._calculate_confidence(profile)

        return profile

    def _determine_target_type(self, target: str) -> TargetType:
        """Determine the type of target for appropriate tool selection"""
        # URL patterns
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        # IP address pattern
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return TargetType.NETWORK_HOST

        # Domain name pattern
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return TargetType.WEB_APPLICATION

        # File patterns
        if target.endswith(('.exe', '.bin', '.elf', '.so', '.dll')):
            return TargetType.BINARY_FILE

        # Cloud service patterns
        if any(cloud in target.lower() for cloud in ['amazonaws.com', 'azure', 'googleapis.com']):
            return TargetType.CLOUD_SERVICE

        return TargetType.UNKNOWN

    def _resolve_domain(self, target: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urllib.parse.urlparse(target).hostname
            else:
                hostname = target

            if hostname:
                ip = socket.gethostbyname(hostname)
                return [ip]
        except Exception:
            pass
        return []

    def _detect_technologies(self, target: str) -> List[TechnologyStack]:
        """Detect technologies using basic heuristics"""
        technologies = []

        # This is a simplified version - in practice, you'd make HTTP requests
        # and analyze headers, content, etc.

        # For now, return some common technologies based on target patterns
        if 'wordpress' in target.lower() or 'wp-' in target.lower():
            technologies.append(TechnologyStack.WORDPRESS)

        if any(ext in target.lower() for ext in ['.php', 'php']):
            technologies.append(TechnologyStack.PHP)

        if any(ext in target.lower() for ext in ['.asp', '.aspx']):
            technologies.append(TechnologyStack.DOTNET)

        return technologies if technologies else [TechnologyStack.UNKNOWN]

    def _detect_cms(self, target: str) -> Optional[str]:
        """Detect CMS type"""
        target_lower = target.lower()

        if 'wordpress' in target_lower or 'wp-' in target_lower:
            return "WordPress"
        elif 'drupal' in target_lower:
            return "Drupal"
        elif 'joomla' in target_lower:
            return "Joomla"

        return None

    def _calculate_attack_surface(self, profile: TargetProfile) -> float:
        """Calculate attack surface score based on profile"""
        score = 0.0

        # Base score by target type
        type_scores = {
            TargetType.WEB_APPLICATION: 7.0,
            TargetType.API_ENDPOINT: 6.0,
            TargetType.NETWORK_HOST: 8.0,
            TargetType.CLOUD_SERVICE: 5.0,
            TargetType.BINARY_FILE: 4.0
        }

        score += type_scores.get(profile.target_type, 3.0)

        # Add points for technologies
        score += len(profile.technologies) * 0.5

        # Add points for open ports
        score += len(profile.open_ports) * 0.3

        # Add points for subdomains
        score += len(profile.subdomains) * 0.2

        # CMS adds attack surface
        if profile.cms_type:
            score += 1.5

        return min(score, 10.0)  # Cap at 10.0

    def _determine_risk_level(self, profile: TargetProfile) -> str:
        """Determine risk level based on attack surface"""
        if profile.attack_surface_score >= 8.0:
            return "critical"
        elif profile.attack_surface_score >= 6.0:
            return "high"
        elif profile.attack_surface_score >= 4.0:
            return "medium"
        elif profile.attack_surface_score >= 2.0:
            return "low"
        else:
            return "minimal"

    def _calculate_confidence(self, profile: TargetProfile) -> float:
        """Calculate confidence score in the analysis"""
        confidence = 0.5  # Base confidence

        # Increase confidence based on available data
        if profile.ip_addresses:
            confidence += 0.1
        if profile.technologies and profile.technologies[0] != TechnologyStack.UNKNOWN:
            confidence += 0.2
        if profile.cms_type:
            confidence += 0.1
        if profile.target_type != TargetType.UNKNOWN:
            confidence += 0.1

        return min(confidence, 1.0)

    def select_optimal_tools(self, profile: TargetProfile, objective: str = "comprehensive") -> List[str]:
        """Select optimal tools based on target profile and objective"""
        target_type = profile.target_type.value
        effectiveness_map = self.tool_effectiveness.get(target_type, {})

        # Get base tools for target type
        base_tools = list(effectiveness_map.keys())

        # Apply objective-based filtering
        if objective == "quick":
            # Select top 3 most effective tools
            sorted_tools = sorted(base_tools, key=lambda t: effectiveness_map.get(t, 0), reverse=True)
            selected_tools = sorted_tools[:3]
        elif objective == "comprehensive":
            # Select all tools with effectiveness > 0.7
            selected_tools = [tool for tool in base_tools if effectiveness_map.get(tool, 0) > 0.7]
        elif objective == "stealth":
            # Select passive tools with lower detection probability
            stealth_tools = ["amass", "subfinder", "httpx", "nuclei"]
            selected_tools = [tool for tool in base_tools if tool in stealth_tools]
        else:
            selected_tools = base_tools

        # Add technology-specific tools
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS and "wpscan" not in selected_tools:
                selected_tools.append("wpscan")
            elif tech == TechnologyStack.PHP and "nikto" not in selected_tools:
                selected_tools.append("nikto")

        return selected_tools

    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Enhanced parameter optimization with advanced intelligence"""
        if context is None:
            context = {}

        # Use advanced parameter optimizer if available
        if hasattr(self, '_use_advanced_optimizer') and self._use_advanced_optimizer:
            return parameter_optimizer.optimize_parameters_advanced(tool, profile, context)

        # Fallback to legacy optimization for compatibility
        optimized_params = {}

        # Tool-specific parameter optimization
        if tool == "nmap":
            optimized_params = self._optimize_nmap_params(profile, context)
        elif tool == "gobuster":
            optimized_params = self._optimize_gobuster_params(profile, context)
        elif tool == "nuclei":
            optimized_params = self._optimize_nuclei_params(profile, context)
        elif tool == "sqlmap":
            optimized_params = self._optimize_sqlmap_params(profile, context)
        elif tool == "ffuf":
            optimized_params = self._optimize_ffuf_params(profile, context)
        elif tool == "hydra":
            optimized_params = self._optimize_hydra_params(profile, context)
        elif tool == "rustscan":
            optimized_params = self._optimize_rustscan_params(profile, context)
        elif tool == "masscan":
            optimized_params = self._optimize_masscan_params(profile, context)
        elif tool == "nmap-advanced":
            optimized_params = self._optimize_nmap_advanced_params(profile, context)
        elif tool == "enum4linux-ng":
            optimized_params = self._optimize_enum4linux_ng_params(profile, context)
        elif tool == "autorecon":
            optimized_params = self._optimize_autorecon_params(profile, context)
        elif tool == "ghidra":
            optimized_params = self._optimize_ghidra_params(profile, context)
        elif tool == "pwntools":
            optimized_params = self._optimize_pwntools_params(profile, context)
        elif tool == "ropper":
            optimized_params = self._optimize_ropper_params(profile, context)
        elif tool == "angr":
            optimized_params = self._optimize_angr_params(profile, context)
        elif tool == "prowler":
            optimized_params = self._optimize_prowler_params(profile, context)
        elif tool == "scout-suite":
            optimized_params = self._optimize_scout_suite_params(profile, context)
        elif tool == "kube-hunter":
            optimized_params = self._optimize_kube_hunter_params(profile, context)
        elif tool == "trivy":
            optimized_params = self._optimize_trivy_params(profile, context)
        elif tool == "checkov":
            optimized_params = self._optimize_checkov_params(profile, context)
        else:
            # Use advanced optimizer for unknown tools
            return parameter_optimizer.optimize_parameters_advanced(tool, profile, context)

        return optimized_params

    def enable_advanced_optimization(self):
        """Enable advanced parameter optimization"""
        self._use_advanced_optimizer = True

    def disable_advanced_optimization(self):
        """Disable advanced parameter optimization (use legacy)"""
        self._use_advanced_optimizer = False

    def _optimize_nmap_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Nmap parameters"""
        params = {"target": profile.target}

        if profile.target_type == TargetType.WEB_APPLICATION:
            params["scan_type"] = "-sV -sC"
            params["ports"] = "80,443,8080,8443,8000,9000"
        elif profile.target_type == TargetType.NETWORK_HOST:
            params["scan_type"] = "-sS -O"
            params["additional_args"] = "--top-ports 1000"

        # Adjust timing based on stealth requirements
        if context.get("stealth", False):
            params["additional_args"] = params.get("additional_args", "") + " -T2"
        else:
            params["additional_args"] = params.get("additional_args", "") + " -T4"

        return params

    def _optimize_gobuster_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Gobuster parameters"""
        params = {"url": profile.target, "mode": "dir"}

        # Select wordlist based on detected technologies
        if TechnologyStack.PHP in profile.technologies:
            params["additional_args"] = "-x php,html,txt,xml"
        elif TechnologyStack.DOTNET in profile.technologies:
            params["additional_args"] = "-x asp,aspx,html,txt"
        elif TechnologyStack.JAVA in profile.technologies:
            params["additional_args"] = "-x jsp,html,txt,xml"
        else:
            params["additional_args"] = "-x html,php,txt,js"

        # Adjust threads based on target type
        if context.get("aggressive", False):
            params["additional_args"] += " -t 50"
        else:
            params["additional_args"] += " -t 20"

        return params

    def _optimize_nuclei_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Nuclei parameters"""
        params = {"target": profile.target}

        # Set severity based on context
        if context.get("quick", False):
            params["severity"] = "critical,high"
        else:
            params["severity"] = "critical,high,medium"

        # Add technology-specific tags
        tags = []
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS:
                tags.append("wordpress")
            elif tech == TechnologyStack.DRUPAL:
                tags.append("drupal")
            elif tech == TechnologyStack.JOOMLA:
                tags.append("joomla")

        if tags:
            params["tags"] = ",".join(tags)

        return params

    def _optimize_sqlmap_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize SQLMap parameters"""
        params = {"url": profile.target}

        # Add database-specific options based on detected technologies
        if TechnologyStack.PHP in profile.technologies:
            params["additional_args"] = "--dbms=mysql --batch"
        elif TechnologyStack.DOTNET in profile.technologies:
            params["additional_args"] = "--dbms=mssql --batch"
        else:
            params["additional_args"] = "--batch"

        # Adjust aggressiveness
        if context.get("aggressive", False):
            params["additional_args"] += " --level=3 --risk=2"

        return params

    def _optimize_ffuf_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize FFuf parameters"""
        params = {"url": profile.target}

        # Set match codes based on target type
        if profile.target_type == TargetType.API_ENDPOINT:
            params["match_codes"] = "200,201,202,204,301,302,401,403"
        else:
            params["match_codes"] = "200,204,301,302,307,401,403"

        # Adjust threads
        if context.get("stealth", False):
            params["additional_args"] = "-t 10 -p 1"
        else:
            params["additional_args"] = "-t 40"

        return params

    def _optimize_hydra_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Hydra parameters"""
        params = {"target": profile.target}

        # Determine service based on open ports
        if 22 in profile.open_ports:
            params["service"] = "ssh"
        elif 21 in profile.open_ports:
            params["service"] = "ftp"
        elif 80 in profile.open_ports or 443 in profile.open_ports:
            params["service"] = "http-get"
        else:
            params["service"] = "ssh"  # Default

        # Set conservative parameters to avoid lockouts
        params["additional_args"] = "-t 4 -w 30"

        return params

    def _optimize_rustscan_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Rustscan parameters"""
        params = {"target": profile.target}

        # Adjust performance based on context
        if context.get("stealth", False):
            params["ulimit"] = 1000
            params["batch_size"] = 500
            params["timeout"] = 3000
        elif context.get("aggressive", False):
            params["ulimit"] = 10000
            params["batch_size"] = 8000
            params["timeout"] = 800
        else:
            params["ulimit"] = 5000
            params["batch_size"] = 4500
            params["timeout"] = 1500

        # Enable scripts for comprehensive scans
        if context.get("objective", "normal") == "comprehensive":
            params["scripts"] = True

        return params

    def _optimize_masscan_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Masscan parameters"""
        params = {"target": profile.target}

        # Intelligent rate limiting based on target type
        if context.get("stealth", False):
            params["rate"] = 100
        elif context.get("aggressive", False):
            params["rate"] = 10000
        else:
            # Default intelligent rate
            params["rate"] = 1000

        # Enable banners for service detection
        if context.get("service_detection", True):
            params["banners"] = True

        return params

    def _optimize_nmap_advanced_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize advanced Nmap parameters"""
        params = {"target": profile.target}

        # Select scan type based on context
        if context.get("stealth", False):
            params["scan_type"] = "-sS"
            params["timing"] = "T2"
            params["stealth"] = True
        elif context.get("aggressive", False):
            params["scan_type"] = "-sS"
            params["timing"] = "T4"
            params["aggressive"] = True
        else:
            params["scan_type"] = "-sS"
            params["timing"] = "T4"
            params["os_detection"] = True
            params["version_detection"] = True

        # Add NSE scripts based on target type
        if profile.target_type == TargetType.WEB_APPLICATION:
            params["nse_scripts"] = "http-*,ssl-*"
        elif profile.target_type == TargetType.NETWORK_HOST:
            params["nse_scripts"] = "default,discovery,safe"

        return params

    def _optimize_enum4linux_ng_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Enum4linux-ng parameters"""
        params = {"target": profile.target}

        # Enable comprehensive enumeration by default
        params["shares"] = True
        params["users"] = True
        params["groups"] = True
        params["policy"] = True

        # Add authentication if available in context
        if context.get("username"):
            params["username"] = context["username"]
        if context.get("password"):
            params["password"] = context["password"]
        if context.get("domain"):
            params["domain"] = context["domain"]

        return params

    def _optimize_autorecon_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize AutoRecon parameters"""
        params = {"target": profile.target}

        # Adjust scan depth based on objective
        if context.get("quick", False):
            params["port_scans"] = "top-100-ports"
            params["timeout"] = 180
        elif context.get("comprehensive", True):
            params["port_scans"] = "top-1000-ports"
            params["timeout"] = 600

        # Set output directory
        params["output_dir"] = f"/tmp/autorecon_{profile.target.replace('.', '_')}"

        return params

    def _optimize_ghidra_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Ghidra parameters"""
        params = {"binary": profile.target}

        # Adjust analysis timeout based on context
        if context.get("quick", False):
            params["analysis_timeout"] = 120
        elif context.get("comprehensive", True):
            params["analysis_timeout"] = 600
        else:
            params["analysis_timeout"] = 300

        # Set project name based on binary
        binary_name = os.path.basename(profile.target).replace('.', '_')
        params["project_name"] = f"hexstrike_{binary_name}"

        return params

    def _optimize_pwntools_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Pwntools parameters"""
        params = {"target_binary": profile.target}

        # Set exploit type based on context
        if context.get("remote_host") and context.get("remote_port"):
            params["exploit_type"] = "remote"
            params["target_host"] = context["remote_host"]
            params["target_port"] = context["remote_port"]
        else:
            params["exploit_type"] = "local"

        return params

    def _optimize_ropper_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Ropper parameters"""
        params = {"binary": profile.target}

        # Set gadget type and quality based on context
        if context.get("exploit_type") == "rop":
            params["gadget_type"] = "rop"
            params["quality"] = 3
        elif context.get("exploit_type") == "jop":
            params["gadget_type"] = "jop"
            params["quality"] = 2
        else:
            params["gadget_type"] = "all"
            params["quality"] = 2

        # Set architecture if known
        if context.get("arch"):
            params["arch"] = context["arch"]

        return params

    def _optimize_angr_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize angr parameters"""
        params = {"binary": profile.target}

        # Set analysis type based on context
        if context.get("symbolic_execution", True):
            params["analysis_type"] = "symbolic"
        elif context.get("cfg_analysis", False):
            params["analysis_type"] = "cfg"
        else:
            params["analysis_type"] = "static"

        # Add find/avoid addresses if provided
        if context.get("find_address"):
            params["find_address"] = context["find_address"]
        if context.get("avoid_addresses"):
            params["avoid_addresses"] = context["avoid_addresses"]

        return params

    def _optimize_prowler_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Prowler parameters"""
        params = {"provider": "aws"}

        # Set provider based on context or target analysis
        if context.get("cloud_provider"):
            params["provider"] = context["cloud_provider"]

        # Set profile and region
        if context.get("aws_profile"):
            params["profile"] = context["aws_profile"]
        if context.get("aws_region"):
            params["region"] = context["aws_region"]

        # Set output format and directory
        params["output_format"] = "json"
        params["output_dir"] = f"/tmp/prowler_{params['provider']}"

        return params

    def _optimize_scout_suite_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Scout Suite parameters"""
        params = {"provider": "aws"}

        # Set provider based on context
        if context.get("cloud_provider"):
            params["provider"] = context["cloud_provider"]

        # Set profile for AWS
        if params["provider"] == "aws" and context.get("aws_profile"):
            params["profile"] = context["aws_profile"]

        # Set report directory
        params["report_dir"] = f"/tmp/scout-suite_{params['provider']}"

        return params

    def _optimize_kube_hunter_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize kube-hunter parameters"""
        params = {"report": "json"}

        # Set target based on context
        if context.get("kubernetes_target"):
            params["target"] = context["kubernetes_target"]
        elif context.get("cidr"):
            params["cidr"] = context["cidr"]
        elif context.get("interface"):
            params["interface"] = context["interface"]

        # Enable active hunting if specified
        if context.get("active_hunting", False):
            params["active"] = True

        return params

    def _optimize_trivy_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Trivy parameters"""
        params = {"target": profile.target, "output_format": "json"}

        # Determine scan type based on target
        if profile.target.startswith(('docker.io/', 'gcr.io/', 'quay.io/')) or ':' in profile.target:
            params["scan_type"] = "image"
        elif os.path.isdir(profile.target):
            params["scan_type"] = "fs"
        else:
            params["scan_type"] = "image"  # Default

        # Set severity filter
        if context.get("severity"):
            params["severity"] = context["severity"]
        else:
            params["severity"] = "HIGH,CRITICAL"

        return params

    def _optimize_checkov_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Checkov parameters"""
        params = {"directory": profile.target, "output_format": "json"}

        # Detect framework based on files in directory
        if context.get("framework"):
            params["framework"] = context["framework"]
        elif os.path.isdir(profile.target):
            # Auto-detect framework
            if any(f.endswith('.tf') for f in os.listdir(profile.target) if os.path.isfile(os.path.join(profile.target, f))):
                params["framework"] = "terraform"
            elif any(f.endswith('.yaml') or f.endswith('.yml') for f in os.listdir(profile.target) if os.path.isfile(os.path.join(profile.target, f))):
                params["framework"] = "kubernetes"

        return params

    def create_attack_chain(self, profile: TargetProfile, objective: str = "comprehensive") -> AttackChain:
        """Create an intelligent attack chain based on target profile"""
        chain = AttackChain(profile)

        # Select attack pattern based on target type and objective
        if profile.target_type == TargetType.WEB_APPLICATION:
            if objective == "quick":
                pattern = self.attack_patterns["vulnerability_assessment"][:2]
            else:
                pattern = self.attack_patterns["web_reconnaissance"] + self.attack_patterns["vulnerability_assessment"]
        elif profile.target_type == TargetType.API_ENDPOINT:
            pattern = self.attack_patterns["api_testing"]
        elif profile.target_type == TargetType.NETWORK_HOST:
            if objective == "comprehensive":
                pattern = self.attack_patterns["comprehensive_network_pentest"]
            else:
                pattern = self.attack_patterns["network_discovery"]
        elif profile.target_type == TargetType.BINARY_FILE:
            if objective == "ctf":
                pattern = self.attack_patterns["ctf_pwn_challenge"]
            else:
                pattern = self.attack_patterns["binary_exploitation"]
        elif profile.target_type == TargetType.CLOUD_SERVICE:
            if objective == "aws":
                pattern = self.attack_patterns["aws_security_assessment"]
            elif objective == "kubernetes":
                pattern = self.attack_patterns["kubernetes_security_assessment"]
            elif objective == "containers":
                pattern = self.attack_patterns["container_security_assessment"]
            elif objective == "iac":
                pattern = self.attack_patterns["iac_security_assessment"]
            else:
                pattern = self.attack_patterns["multi_cloud_assessment"]
        else:
            # Handle bug bounty specific objectives
            if objective == "bug_bounty_recon":
                pattern = self.attack_patterns["bug_bounty_reconnaissance"]
            elif objective == "bug_bounty_hunting":
                pattern = self.attack_patterns["bug_bounty_vulnerability_hunting"]
            elif objective == "bug_bounty_high_impact":
                pattern = self.attack_patterns["bug_bounty_high_impact"]
            else:
                pattern = self.attack_patterns["web_reconnaissance"]

        # Create attack steps
        for step_config in pattern:
            tool = step_config["tool"]
            optimized_params = self.optimize_parameters(tool, profile)

            # Calculate success probability based on tool effectiveness
            effectiveness = self.tool_effectiveness.get(profile.target_type.value, {}).get(tool, 0.5)
            success_prob = effectiveness * profile.confidence_score

            # Estimate execution time (simplified)
            time_estimates = {
                "nmap": 120, "gobuster": 300, "nuclei": 180, "nikto": 240,
                "sqlmap": 600, "ffuf": 200, "hydra": 900, "amass": 300,
                "ghidra": 300, "radare2": 180, "gdb": 120, "gdb-peda": 150,
                "angr": 600, "pwntools": 240, "ropper": 120, "one-gadget": 60,
                "checksec": 30, "pwninit": 60, "libc-database": 90,
                "prowler": 600, "scout-suite": 480, "cloudmapper": 300, "pacu": 420,
                "trivy": 180, "clair": 240, "kube-hunter": 300, "kube-bench": 120,
                "docker-bench-security": 180, "falco": 120, "checkov": 240, "terrascan": 200
            }
            exec_time = time_estimates.get(tool, 180)

            step = AttackStep(
                tool=tool,
                parameters=optimized_params,
                expected_outcome=f"Discover vulnerabilities using {tool}",
                success_probability=success_prob,
                execution_time_estimate=exec_time
            )

            chain.add_step(step)

        # Calculate overall chain metrics
        chain.calculate_success_probability()
        chain.risk_level = profile.risk_level

        return chain

# Global decision engine instance
decision_engine = IntelligentDecisionEngine()


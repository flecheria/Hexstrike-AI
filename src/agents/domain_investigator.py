#!/usr/bin/env python3
"""
HexStrike AI - Single & Multi-Domain Security Investigation Manager

Coordinates security investigations, reconnaissance, technology profiling,
attack chain creation, workflow planning, and live tool execution across
single or multiple domains.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

from src.config import logger
from src.core.domain_utils import normalize_targets, extract_domain, ensure_url
from src.core.tool_registry import tool_registry
from src.core.executor import (
    execute_command,
    execute_nmap_scan,
    execute_gobuster_scan,
    execute_nuclei_scan,
    execute_nikto_scan,
    execute_sqlmap_scan,
    execute_ffuf_scan,
    execute_feroxbuster_scan,
    execute_katana_scan,
    execute_httpx_scan,
    execute_wpscan_scan,
    execute_dirsearch_scan,
    execute_arjun_scan,
    execute_paramspider_scan,
    execute_dalfox_scan,
    execute_amass_scan,
    execute_subfinder_scan,
)
from src.agents.decision_engine import decision_engine
from src.agents.bugbounty import BugBountyTarget, bugbounty_manager


class DomainInvestigationManager:
    """
    Coordinates security investigations across a single domain or multiple domains,
    combining AI target profiling, tool selection, parameter optimization,
    reconnaissance/bug-bounty workflows, and optional live tool execution.
    """

    DEFAULT_RECON_TOOLS = ["subfinder", "amass", "httpx", "nmap", "katana"]

    def __init__(self) -> None:
        self.tool_executors: Dict[str, Callable[[str, Dict[str, Any]], Dict[str, Any]]] = {
            "nmap": lambda t, p: execute_nmap_scan(extract_domain(t) or t, p),
            "gobuster": lambda t, p: execute_gobuster_scan(ensure_url(t), p),
            "nuclei": lambda t, p: execute_nuclei_scan(ensure_url(t), p),
            "nikto": lambda t, p: execute_nikto_scan(ensure_url(t), p),
            "sqlmap": lambda t, p: execute_sqlmap_scan(ensure_url(t), p),
            "ffuf": lambda t, p: execute_ffuf_scan(ensure_url(t), p),
            "feroxbuster": lambda t, p: execute_feroxbuster_scan(ensure_url(t), p),
            "katana": lambda t, p: execute_katana_scan(ensure_url(t), p),
            "httpx": lambda t, p: execute_httpx_scan(extract_domain(t) or t, p),
            "wpscan": lambda t, p: execute_wpscan_scan(ensure_url(t), p),
            "dirsearch": lambda t, p: execute_dirsearch_scan(ensure_url(t), p),
            "arjun": lambda t, p: execute_arjun_scan(ensure_url(t), p),
            "paramspider": lambda t, p: execute_paramspider_scan(extract_domain(t) or t, p),
            "dalfox": lambda t, p: execute_dalfox_scan(ensure_url(t), p),
            "amass": lambda t, p: execute_amass_scan(extract_domain(t) or t, p),
            "subfinder": lambda t, p: execute_subfinder_scan(extract_domain(t) or t, p),
            "fierce": lambda t, p: execute_command(f"fierce --domain {extract_domain(t) or t} {p.get('additional_args', '')}".strip()),
            "dnsenum": lambda t, p: execute_command(f"dnsenum --noreverse {extract_domain(t) or t} {p.get('additional_args', '')}".strip()),
            "wafw00f": lambda t, p: execute_command(f"wafw00f {ensure_url(t)} {p.get('additional_args', '')}".strip()),
            "gau": lambda t, p: execute_command(f"gau {extract_domain(t) or t} {p.get('additional_args', '')}".strip()),
            "waybackurls": lambda t, p: execute_command(f"echo {extract_domain(t) or t} | waybackurls {p.get('additional_args', '')}".strip()),
        }

    def investigate_single_domain(
        self,
        raw_target: str,
        objective: str = "comprehensive",
        include_workflows: bool = True,
        execute_tools: bool = False,
        tools: Optional[List[str]] = None,
        max_tools: int = 5,
    ) -> Dict[str, Any]:
        """Run a full investigation on a single domain/target."""
        clean_domain = extract_domain(raw_target) or raw_target.strip()
        target_url = ensure_url(raw_target)

        logger.info(f"🔍 Investigating domain: {clean_domain} (objective={objective}, execute_tools={execute_tools})")

        profile = decision_engine.analyze_target(clean_domain)
        if tools:
            selected_tools = tools
        else:
            candidates = decision_engine.select_optimal_tools(profile, objective)
            if execute_tools:
                installed_candidates = [t for t in candidates if tool_registry.is_tool_installed(t)]
                selected_tools = (installed_candidates or candidates)[:max_tools]
            else:
                selected_tools = candidates[:max_tools]
        attack_chain = decision_engine.create_attack_chain(profile, objective)

        optimized_parameters: Dict[str, Dict[str, Any]] = {}
        for tool_name in selected_tools:
            optimized_parameters[tool_name] = decision_engine.optimize_parameters(tool_name, profile)

        report: Dict[str, Any] = {
            "domain": clean_domain,
            "input_target": raw_target,
            "target_url": target_url,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "selected_tools": selected_tools,
            "optimized_parameters": optimized_parameters,
            "attack_chain": attack_chain.to_dict(),
        }

        if include_workflows:
            bb_target = BugBountyTarget(domain=clean_domain)
            report["workflows"] = {
                "reconnaissance": bugbounty_manager.create_reconnaissance_workflow(bb_target),
                "vulnerability_hunting": bugbounty_manager.create_vulnerability_hunting_workflow(bb_target),
                "osint": bugbounty_manager.create_osint_workflow(bb_target),
            }

        if execute_tools:
            tool_results: List[Dict[str, Any]] = []
            total_vulns = 0
            for tool_name in selected_tools:
                params = optimized_parameters.get(tool_name, {})
                executor_fn = self.tool_executors.get(tool_name)
                if executor_fn:
                    res = executor_fn(raw_target, params)
                    stdout = res.get("stdout", "") if isinstance(res, dict) else ""
                    vuln_indicators = ["CRITICAL", "HIGH", "MEDIUM", "VULNERABILITY", "EXPLOIT", "SQL injection", "XSS", "CSRF"]
                    vuln_count = sum(1 for ind in vuln_indicators if ind.lower() in stdout.lower())
                    total_vulns += vuln_count
                    tool_results.append({
                        "tool": tool_name,
                        "parameters": params,
                        "success": bool(res.get("success")) if isinstance(res, dict) else False,
                        "command": res.get("command", "") if isinstance(res, dict) else "",
                        "execution_time": res.get("execution_time", 0) if isinstance(res, dict) else 0,
                        "vulnerabilities_found": vuln_count,
                        "stdout": stdout,
                        "stderr": res.get("stderr", "") if isinstance(res, dict) else "",
                    })
                else:
                    tool_results.append({
                        "tool": tool_name,
                        "parameters": params,
                        "success": False,
                        "status": "skipped",
                        "error": f"No live executor configured for {tool_name}",
                    })

            report["execution"] = {
                "executed": True,
                "tools_run": len(tool_results),
                "successful_tools": sum(1 for r in tool_results if r.get("success")),
                "total_vulnerabilities": total_vulns,
                "tool_results": tool_results,
            }
        else:
            report["execution"] = {"executed": False}

        return report

    def investigate_domains(
        self,
        domains_input: Union[str, List[str]],
        objective: str = "comprehensive",
        include_workflows: bool = True,
        execute_tools: bool = False,
        tools: Optional[List[str]] = None,
        max_tools: int = 5,
        parallel: bool = True,
        max_workers: int = 5,
    ) -> Dict[str, Any]:
        """
        Investigate single or multiple domains and produce both per-domain reports
        and cross-domain correlation intelligence.
        """
        targets = normalize_targets(domains_input)
        if not targets:
            return {"success": False, "error": "At least one domain or target is required"}

        worker_count = min(max_workers, len(targets), 10)
        results_by_domain: Dict[str, Dict[str, Any]] = {}

        if parallel and len(targets) > 1 and worker_count > 1:
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                fut_map = {
                    pool.submit(
                        self.investigate_single_domain,
                        t,
                        objective,
                        include_workflows,
                        execute_tools,
                        tools,
                        max_tools,
                    ): t
                    for t in targets
                }
                temp_map: Dict[str, Dict[str, Any]] = {}
                for fut in as_completed(fut_map):
                    t_key = fut_map[fut]
                    try:
                        temp_map[t_key] = fut.result()
                    except Exception as exc:
                        logger.error(f"Error investigating {t_key}: {exc}")
                        temp_map[t_key] = {"domain": extract_domain(t_key) or t_key, "success": False, "error": str(exc)}
            for t in targets:
                d_key = temp_map[t].get("domain", t)
                results_by_domain[d_key] = temp_map[t]
        else:
            for t in targets:
                rep = self.investigate_single_domain(
                    t, objective, include_workflows, execute_tools, tools, max_tools
                )
                results_by_domain[rep.get("domain", t)] = rep

        # Build cross-domain correlation summary
        risk_distribution: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        tech_frequency: Dict[str, List[str]] = {}
        tool_recommendations_union: List[str] = []

        for dom, rep in results_by_domain.items():
            prof = rep.get("target_profile", {})
            risk = str(prof.get("risk_level", "unknown")).lower()
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1

            for tech in prof.get("technologies", []):
                tech_frequency.setdefault(tech, []).append(dom)

            for tl in rep.get("selected_tools", []):
                if tl not in tool_recommendations_union:
                    tool_recommendations_union.append(tl)

        shared_technologies = {tech: doms for tech, doms in tech_frequency.items() if len(doms) > 1}

        return {
            "success": True,
            "mode": "multi_domain" if len(targets) > 1 else "single_domain",
            "total_domains": len(targets),
            "domains": list(results_by_domain.keys()),
            "objective": objective,
            "summary": {
                "risk_distribution": risk_distribution,
                "technologies_across_domains": tech_frequency,
                "shared_technologies": shared_technologies,
                "recommended_tools_union": tool_recommendations_union,
            },
            "results_by_domain": results_by_domain,
            "timestamp": datetime.now().isoformat(),
        }

    def recon_domains(
        self,
        domains_input: Union[str, List[str]],
        tools: Optional[List[str]] = None,
        execute_tools: bool = False,
        parallel: bool = True,
    ) -> Dict[str, Any]:
        """Run or plan reconnaissance across single or multiple domains."""
        recon_tools = tools if tools else self.DEFAULT_RECON_TOOLS
        return self.investigate_domains(
            domains_input=domains_input,
            objective="quick",
            include_workflows=True,
            execute_tools=execute_tools,
            tools=recon_tools,
            max_tools=len(recon_tools),
            parallel=parallel,
        )

    def compare_domains(
        self,
        domains_input: Union[str, List[str]],
        objective: str = "comprehensive",
    ) -> Dict[str, Any]:
        """Compare security posture, target profiles, and attack surfaces across domains."""
        base = self.investigate_domains(
            domains_input=domains_input,
            objective=objective,
            include_workflows=False,
            execute_tools=False,
            parallel=True,
        )
        if not base.get("success"):
            return base

        comparison_matrix: List[Dict[str, Any]] = []
        for dom, rep in base.get("results_by_domain", {}).items():
            prof = rep.get("target_profile", {})
            chain = rep.get("attack_chain", {})
            comparison_matrix.append({
                "domain": dom,
                "target_type": prof.get("target_type", "unknown"),
                "risk_level": prof.get("risk_level", "unknown"),
                "attack_surface_score": prof.get("attack_surface_score", 0.0),
                "confidence_score": prof.get("confidence_score", 0.0),
                "technologies": prof.get("technologies", []),
                "cms_type": prof.get("cms_type"),
                "recommended_tools": rep.get("selected_tools", []),
                "estimated_assessment_time": chain.get("estimated_time", 0),
                "success_probability": chain.get("success_probability", 0.0),
            })

        # Sort by attack_surface_score descending
        comparison_matrix.sort(key=lambda x: x.get("attack_surface_score", 0.0), reverse=True)

        return {
            "success": True,
            "total_domains": len(comparison_matrix),
            "domains": [c["domain"] for c in comparison_matrix],
            "prioritized_ranking": comparison_matrix,
            "summary": base.get("summary", {}),
            "timestamp": datetime.now().isoformat(),
        }


domain_investigator = DomainInvestigationManager()

#!/usr/bin/env python3
"""
HexStrike AI - Single & Multi-Domain Target Normalization and Dispatch Utilities

Provides helper utilities and a custom FastAPI APIRouter (`MultiTargetAPIRouter`)
that enables every security tool, reconnaissance, bug bounty, and intelligence
endpoint to seamlessly investigate either a single domain/target or multiple
domains/targets in parallel.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import wraps
import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from src.config import logger


# Canonical mapping from plural/singular payload keys to the singular key expected by handlers
TARGET_KEY_PAIRS: List[Tuple[str, str]] = [
    ("domains", "domain"),
    ("targets", "target"),
    ("target_urls", "target_url"),
    ("urls", "url"),
]


def normalize_targets(raw_value: Union[str, List[str], Tuple[str, ...], set, None]) -> List[str]:
    """
    Normalize a single domain/target string, a comma/newline-separated string,
    or a collection of strings into a clean, deduplicated list of targets.
    """
    if raw_value is None:
        return []

    items: List[str] = []
    if isinstance(raw_value, str):
        # Support comma-separated or newline-separated domains/targets
        # Avoid splitting if it's a single URL or command flag containing commas in query params
        if "\n" in raw_value:
            parts = [p.strip() for p in raw_value.splitlines()]
        elif "," in raw_value and not ("?" in raw_value and "=" in raw_value):
            parts = [p.strip() for p in raw_value.split(",")]
        else:
            parts = [raw_value.strip()]
        items.extend(p for p in parts if p)
    elif isinstance(raw_value, (list, tuple, set)):
        for elem in raw_value:
            if isinstance(elem, str):
                items.extend(normalize_targets(elem))
            elif elem is not None:
                s = str(elem).strip()
                if s:
                    items.append(s)

    # Deduplicate while preserving order
    seen = set()
    deduped: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def extract_domain(target: str) -> str:
    """Extract clean domain/hostname from a URL or domain string."""
    if not target:
        return ""
    cleaned = target.strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        host = parsed.netloc or parsed.path.split("/")[0]
    else:
        host = cleaned.split("/")[0]
    # Strip port if present (unless IPv6)
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    return host.strip().lower()


def ensure_url(target: str, default_scheme: str = "https") -> str:
    """Ensure a domain/target has an HTTP/HTTPS scheme when required by web tools."""
    if not target:
        return ""
    cleaned = target.strip()
    if cleaned.startswith(("http://", "https://")):
        return cleaned
    return f"{default_scheme}://{cleaned}"


def extract_multi_target_info(
    data: Optional[Dict[str, Any]],
    preferred_singular_key: Optional[str] = None,
) -> Tuple[Optional[str], List[str], bool]:
    """
    Inspect a request payload dictionary for single or multiple domains/targets.

    Returns:
        (singular_key, targets_list, is_explicit_multi)
    """
    if not isinstance(data, dict):
        return None, [], False

    # 1. Check explicit plural keys first (domains, targets, target_urls, urls)
    for plural_key, singular_key in TARGET_KEY_PAIRS:
        if plural_key in data and data[plural_key] is not None:
            targets = normalize_targets(data[plural_key])
            resolved_key = preferred_singular_key or singular_key
            # If the payload didn't specify the singular key, infer whether handler uses domain, target, url, or target_url
            if preferred_singular_key is None:
                for _, sk in TARGET_KEY_PAIRS:
                    if sk in data:
                        resolved_key = sk
                        break
            return resolved_key, targets, True

    # 2. Check singular keys (domain, target, target_url, url) that might contain a list or comma-separated domains
    for _, singular_key in TARGET_KEY_PAIRS:
        if singular_key in data and data[singular_key] is not None:
            raw_val = data[singular_key]
            targets = normalize_targets(raw_val)
            is_multi = isinstance(raw_val, (list, tuple, set)) or len(targets) > 1
            return singular_key, targets, is_multi

    return None, [], False


def _unwrap_response(resp: Any) -> Tuple[Dict[str, Any], int]:
    """Convert a route handler return value (dict or JSONResponse) into (dict, status_code)."""
    if isinstance(resp, JSONResponse):
        try:
            body_dict = json.loads(resp.body.decode("utf-8"))
        except Exception:
            body_dict = {"raw_body": resp.body.decode("utf-8", errors="replace")}
        return body_dict, resp.status_code
    if isinstance(resp, dict):
        return resp, 200
    return {"result": resp}, 200


def wrap_endpoint_for_multi_target(func: Callable) -> Callable:
    """
    Decorator that wraps a FastAPI POST endpoint accepting a dict body (`data` or `params`)
    so that it supports both single and multiple domains/targets transparently.
    """
    sig = inspect.signature(func)
    param_names = list(sig.parameters.keys())
    if len(param_names) != 1:
        return func

    body_param_name = param_names[0]

    # Inspect function source/bytecode constants to see which singular key it primarily expects
    code_consts = getattr(func, "__code__", None)
    consts = set(code_consts.co_consts) if code_consts else set()
    preferred_key: Optional[str] = None
    for candidate in ("domain", "target_url", "url", "target"):
        if candidate in consts:
            preferred_key = candidate
            break

    @wraps(func)
    def wrapper(*args, **kwargs):
        data = kwargs.get(body_param_name) if body_param_name in kwargs else (args[0] if args else None)
        if not isinstance(data, dict):
            return func(*args, **kwargs)

        singular_key, targets, is_explicit_multi = extract_multi_target_info(data, preferred_key)
        force_multi = bool(data.get("multi_domain") or data.get("multi_target"))

        if not singular_key or not targets:
            return func(*args, **kwargs)

        # Single target/domain path -> 100% backwards-compatible response
        if len(targets) == 1 and not force_multi:
            single_payload = dict(data)
            for plural_key, _ in TARGET_KEY_PAIRS:
                single_payload.pop(plural_key, None)
            single_payload[singular_key] = targets[0]
            # Also populate fallback alias if neither domain nor target was present originally
            if preferred_key and preferred_key not in single_payload:
                single_payload[preferred_key] = targets[0]
            return func(**{body_param_name: single_payload})

        # Multi-domain / multi-target execution path
        parallel = data.get("parallel", True)
        max_workers = min(int(data.get("max_workers", 5)), len(targets), 10)
        logger.info(
            f"🌐 Multi-domain execution for {func.__name__} across {len(targets)} targets "
            f"(parallel={parallel}, max_workers={max_workers})"
        )

        def run_single(target_val: str) -> Tuple[str, Dict[str, Any], int]:
            item_payload = dict(data)
            for plural_key, _ in TARGET_KEY_PAIRS:
                item_payload.pop(plural_key, None)
            item_payload.pop("multi_domain", None)
            item_payload.pop("multi_target", None)
            item_payload[singular_key] = target_val
            if preferred_key and preferred_key not in item_payload:
                item_payload[preferred_key] = target_val
            try:
                raw_res = func(**{body_param_name: item_payload})
                res_dict, status_code = _unwrap_response(raw_res)
                return target_val, res_dict, status_code
            except Exception as exc:
                logger.error(f"❌ Error executing {func.__name__} for target {target_val}: {exc}")
                return target_val, {"success": False, "error": str(exc), "target": target_val}, 500

        results_by_target: Dict[str, Dict[str, Any]] = {}
        ordered_results: List[Dict[str, Any]] = []
        successful_targets: List[str] = []
        failed_targets: List[str] = []

        if parallel and max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                future_map = {pool.submit(run_single, t): t for t in targets}
                temp_results: Dict[str, Tuple[Dict[str, Any], int]] = {}
                for fut in as_completed(future_map):
                    t_val, r_dict, s_code = fut.result()
                    temp_results[t_val] = (r_dict, s_code)
            for t_val in targets:
                r_dict, s_code = temp_results[t_val]
                results_by_target[t_val] = r_dict
                ordered_results.append({"target": t_val, "status_code": s_code, "result": r_dict})
                if s_code < 400 and r_dict.get("success", True):
                    successful_targets.append(t_val)
                else:
                    failed_targets.append(t_val)
        else:
            for t_val in targets:
                _, r_dict, s_code = run_single(t_val)
                results_by_target[t_val] = r_dict
                ordered_results.append({"target": t_val, "status_code": s_code, "result": r_dict})
                if s_code < 400 and r_dict.get("success", True):
                    successful_targets.append(t_val)
                else:
                    failed_targets.append(t_val)

        return {
            "success": len(successful_targets) > 0,
            "multi_domain": True,
            "endpoint": func.__name__,
            "targets": targets,
            "total_targets": len(targets),
            "successful_count": len(successful_targets),
            "failed_count": len(failed_targets),
            "successful_targets": successful_targets,
            "failed_targets": failed_targets,
            "results_by_target": results_by_target,
            "results": ordered_results,
            "timestamp": datetime.now().isoformat(),
        }

    wrapper.__signature__ = sig  # type: ignore[attr-defined]
    setattr(wrapper, "_multi_target_wrapped", True)
    return wrapper


class MultiTargetAPIRouter(APIRouter):
    """
    FastAPI APIRouter subclass that automatically wraps POST endpoints with
    single/multi-domain target normalization and parallel multi-target execution.
    """

    def add_api_route(self, path: str, endpoint: Callable, **kwargs: Any) -> None:
        methods = kwargs.get("methods") or []
        if any(m.upper() == "POST" for m in methods) and not getattr(endpoint, "_multi_target_wrapped", False):
            endpoint = wrap_endpoint_for_multi_target(endpoint)
        super().add_api_route(path, endpoint, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Callable:
        parent_decorator = super().post(path, **kwargs)

        def decorator(func: Callable) -> Callable:
            wrapped = wrap_endpoint_for_multi_target(func)
            parent_decorator(wrapped)
            return wrapped

        return decorator

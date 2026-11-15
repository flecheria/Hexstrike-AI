#!/usr/bin/env python3
"""
HexStrike AI - Configurable Container Tool Installer

Reads `config/tools_manifest.json` and installs the selected subset of security
tools based on:
  1. Profile (`--profile recon_network_scan`, `minimal`, `manifest`, `web_security`, `full`, etc.)
  2. Extra tools (`--extra-tools hydra,john,trivy`)
  3. Excluded tools (`--exclude-tools amass,masscan`)

Writes the resulting installation state to `config/installed_tools.json` so the
HexStrike server and MCP client know the exact build profile and installed tools.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Set
import urllib.request
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "tools_manifest.json"
DEFAULT_STATE_OUT = PROJECT_ROOT / "config" / "installed_tools.json"
OPT_TOOLS_DIR = Path("/opt/hexstrike-tools")
BIN_DIR = Path("/usr/local/bin")

DEFAULT_COMMON_WORDLIST = [
    "admin", "login", "api", "v1", "v2", "graphql", "swagger", "docs",
    "config", "backup", "db", "test", "dev", "staging", "uploads", "static",
    "assets", "images", "js", "css", "robots.txt", "sitemap.xml", ".env",
    ".git/HEAD", "wp-admin", "wp-login.php", "phpmyadmin", "console",
    "status", "health", "metrics", "actuator", "debug", "server-status",
]


def log(msg: str) -> None:
    print(f"[HexStrike-Installer] {msg}", flush=True)


def detect_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return "amd64"


def run_cmd(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def is_tool_present(tool_name: str, binary_spec: str) -> bool:
    if tool_name == "angr" or "import angr" in binary_spec:
        res = subprocess.run([sys.executable, "-c", "import angr"], capture_output=True)
        return res.returncode == 0
    if tool_name == "pwntools":
        if shutil.which("pwn"):
            return True
        res = subprocess.run([sys.executable, "-c", "import pwn"], capture_output=True)
        return res.returncode == 0

    binary = (binary_spec or tool_name).split()[0]
    return shutil.which(binary) is not None or shutil.which(tool_name) is not None


def select_tools(
    manifest: Dict[str, Any],
    profile: str,
    extra_tools: Set[str],
    exclude_tools: Set[str],
) -> List[str]:
    tools_cfg = manifest.get("tools", {})
    selected: List[str] = []

    for name, meta in tools_cfg.items():
        if name in exclude_tools:
            continue
        include = False
        if profile in ("manifest", "enabled", "custom"):
            include = bool(meta.get("enabled", False))
        elif profile == "all" or profile == "full":
            include = True
        else:
            include = profile in meta.get("profiles", [])
            if profile == manifest.get("default_profile") and meta.get("enabled", False):
                include = True

        if name in extra_tools:
            include = True

        if include:
            selected.append(name)

    # Also warn if user passed an unknown tool in extra_tools
    for extra in extra_tools:
        if extra not in tools_cfg and extra not in exclude_tools:
            log(f"WARNING: Extra tool '{extra}' is not in manifest; attempting apt/pip fallback.")
            selected.append(extra)

    return selected


def apt_package_available(pkg: str) -> bool:
    res = subprocess.run(["apt-cache", "show", pkg], capture_output=True, text=True)
    return res.returncode == 0 and bool(res.stdout.strip())


def install_apt_packages(packages: List[str]) -> bool:
    if not packages:
        return True
    unique_pkgs = sorted(set(packages))
    log(f"Updating apt cache and installing {len(unique_pkgs)} apt package(s): {', '.join(unique_pkgs)}")
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    subprocess.run(["apt-get", "update", "-qq"], env=env, check=False)
    available_pkgs = [p for p in unique_pkgs if apt_package_available(p)]
    missing_pkgs = [p for p in unique_pkgs if p not in available_pkgs]
    if missing_pkgs:
        log(f"Note: apt packages not found in current distro repos (will use fallback if configured): {', '.join(missing_pkgs)}")

    if not available_pkgs:
        return False

    cmd = ["apt-get", "install", "-y", "--no-install-recommends"] + available_pkgs
    res = subprocess.run(cmd, env=env)
    if res.returncode != 0:
        log("Batch apt-get install encountered an error; retrying package-by-package...")
        for pkg in available_pkgs:
            subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", pkg], env=env)
    return True


def install_pip_package(pkg: str) -> bool:
    log(f"Installing Python package via pip: {pkg}")
    cmd = [sys.executable, "-m", "pip", "install", "--no-cache-dir", pkg]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 and "break-system-packages" in (res.stderr or ""):
        cmd.append("--break-system-packages")
        res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        log(f"WARNING: pip install failed for {pkg}: {res.stderr.strip()[:300]}")
        return False
    return True


def install_github_release(tool_name: str, binary_name: str, spec: Dict[str, Any], arch: str) -> bool:
    repo = spec.get("repo", "")
    patterns = spec.get("asset_patterns", {}).get(arch, [])
    if not repo or not patterns:
        return False

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    log(f"Fetching latest GitHub release for {tool_name} ({repo}) [{arch}]...")
    headers = {"User-Agent": "HexStrike-AI-Container-Builder"}
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            release_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        log(f"WARNING: Could not fetch GitHub release metadata for {repo}: {e}")
        return False

    assets = release_data.get("assets", [])
    matched_asset: Optional[Dict[str, Any]] = None
    for pat in patterns:
        regex = re.compile(pat, re.IGNORECASE)
        for asset in assets:
            if regex.search(asset.get("name", "")):
                matched_asset = asset
                break
        if matched_asset:
            break

    if not matched_asset:
        log(f"WARNING: No matching release asset found in {repo} for arch={arch}")
        return False

    download_url = matched_asset["browser_download_url"]
    asset_name = matched_asset["name"]
    log(f"Downloading {asset_name} from {download_url}...")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            archive_path = tmp_path / asset_name
            dl_req = urllib.request.Request(download_url, headers=headers)
            with urllib.request.urlopen(dl_req, timeout=120) as resp, open(archive_path, "wb") as out_f:
                shutil.copyfileobj(resp, out_f)

            extract_dir = tmp_path / "extracted"
            extract_dir.mkdir(parents=True, exist_ok=True)

            if asset_name.endswith(".deb"):
                res = subprocess.run(["dpkg", "-i", str(archive_path)], capture_output=True, text=True)
                return res.returncode == 0

            if asset_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_dir)
                # Check if inner tar.gz exists (e.g. rustscan.tar.gz.zip)
                for inner_tar in extract_dir.rglob("*.tar.gz"):
                    with tarfile.open(inner_tar, "r:gz") as tf:
                        tf.extractall(extract_dir)
            elif asset_name.endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive_path, "r:gz") as tf:
                    tf.extractall(extract_dir)
            else:
                # Raw binary
                target_bin = BIN_DIR / binary_name
                shutil.copy2(archive_path, target_bin)
                target_bin.chmod(target_bin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                return True

            # Locate the binary inside extract_dir
            candidates = list(extract_dir.rglob(binary_name))
            if not candidates and tool_name != binary_name:
                candidates = list(extract_dir.rglob(tool_name))

            for candidate in candidates:
                if candidate.is_file():
                    target_bin = BIN_DIR / binary_name
                    shutil.copy2(candidate, target_bin)
                    target_bin.chmod(0o755)
                    log(f"Installed {binary_name} -> {target_bin}")
                    return True

            log(f"WARNING: Binary '{binary_name}' not found inside archive {asset_name}")
            return False
    except Exception as e:
        log(f"WARNING: Failed to install {tool_name} from GitHub release: {e}")
        return False


def install_git_tool(tool_name: str, binary_name: str, spec: Dict[str, Any]) -> bool:
    repo_url = spec.get("url", "")
    entrypoint = spec.get("entrypoint", "")
    if not repo_url or not entrypoint:
        return False

    apt_deps = spec.get("apt_deps", [])
    if apt_deps:
        install_apt_packages(apt_deps)

    pip_deps = spec.get("pip_deps", [])
    for dep in pip_deps:
        install_pip_package(dep)

    OPT_TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    dest_dir = OPT_TOOLS_DIR / tool_name
    if dest_dir.exists():
        shutil.rmtree(dest_dir)

    log(f"Cloning {repo_url} -> {dest_dir}...")
    res = subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest_dir)], capture_output=True, text=True)
    if res.returncode != 0:
        log(f"WARNING: git clone failed for {tool_name}: {res.stderr.strip()}")
        return False

    entry_path = dest_dir / entrypoint
    if not entry_path.exists():
        log(f"WARNING: Entrypoint {entry_path} not found in cloned repository")
        return False

    entry_path.chmod(0o755)
    wrapper_path = BIN_DIR / binary_name
    if wrapper_path.exists() or wrapper_path.is_symlink():
        wrapper_path.unlink()

    if entrypoint.endswith(".py"):
        wrapper_path.write_text(f"#!/usr/bin/env bash\nexec python3 {entry_path} \"$@\"\n", encoding="utf-8")
        wrapper_path.chmod(0o755)
    elif entrypoint.endswith(".pl"):
        wrapper_path.write_text(f"#!/usr/bin/env bash\nexec perl {entry_path} \"$@\"\n", encoding="utf-8")
        wrapper_path.chmod(0o755)
    else:
        wrapper_path.symlink_to(entry_path)

    log(f"Linked {binary_name} -> {entry_path}")
    return True


def ensure_default_wordlists() -> None:
    wordlist_dir = Path("/usr/share/wordlists/dirb")
    common_txt = wordlist_dir / "common.txt"
    if not common_txt.exists():
        try:
            wordlist_dir.mkdir(parents=True, exist_ok=True)
            common_txt.write_text("\n".join(DEFAULT_COMMON_WORDLIST) + "\n", encoding="utf-8")
            log(f"Created default discovery wordlist at {common_txt}")
        except OSError as e:
            log(f"Note: Could not create default wordlist at {common_txt}: {e}")


def write_installed_state(
    manifest: Dict[str, Any],
    profile: str,
    selected_tools: List[str],
    extra_tools: Set[str],
    exclude_tools: Set[str],
    state_out: Path,
) -> Dict[str, Any]:
    tools_cfg = manifest.get("tools", {})
    verification: Dict[str, Dict[str, Any]] = {}
    installed_list: List[str] = []
    missing_selected: List[str] = []

    for name, meta in tools_cfg.items():
        binary_spec = meta.get("binary", name)
        present = is_tool_present(name, binary_spec)
        bin_path = shutil.which(binary_spec.split()[0]) or shutil.which(name)
        verification[name] = {
            "installed": present,
            "binary": binary_spec,
            "binary_path": bin_path,
            "category": meta.get("category", "additional"),
            "selected_in_build": name in selected_tools,
            "mcp_tools": meta.get("mcp_tools", []),
            "api_endpoints": meta.get("api_endpoints", []),
        }
        if present:
            installed_list.append(name)
        elif name in selected_tools:
            missing_selected.append(name)

    state = {
        "version": manifest.get("version", "6.0.0"),
        "profile": profile,
        "architecture": detect_arch(),
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "selected_tools": selected_tools,
        "extra_tools": sorted(extra_tools),
        "excluded_tools": sorted(exclude_tools),
        "installed_tools": installed_list,
        "missing_selected_tools": missing_selected,
        "installed_count": len(installed_list),
        "selected_count": len(selected_tools),
        "tools": verification,
    }

    state_out.parent.mkdir(parents=True, exist_ok=True)
    with open(state_out, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    log(f"Wrote container tool state to {state_out} ({len(installed_list)} tools available)")
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure and install HexStrike AI container security tools")
    parser.add_argument("--manifest", type=str, default=str(DEFAULT_MANIFEST), help="Path to tools_manifest.json")
    parser.add_argument("--state-output", type=str, default=str(DEFAULT_STATE_OUT), help="Path to write installed_tools.json")
    parser.add_argument("--profile", type=str, default=os.environ.get("TOOL_PROFILE", "recon_network_scan"),
                        help="Build profile to install (recon_network_scan, minimal, manifest, web_security, auth_password, binary_forensics, cloud_security, full)")
    parser.add_argument("--extra-tools", type=str, default=os.environ.get("EXTRA_TOOLS", ""),
                        help="Comma-separated list of extra tools to install")
    parser.add_argument("--exclude-tools", type=str, default=os.environ.get("EXCLUDE_TOOLS", ""),
                        help="Comma-separated list of tools to skip")
    parser.add_argument("--list", action="store_true", help="List profiles and tools in the manifest and exit")
    parser.add_argument("--verify-only", action="store_true", help="Only probe currently installed tools and write state file")
    parser.add_argument("--dry-run", action="store_true", help="Print selected tools without installing")
    parser.add_argument("--skip-wordlists", action="store_true", help="Do not create default fallback wordlists")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        log(f"ERROR: Manifest file not found at {manifest_path}")
        return 1

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    extra_set = {t.strip() for t in args.extra_tools.split(",") if t.strip()}
    exclude_set = {t.strip() for t in args.exclude_tools.split(",") if t.strip()}
    profile = args.profile.strip() or manifest.get("default_profile", "recon_network_scan")

    if args.list:
        print(f"Default Profile: {manifest.get('default_profile')}")
        print("\nAvailable Profiles:")
        for pname, pmeta in manifest.get("profiles", {}).items():
            ptools = select_tools(manifest, pname, set(), set())
            print(f"  - {pname:20s}: {pmeta.get('description', '')} ({len(ptools)} tools: {', '.join(ptools)})")
        return 0

    selected = select_tools(manifest, profile, extra_set, exclude_set)
    log(f"Profile: {profile} | Selected {len(selected)} tool(s): {', '.join(selected)}")

    if args.dry_run:
        return 0

    if args.verify_only:
        write_installed_state(manifest, profile, selected, extra_set, exclude_set, Path(args.state_output))
        return 0

    arch = detect_arch()
    tools_cfg = manifest.get("tools", {})

    # Phase 1: Collect apt packages for selected tools that are not yet installed
    apt_queue: List[str] = []
    fallback_queue: List[str] = []

    for name in selected:
        meta = tools_cfg.get(name, {"binary": name, "install": {"method": "apt", "package": name}})
        binary_spec = meta.get("binary", name)
        if is_tool_present(name, binary_spec):
            log(f"Tool '{name}' ({binary_spec}) is already installed.")
            continue

        install_spec = meta.get("install", {})
        if install_spec.get("method") == "apt":
            pkg = install_spec.get("package", name)
            apt_queue.append(pkg)
            if install_spec.get("fallback"):
                fallback_queue.append(name)

    if apt_queue:
        install_apt_packages(apt_queue)

    # Phase 2: Process pip, github_release, git, and any apt fallbacks
    for name in selected:
        meta = tools_cfg.get(name, {"binary": name, "install": {"method": "apt", "package": name}})
        binary_spec = meta.get("binary", name)
        binary_name = binary_spec.split()[0]

        if is_tool_present(name, binary_spec):
            continue

        install_spec = meta.get("install", {})
        method = install_spec.get("method", "apt")

        # If apt failed in Phase 1 and fallback exists, switch to fallback spec
        if method == "apt" and install_spec.get("fallback"):
            install_spec = install_spec["fallback"]
            method = install_spec.get("method", "pip")

        success = False
        if method == "pip":
            success = install_pip_package(install_spec.get("package", name))
        elif method == "github_release":
            success = install_github_release(name, binary_name, install_spec, arch)
        elif method == "git":
            success = install_git_tool(name, binary_name, install_spec)

        # Check secondary fallback if primary non-apt method failed
        if not success and install_spec.get("fallback"):
            fb = install_spec["fallback"]
            fb_method = fb.get("method")
            log(f"Trying fallback method '{fb_method}' for {name}...")
            if fb_method == "apt":
                install_apt_packages([fb.get("package", name)])
            elif fb_method == "pip":
                install_pip_package(fb.get("package", name))
            elif fb_method == "git":
                install_git_tool(name, binary_name, fb)

    if not args.skip_wordlists:
        ensure_default_wordlists()

    # Clean apt cache to keep container layer small
    subprocess.run(["apt-get", "clean"], check=False)
    shutil.rmtree("/var/lib/apt/lists", ignore_errors=True)

    state = write_installed_state(manifest, profile, selected, extra_set, exclude_set, Path(args.state_output))
    log(f"Installation complete: {state['installed_count']}/{state['selected_count']} selected tools ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

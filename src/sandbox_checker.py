"""sandbox_checker.py
─────────────────
Sandbox environment builder and package upgrade simulator.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("pre_upgrade_system")

@dataclass
class SandboxResult:
    success: bool = False
    old_source_dir: str = ""
    new_source_dir: str = ""
    conflict_detected: bool = False
    pip_log: str = ""
    pip_check_output: str = ""
    regression_passed: Optional[bool] = None

def get_venv_executables(venv_path: Path) -> tuple[Path, Path, Path]:
    """Returns absolute paths to python, pip, and pytest executables inside the venv."""
    is_windows = platform.system() == "Windows"
    bin_dir = venv_path / "Scripts" if is_windows else venv_path / "bin"
    
    python_exe = bin_dir / ("python.exe" if is_windows else "python")
    pip_exe = bin_dir / ("pip.exe" if is_windows else "pip")
    pytest_exe = bin_dir / ("pytest.exe" if is_windows else "pytest")
    
    return python_exe, pip_exe, pytest_exe

async def run_command(cmd: list[str], timeout: float = 120.0, cwd: Optional[str] = None) -> tuple[int, str, str]:
    """Helper to run system commands asynchronously."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        try:
            process.kill()
        except OSError:
            pass
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as exc:
        return -1, "", f"Failed to execute command: {exc}"

def find_package_in_site_packages(site_packages: Path, package_name: str) -> Optional[Path]:
    """Locates the package directory in site-packages using normalized or case-insensitive matching."""
    if not site_packages.exists():
        return None
        
    normalized = package_name.lower().replace("-", "_")
    
    # Try exact match
    p = site_packages / package_name
    if p.exists() and p.is_dir():
        return p
        
    p = site_packages / normalized
    if p.exists() and p.is_dir():
        return p
        
    # Case-insensitive matching
    for child in site_packages.iterdir():
        if child.is_dir():
            name_lower = child.name.lower()
            if name_lower == package_name.lower() or name_lower == normalized:
                return child
                
    # Fallback to checking site-packages subdirectories containing files
    # E.g. jinja2 installs as jinja2
    return None

def parse_current_version(repo_path: str, package_name: str) -> Optional[str]:
    """Reads project configuration files to find currently pinned version of package_name."""
    repo_dir = Path(repo_path).resolve()
    normalized_target = package_name.lower().replace("_", "-")
    
    # 1. Parse requirements.txt / requirements-core.txt
    req_files = [repo_dir / "requirements.txt", repo_dir / "requirements-core.txt"]
    for req_file in req_files:
        if req_file.exists():
            try:
                for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Match package==version
                    match = re.match(r"^\s*([\w\-]+)\s*==\s*([\w\.\-]+)", line, re.IGNORECASE)
                    if match:
                        name, ver = match.groups()
                        if name.lower().replace("_", "-") == normalized_target:
                            return ver
            except Exception as e:
                logger.warning("Failed to parse %s: %s", req_file, e)

    # 2. Parse pyproject.toml
    pyproject = repo_dir / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="replace")
            # Look for line: package = "==version" or similar patterns
            match = re.search(rf'"{re.escape(package_name)}"\s*:\s*"\D*([\w\.\-]+)"', content, re.IGNORECASE)
            if match:
                return match.group(1)
            # Try package == "version" pattern
            match = re.search(rf'{re.escape(package_name)}\s*==\s*[\'"]([\w\.\-]+)[\'"]', content, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception as e:
            logger.warning("Failed to parse %s: %s", pyproject, e)

    # 3. Parse setup.cfg
    setup_cfg = repo_dir / "setup.cfg"
    if setup_cfg.exists():
        try:
            content = setup_cfg.read_text(encoding="utf-8", errors="replace")
            match = re.search(rf'{re.escape(package_name)}\s*==\s*([\w\.\-]+)', content, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception as e:
            logger.warning("Failed to parse %s: %s", setup_cfg, e)
            
    return None

async def simulate_upgrade(
    repo_path: str,
    package_name: str,
    target_version: str
) -> SandboxResult:
    """Creates an isolated virtual environment, installs current packages,
    upgrades, runs pip check and checks for regressions.
    """
    repo_dir = Path(repo_path).resolve()
    logger.info("Starting sandbox simulator for %s -> %s", package_name, target_version)
    
    # 1. Determine currently pinned version
    curr_version = parse_current_version(repo_path, package_name)
    logger.info("Detected current version of %s: %s", package_name, curr_version)
    
    temp_sandbox_dir = tempfile.mkdtemp(prefix="sandbox_upgrade_")
    venv_path = Path(temp_sandbox_dir) / "venv"
    
    result = SandboxResult()
    
    try:
        # Create isolated virtual environment
        logger.info("Creating venv at %s", venv_path)
        exit_code, stdout, stderr = await run_command(["python", "-m", "venv", str(venv_path)], timeout=120)
        if exit_code != 0:
            result.pip_log = f"Failed to create virtual environment:\n{stderr}"
            return result
            
        python_exe, pip_exe, pytest_exe = get_venv_executables(venv_path)
        
        # Install baseline packages if requirements.txt exists
        req_file = repo_dir / "requirements.txt"
        if req_file.exists():
            logger.info("Installing project requirements in sandbox...")
            code, out, err = await run_command([str(pip_exe), "install", "-r", str(req_file)], timeout=240)
            result.pip_log += f"--- Baseline requirements install ---\n{out}\n{err}\n"
        elif curr_version:
            # If no requirements file, at least install the target package baseline version
            logger.info("Installing baseline package version %s==%s", package_name, curr_version)
            code, out, err = await run_command([str(pip_exe), "install", f"{package_name}=={curr_version}"], timeout=120)
            result.pip_log += f"--- Baseline package install ---\n{out}\n{err}\n"
            
        # Capture old source dir from site-packages
        site_packages_dir = next(venv_path.glob("**/site-packages"), None)
        if site_packages_dir:
            pkg_path = find_package_in_site_packages(site_packages_dir, package_name)
            if pkg_path and pkg_path.exists():
                old_copy_dir = tempfile.mkdtemp(prefix=f"old_{package_name}_")
                shutil.copytree(pkg_path, Path(old_copy_dir) / package_name, dirs_exist_ok=True)
                result.old_source_dir = old_copy_dir
                logger.info("Copied old source tree to: %s", old_copy_dir)
                
        # Upgrade package to target version
        logger.info("Upgrading package to %s==%s", package_name, target_version)
        code, out, err = await run_command([str(pip_exe), "install", f"{package_name}=={target_version}"], timeout=180)
        result.pip_log += f"--- Package upgrade to {target_version} ---\n{out}\n{err}\n"
        
        if code != 0:
            result.pip_log += f"Upgrade installation failed: {err}\n"
            return result
            
        # Capture new source dir from site-packages after upgrade
        if site_packages_dir:
            pkg_path = find_package_in_site_packages(site_packages_dir, package_name)
            if pkg_path and pkg_path.exists():
                new_copy_dir = tempfile.mkdtemp(prefix=f"new_{package_name}_")
                shutil.copytree(pkg_path, Path(new_copy_dir) / package_name, dirs_exist_ok=True)
                result.new_source_dir = new_copy_dir
                logger.info("Copied new source tree to: %s", new_copy_dir)
                
        # Run pip check for dependency conflicts
        logger.info("Running dependency conflict check (pip check)...")
        code, out, err = await run_command([str(pip_exe), "check"], timeout=45)
        result.pip_check_output = out.strip() + "\n" + err.strip()
        if code != 0:
            result.conflict_detected = True
            logger.warning("Dependency conflict detected: %s", result.pip_check_output)
            
        # Run project tests in sandbox if test/tests directory is present
        test_dir = next((d for d in [repo_dir / "tests", repo_dir / "test"] if d.exists() and d.is_dir()), None)
        if test_dir:
            logger.info("Executing project tests in sandbox...")
            # Ensure pytest is installed
            if not pytest_exe.exists():
                await run_command([str(pip_exe), "install", "pytest"], timeout=60)
            
            t_code, t_out, t_err = await run_command([str(pytest_exe), str(test_dir)], timeout=120, cwd=str(repo_dir))
            result.pip_log += f"--- Regression test run ---\n{t_out}\n{t_err}\n"
            result.regression_passed = (t_code == 0)
            logger.info("Sandbox test run completed. Regression passed: %s", result.regression_passed)
        else:
            result.regression_passed = None
            logger.info("No test directory found. Skipping test phase.")
            
        result.success = True
        
    except Exception as e:
        logger.exception("Exception occurred in sandbox upgraded simulation:")
        result.pip_log += f"\nException in sandbox_checker: {e}\n"
    finally:
        # Clean up temporary venv directory
        logger.info("Cleaning up sandbox virtualenv directory: %s", temp_sandbox_dir)
        shutil.rmtree(temp_sandbox_dir, ignore_errors=True)
        
    return result

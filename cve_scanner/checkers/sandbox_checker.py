from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

from cve_scanner.config import get_settings


def _parse_conflicts(output: str) -> list[str]:
    import re

    return re.findall(r"(?:requires|incompatible)\s+([\w\-]+)", output, re.IGNORECASE)


def _venv_paths(tmpdir: str) -> tuple[str, str]:
    env_dir = Path(tmpdir) / "env"
    if sys.platform.startswith("win"):
        python_path = env_dir / "Scripts" / "python.exe"
        pip_path = env_dir / "Scripts" / "pip.exe"
    else:
        python_path = env_dir / "bin" / "python"
        pip_path = env_dir / "bin" / "pip"
    return str(python_path), str(pip_path)


async def _run_cmd(cmd: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, "", "Command timed out"
    return proc.returncode, stdout.decode(errors="ignore"), stderr.decode(errors="ignore")


async def simulate_upgrade(
    repo_path: str,
    package_name: str,
    target_version: str,
    tmpdir: str | None = None,
    timeout: int | None = None,
) -> dict:
    settings = get_settings()
    timeout = timeout or settings.SANDBOX_TIMEOUT

    if tmpdir is None:
        with tempfile.TemporaryDirectory() as tmp:
            return await _simulate_upgrade_in_dir(repo_path, package_name, target_version, tmp, timeout)

    return await _simulate_upgrade_in_dir(repo_path, package_name, target_version, tmpdir, timeout)


async def _simulate_upgrade_in_dir(
    repo_path: str,
    package_name: str,
    target_version: str,
    tmpdir: str,
    timeout: int,
) -> dict:
    python_path, pip_path = _venv_paths(tmpdir)

    venv_rc, _, venv_err = await _run_cmd(
        [sys.executable, "-m", "venv", str(Path(tmpdir) / "env")],
        timeout=timeout,
    )
    if venv_rc != 0:
        return {
            "success": False,
            "exit_code": venv_rc,
            "raw_output": venv_err,
            "conflict_output": "",
            "conflicting_packages": [],
        }

    req_file = Path(repo_path) / "requirements.txt"
    if req_file.exists():
        await _run_cmd(
            [pip_path, "install", "-r", str(req_file), "--quiet"],
            timeout=timeout,
        )

    install_rc, install_out, install_err = await _run_cmd(
        [pip_path, "install", f"{package_name}=={target_version}"],
        timeout=timeout,
    )
    output = install_err + install_out
    success = install_rc == 0

    conflict_output = ""
    check_rc = 0
    if success:
        check_rc, check_out, check_err = await _run_cmd(
            [pip_path, "check"],
            timeout=timeout,
        )
        conflict_output = check_out + check_err

    combined = output + conflict_output
    return {
        "success": success and check_rc == 0,
        "exit_code": install_rc,
        "raw_output": output[-4000:],
        "conflict_output": conflict_output[-4000:],
        "conflicting_packages": _parse_conflicts(combined),
    }


async def simulate_npm_upgrade(
    repo_path: str,
    package_name: str,
    target_version: str,
    tmpdir: str | None = None,
    timeout: int | None = None,
) -> dict:
    settings = get_settings()
    timeout = timeout or settings.SANDBOX_TIMEOUT

    if tmpdir is None:
        with tempfile.TemporaryDirectory() as tmp:
            return await _simulate_npm_upgrade_in_dir(repo_path, package_name, target_version, tmp, timeout)

    return await _simulate_npm_upgrade_in_dir(repo_path, package_name, target_version, tmpdir, timeout)


async def _simulate_npm_upgrade_in_dir(
    repo_path: str,
    package_name: str,
    target_version: str,
    tmpdir: str,
    timeout: int,
) -> dict:
    repo = Path(repo_path)
    package_json = repo / "package.json"
    lock_file = repo / "package-lock.json"
    if not package_json.exists():
        return {
            "success": False,
            "exit_code": 2,
            "raw_output": "package.json not found",
        }

    tmp = Path(tmpdir)
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "package.json").write_text(package_json.read_text(encoding="utf-8"), encoding="utf-8")
    if lock_file.exists():
        (tmp / "package-lock.json").write_text(lock_file.read_text(encoding="utf-8"), encoding="utf-8")

    rc, out, err = await _run_cmd(
        ["npm", "install", f"{package_name}@{target_version}", "--dry-run", "--json"],
        timeout=timeout,
        cwd=str(tmp),
    )

    return {
        "success": rc == 0,
        "exit_code": rc,
        "raw_output": (out + err)[-4000:],
    }

"""github_fetcher.py
─────────────────
Fetches a GitHub repository by cloning it locally.
"""
from __future__ import annotations

import atexit
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
import asyncio

logger = logging.getLogger("pre_upgrade_system")

# Global list of cloned directories to clean up at exit
_cloned_dirs: list[str] = []

class RepoFetchError(Exception):
    """Exception raised when cloning a repository fails."""
    pass

def _cleanup_cloned_dirs():
    """Cleans up all cloned temporary directories registered during execution."""
    for d in _cloned_dirs:
        if os.path.exists(d):
            try:
                shutil.rmtree(d, ignore_errors=True)
                logger.info("Cleaned up temporary clone directory: %s", d)
            except Exception as e:
                logger.warning("Failed to clean up temporary directory %s: %s", d, e)

# Register cleanup handler
atexit.register(_cleanup_cloned_dirs)

def normalize_github_url(url: str) -> str:
    """Normalizes various GitHub URL formats into a cloneable HTTPS URL.
    
    Supported formats:
    - https://github.com/user/repo
    - https://github.com/user/repo.git
    - github.com/user/repo
    - git@github.com:user/repo.git
    """
    cleaned = url.strip()
    
    # Handle git@github.com:user/repo.git
    if cleaned.startswith("git@github.com:"):
        path_part = cleaned.replace("git@github.com:", "")
        cleaned = f"https://github.com/{path_part}"
        
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        # If it doesn't start with http/https but contains github.com
        if cleaned.startswith("github.com/"):
            cleaned = "https://" + cleaned
        else:
            cleaned = "https://github.com/" + cleaned
            
    # Remove trailing .git if present
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
        
    return cleaned

async def fetch_repo(github_url: str) -> str:
    """Clones a GitHub repository to a local temporary directory.
    
    Supports authentication via GITHUB_TOKEN environment variable.
    """
    normalized_url = normalize_github_url(github_url)
    
    # Check for GITHUB_TOKEN to authenticate private repos
    token = os.environ.get("GITHUB_TOKEN")
    clone_url = normalized_url
    if token:
        # Insert token into URL: https://<token>@github.com/user/repo
        clone_url = normalized_url.replace("https://", f"https://{token}@")
        
    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="git_clone_")
    _cloned_dirs.append(temp_dir)
    
    logger.info("Cloning repository %s to temporary directory %s", normalized_url, temp_dir)
    
    # Build clone command
    cmd = ["git", "clone", "--depth=1", clone_url, temp_dir]
    
    try:
        # Run clone process asynchronously
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            err_msg = stderr.decode(errors="replace").strip()
            # Redact token from error message if present
            if token:
                err_msg = err_msg.replace(token, "********")
            raise RepoFetchError(f"git clone failed with code {process.returncode}: {err_msg}")
            
    except Exception as exc:
        # Clean up temp dir if clone failed
        shutil.rmtree(temp_dir, ignore_errors=True)
        if temp_dir in _cloned_dirs:
            _cloned_dirs.remove(temp_dir)
            
        if isinstance(exc, RepoFetchError):
            raise exc
        raise RepoFetchError(f"Failed to clone repository: {exc}") from exc
        
    return temp_dir

"""Fetch security patches from GitHub and extract vulnerable symbols from diffs.

Offline-first: every CVE is cached under ``data/patches/{CVE_ID}.json``.
Network access is only used on cache miss or ``force_refresh=True``.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from dateutil import parser as date_parser
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from unidiff import PatchSet

logger = logging.getLogger(__name__)

# ── Paths & constants ───────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = _REPO_ROOT / "data" / "patches"
TRIVY_ENRICHED = _REPO_ROOT / "enriched_trivy_output.json"
CACHE_MAX_AGE_DAYS = 30
MAX_FILES_PARTIAL = 20
REQUEST_TIMEOUT = 10
GITHUB_COMMIT_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[a-f0-9]+)",
    re.IGNORECASE,
)

# Last-resort hints for offline demos (public fix commits; discovery usually finds these first)
_DEMO_COMMIT_HINTS: dict[str, list[str]] = {
    "CVE-2023-32681": [
        "https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5",
    ],
    "CVE-2019-10906": [
        "https://github.com/pallets/jinja/commit/a2a6c930bcca591a25d2b316fcfd2d6793897b26",
    ],
    "CVE-2020-1747": [
        "https://github.com/yaml/pyyaml/commit/5080ba513377b6355a0502104846ee804656f1e0",
    ],
    "CVE-2020-5313": [
        "https://github.com/python-pillow/Pillow/commit/a09acd0decd8a87ccce939d5ff65dab59e7d365b",
    ],
    "CVE-2018-1000656": [
        "https://github.com/pallets/flask/commit/b178e89e4456e777b1a7ac6d7199052d0dfdbbbe",
    ],
    "CVE-2019-11324": [
        "https://github.com/urllib3/urllib3/commit/1efadf43dc63317cd9eaa3e0fdb9e05ab07254b1",
    ],
    "CVE-2020-26137": [
        "https://github.com/urllib3/urllib3/commit/1dd69c5c5982fae7c87a620d487c2ebf7a6b436b",
    ],
    "CVE-2020-25659": [
        "https://github.com/pyca/cryptography/commit/58494b41d6ecb0f56b7c5f05d5f5e3ca0320d494",
    ],
}

_PR_COMMIT_RE = re.compile(
    r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/\d+/commits/(?P<sha>[a-f0-9]+)",
    re.IGNORECASE,
)

# Package → import root for alias generation
_PACKAGE_IMPORT_ROOT: dict[str, str] = {
    "requests": "requests",
    "jinja2": "jinja2",
    "pyyaml": "yaml",
    "pillow": "PIL",
    "flask": "flask",
    "urllib3": "urllib3",
    "cryptography": "cryptography",
}

VALID_CLASSIFICATIONS = frozenset({
    "RENAMED",
    "SIGNATURE_CHANGED",
    "HARDENED_ONLY",
    "RETURN_CHANGED",
    "INTERNAL_CHANGE",
    "REMOVED",
    "ADDED",
})

VALID_STATUSES = frozenset({"ok", "partial", "no_patch_found", "network_error"})

# Public API symbols for demo CVEs when patches touch internal helpers (deterministic)
_DEMO_API_SYMBOLS: dict[str, list[dict[str, Any]]] = {
    "CVE-2023-32681": [{
        "fully_qualified_name": "requests.sessions.Session.rebuild_auth",
        "short_name": "rebuild_auth",
        "kind": "function",
        "file_in_patch": "requests/sessions.py",
        "change_classification": "INTERNAL_CHANGE",
        "summary": "Proxy-Authorization handling on redirect; patch hardens rebuild_proxies",
    }],
    "CVE-2019-10906": [{
        "fully_qualified_name": "jinja2.sandbox.SandboxedEnvironment",
        "short_name": "SandboxedEnvironment",
        "kind": "class",
        "file_in_patch": "jinja2/sandbox.py",
        "change_classification": "HARDENED_ONLY",
        "summary": "Sandbox escape fix via format_map handling in SandboxedEnvironment",
    }],
    "CVE-2020-1747": [{
        "fully_qualified_name": "yaml.load",
        "short_name": "load",
        "kind": "function",
        "file_in_patch": "lib/yaml/constructor.py",
        "change_classification": "HARDENED_ONLY",
        "summary": "FullLoader constructor hardened; yaml.load uses affected loader",
    }],
    "CVE-2020-5313": [{
        "fully_qualified_name": "PIL.Image.open",
        "short_name": "open",
        "kind": "function",
        "file_in_patch": "src/libImaging/FliDecode.c",
        "change_classification": "INTERNAL_CHANGE",
        "summary": "FLI buffer overrun fix in native decoder reached via Image.open",
    }],
    "CVE-2018-1000656": [{
        "fully_qualified_name": "flask.wrappers.Request.get_json",
        "short_name": "get_json",
        "kind": "function",
        "file_in_patch": "flask/wrappers.py",
        "change_classification": "HARDENED_ONLY",
        "summary": "JSON decoding DoS fix via encoding detection",
    }],
    "CVE-2019-11324": [{
        "fully_qualified_name": "urllib3.util.ssl_.ssl_wrap_socket",
        "short_name": "ssl_wrap_socket",
        "kind": "function",
        "file_in_patch": "src/urllib3/util/ssl_.py",
        "change_classification": "HARDENED_ONLY",
        "summary": "Certificate validation hardening in TLS wrap",
    }],
    "CVE-2020-26137": [{
        "fully_qualified_name": "urllib3.connection.HTTPConnection.putrequest",
        "short_name": "putrequest",
        "kind": "function",
        "file_in_patch": "src/urllib3/connection.py",
        "change_classification": "HARDENED_ONLY",
        "summary": "CRLF injection blocked in request line construction",
    }],
    "CVE-2020-25659": [{
        "fully_qualified_name": "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.decrypt",
        "short_name": "decrypt",
        "kind": "function",
        "file_in_patch": "src/cryptography/hazmat/backends/openssl/rsa.py",
        "change_classification": "HARDENED_ONLY",
        "summary": "RSA OAEP decryption timing attack mitigation",
    }],
}

_CODE_EXTENSIONS = {".py", ".c", ".h", ".pyx", ".pxd", ".cc", ".cpp"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _empty_result(cve_id: str, package: Optional[str] = None) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "package": package,
        "fetched_at": _utc_now_iso(),
        "status": "no_patch_found",
        "sources_tried": [],
        "patch_url": None,
        "patch_commit": None,
        "patch_repo": None,
        "files_changed": [],
        "vulnerable_symbols": [],
        "import_aliases": [],
    }


def _cache_path(cve_id: str) -> Path:
    safe = cve_id.upper().replace("/", "_")
    return CACHE_DIR / f"{safe}.json"


def load_cache(cve_id: str) -> Optional[dict[str, Any]]:
    """Return cached patch data or None."""
    path = _cache_path(cve_id)
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read cache for %s: %s", cve_id, exc)
        return None


def save_cache(cve_id: str, data: dict[str, Any]) -> None:
    """Persist patch data to data/patches/{cve_id}.json."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(cve_id)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _cache_is_fresh(data: dict[str, Any]) -> bool:
    fetched = data.get("fetched_at")
    if not fetched:
        return False
    try:
        ts = date_parser.isoparse(fetched)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return False
    age = datetime.now(timezone.utc) - ts
    return age < timedelta(days=CACHE_MAX_AGE_DAYS)


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class _NetworkError(Exception):
    """Raised internally to trigger retry / source fallback."""


@retry(
    retry=retry_if_exception_type(_NetworkError),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)
def _http_get(url: str, *, accept: Optional[str] = None) -> requests.Response:
    headers = _github_headers() if "github.com" in url or "api.github.com" in url else {}
    if accept:
        headers["Accept"] = accept
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise _NetworkError(str(exc)) from exc
    if resp.status_code == 403:
        raise _NetworkError(f"rate limited: {url}")
    if resp.status_code >= 500:
        raise _NetworkError(f"server error {resp.status_code}: {url}")
    return resp


def _parse_commit_url(url: str) -> Optional[tuple[str, str, str]]:
    m = GITHUB_COMMIT_RE.search(url)
    if m:
        return m.group("owner"), m.group("repo"), m.group("sha")
    m = _PR_COMMIT_RE.search(url)
    if m:
        return m.group("owner"), m.group("repo"), m.group("sha")
    return None


def _normalize_commit_url(url: str) -> str:
    """Convert PR-scoped commit links to canonical /commit/ URLs."""
    parsed = _parse_commit_url(url)
    if not parsed:
        return url
    owner, repo, sha = parsed
    return f"https://github.com/{owner}/{repo}/commit/{sha}"


def _dedupe_preserve_order(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        norm = _normalize_commit_url(u)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _load_trivy_commits(cve_id: str, package: Optional[str]) -> list[str]:
    if not TRIVY_ENRICHED.is_file():
        return []
    try:
        with TRIVY_ENRICHED.open(encoding="utf-8") as fh:
            rows = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    urls: list[str] = []
    for row in rows:
        if row.get("cve") != cve_id:
            continue
        if package and row.get("package", "").lower() != package.lower():
            continue
        urls.extend(row.get("commit_urls") or [])
    return urls


def _extract_github_commits_from_refs(refs: list[Any]) -> list[str]:
    urls: list[str] = []
    for ref in refs:
        if isinstance(ref, str):
            if "github.com" in ref and "/commit/" in ref:
                urls.append(ref)
        elif isinstance(ref, dict):
            u = ref.get("url") or ref.get("source")
            if u and "github.com" in u and "/commit/" in u:
                urls.append(u)
    return urls


def _source_nvd(cve_id: str) -> list[str]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        resp = _http_get(url)
    except _NetworkError:
        logger.debug("NVD unreachable for %s", cve_id)
        return []
    if resp.status_code != 200:
        return []
    try:
        body = resp.json()
    except ValueError:
        return []
    urls: list[str] = []
    for vuln in body.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        for ref in cve.get("references", []):
            u = ref.get("url", "")
            if "github.com" in u and "/commit/" in u:
                urls.append(u)
    return urls


def _source_osv(cve_id: str) -> list[str]:
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    try:
        resp = _http_get(url)
    except _NetworkError:
        return []
    if resp.status_code != 200:
        return []
    try:
        body = resp.json()
    except ValueError:
        return []
    urls: list[str] = []
    for affected in body.get("affected", []):
        for repo in affected.get("ecosystem_specific", {}).get("fixes", []):
            if isinstance(repo, str) and "/commit/" in repo:
                urls.append(repo)
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("type") == "fixed" and event.get("commit"):
                    # OSV may store bare SHA; skip without repo context
                    commit = event["commit"]
                    if commit.startswith("http"):
                        urls.append(commit)
        for ref in body.get("references", []):
            u = ref if isinstance(ref, str) else ref.get("url", "")
            if "github.com" in u and "/commit/" in u:
                urls.append(u)
        for db_spec in affected.get("database_specific", {}).get("source", ""):
            if isinstance(db_spec, str) and "/commit/" in db_spec:
                urls.append(db_spec)
    # GitHub-originated OSV entries often include repo in affected.package
    for affected in body.get("affected", []):
        pkg = affected.get("package", {})
        repo = pkg.get("name", "")
        for rng in affected.get("ranges", []):
            repo_url = rng.get("repo")
            if repo_url and "github.com" in repo_url:
                for event in rng.get("events", []):
                    if event.get("type") == "fixed" and event.get("commit"):
                        sha = event["commit"]
                        if not sha.startswith("http"):
                            base = repo_url.rstrip("/")
                            urls.append(f"{base}/commit/{sha}")
    return urls


def _source_ghsa(cve_id: str) -> list[str]:
    url = f"https://api.github.com/advisories?cve_id={cve_id}"
    try:
        resp = _http_get(url, accept="application/vnd.github+json")
    except _NetworkError:
        return []
    if resp.status_code != 200:
        return []
    try:
        advisories = resp.json()
    except ValueError:
        return []
    urls: list[str] = []
    for adv in advisories if isinstance(advisories, list) else []:
        for ref in adv.get("references", []):
            u = ref if isinstance(ref, str) else ref.get("url", "")
            if "github.com" in u and "/commit/" in u:
                urls.append(u)
    return urls


def _discover_commit_urls(
    cve_id: str,
    package: Optional[str],
    sources_tried: list[str],
) -> list[str]:
    """Try trivy → nvd → osv → ghsa and return candidate commit URLs."""
    all_urls: list[str] = []

    trivy_urls = _load_trivy_commits(cve_id, package)
    if trivy_urls:
        sources_tried.append("trivy")
        all_urls.extend(trivy_urls)

    nvd_urls = _source_nvd(cve_id)
    if nvd_urls:
        sources_tried.append("nvd")
        all_urls.extend(nvd_urls)

    osv_urls = _source_osv(cve_id)
    if osv_urls:
        sources_tried.append("osv")
        all_urls.extend(osv_urls)

    ghsa_urls = _source_ghsa(cve_id)
    if ghsa_urls:
        sources_tried.append("ghsa")
        all_urls.extend(ghsa_urls)

    hints = _DEMO_COMMIT_HINTS.get(cve_id, [])
    all_urls.extend(hints)

    return _dedupe_preserve_order(all_urls)


def _fetch_patch_text(owner: str, repo: str, sha: str) -> Optional[str]:
    patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    try:
        resp = _http_get(patch_url)
    except _NetworkError:
        return None
    if resp.status_code != 200:
        return None
    return resp.text


def _arg_names(args: ast.arguments) -> list[str]:
    names: list[str] = []
    for arg in args.posonlyargs + args.args:
        names.append(arg.arg)
    if args.vararg:
        names.append(f"*{args.vararg.arg}")
    for arg in args.kwonlyargs:
        names.append(arg.arg)
    if args.kwarg:
        names.append(f"**{args.kwarg.arg}")
    return names


def _format_signature(node: ast.AST) -> str:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        try:
            return ast.unparse(node).split("\n", 1)[0]
        except Exception:
            return f"def {node.name}(...)"
    if isinstance(node, ast.ClassDef):
        return f"class {node.name}"
    return ""


def _count_returns(node: ast.AST) -> list[ast.Return]:
    returns: list[ast.Return] = []

    class Visitor(ast.NodeVisitor):
        def visit_Return(self, ret: ast.Return) -> None:
            returns.append(ret)

    Visitor().visit(node)
    return returns


def _count_guard_nodes(node: ast.AST) -> int:
    guards = 0

    class Visitor(ast.NodeVisitor):
        def visit_If(self, _: ast.If) -> None:
            nonlocal guards
            guards += 1

        def visit_Assert(self, _: ast.Assert) -> None:
            nonlocal guards
            guards += 1

        def visit_Raise(self, _: ast.Raise) -> None:
            nonlocal guards
            guards += 1

    Visitor().visit(node)
    return guards


def _classify_ast_change(
    before: Optional[ast.AST],
    after: Optional[ast.AST],
    *,
    before_name: str,
    after_name: str,
) -> str:
    if before is None and after is not None:
        return "ADDED"
    if before is not None and after is None:
        return "REMOVED"
    if before is None or after is None:
        return "INTERNAL_CHANGE"

    if before_name != after_name:
        return "RENAMED"

    if isinstance(before, ast.ClassDef) and isinstance(after, ast.ClassDef):
        # Class body changed — compare methods loosely
        if before.name != after.name:
            return "RENAMED"
        return "INTERNAL_CHANGE"

    if not isinstance(before, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "INTERNAL_CHANGE"
    if not isinstance(after, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "INTERNAL_CHANGE"

    if _arg_names(before.args) != _arg_names(after.args):
        return "SIGNATURE_CHANGED"
    if len(before.args.defaults) != len(after.args.defaults):
        return "SIGNATURE_CHANGED"
    if before.args.kw_defaults != after.args.kw_defaults:
        return "SIGNATURE_CHANGED"

    before_returns = _count_returns(before)
    after_returns = _count_returns(after)
    if len(before_returns) != len(after_returns):
        return "RETURN_CHANGED"
    try:
        before_ret_unparsed = [ast.unparse(r) for r in before_returns]
        after_ret_unparsed = [ast.unparse(r) for r in after_returns]
        if before_ret_unparsed != after_ret_unparsed:
            return "RETURN_CHANGED"
    except Exception:
        pass

    if _count_guard_nodes(after) > _count_guard_nodes(before):
        # More validation/guards without signature or return change
        try:
            before_body = ast.unparse(before.body)
            after_body = ast.unparse(after.body)
            # Strip guard-only differences heuristic: if returns match, call hardened
            if before_body != after_body:
                return "HARDENED_ONLY"
        except Exception:
            return "HARDENED_ONLY"

    if ast.dump(before) != ast.dump(after):
        return "INTERNAL_CHANGE"
    return "INTERNAL_CHANGE"


def _extract_defs_from_source(source: str) -> dict[str, ast.AST]:
    """Map short name → AST node for top-level functions and classes."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = node
    return out


def _build_side_source(hunk_lines: list[tuple[str, str]]) -> str:
    """Build parseable source from hunk lines: (marker, text). marker in -,+, ."""
    lines: list[str] = []
    for marker, text in hunk_lines:
        if marker in (".", "-"):
            lines.append(text)
    return "\n".join(lines) + ("\n" if lines else "")


def _build_after_source(hunk_lines: list[tuple[str, str]]) -> str:
    lines: list[str] = []
    for marker, text in hunk_lines:
        if marker in (".", "+"):
            lines.append(text)
    return "\n".join(lines) + ("\n" if lines else "")


def _module_path_from_file(file_path: str, package: Optional[str]) -> str:
    path = file_path.replace("\\", "/")
    if path.endswith(".py"):
        path = path[:-3]
    parts = path.split("/")
    root = _PACKAGE_IMPORT_ROOT.get((package or "").lower(), parts[0] if parts else "")
    if parts and parts[0] == root:
        return ".".join(parts)
    if root and parts and parts[0] != root:
        return f"{root}.{'.'.join(parts)}"
    return ".".join(parts)


def _generate_import_aliases(
    symbols: list[dict[str, Any]],
    package: Optional[str],
) -> list[str]:
    aliases: list[str] = []
    seen: set[str] = set()
    for sym in symbols:
        if sym.get("kind") == "file":
            continue
        fqn = sym.get("fully_qualified_name", "")
        short = sym.get("short_name", "")
        file_path = sym.get("file_in_patch", "")
        if not fqn or not short or short.endswith((".c", ".h")):
            continue
        parts = fqn.split(".")
        if len(parts) >= 2:
            mod = ".".join(parts[:-1])
            stmt = f"from {mod} import {short}"
            if stmt not in seen:
                seen.add(stmt)
                aliases.append(stmt)
        if package:
            pkg_root = _PACKAGE_IMPORT_ROOT.get(package.lower(), package.lower())
            top_stmt = f"from {pkg_root} import {parts[-2] if len(parts) > 1 else pkg_root}"
            if top_stmt not in seen and len(parts) > 2:
                seen.add(top_stmt)
                aliases.append(top_stmt)
        _ = file_path  # reserved for future alias heuristics
    return aliases


def _name_from_section_header(header: str) -> Optional[tuple[str, str]]:
    """Return (short_name, kind) from a unified-diff @@ section header."""
    header = header.strip()
    if header.startswith("def ") or header.startswith("async def "):
        m = re.match(r"(?:async\s+)?def\s+(\w+)\s*\(", header)
        if m:
            return m.group(1), "function"
    if header.startswith("class "):
        m = re.match(r"class\s+(\w+)", header)
        if m:
            return m.group(1), "class"
    return None


def _summarize_symbol(name: str, classification: str, lines_added: int, lines_removed: int) -> str:
    templates = {
        "HARDENED_ONLY": f"Added validation or guards in {name}",
        "SIGNATURE_CHANGED": f"Parameter list changed in {name}",
        "RETURN_CHANGED": f"Return behavior changed in {name}",
        "RENAMED": f"Symbol renamed (was {name})",
        "REMOVED": f"Removed {name} in security patch",
        "ADDED": f"Added helper {name} in security patch",
        "INTERNAL_CHANGE": f"Internal logic updated in {name}",
    }
    base = templates.get(classification, f"Modified {name}")
    if lines_added or lines_removed:
        return f"{base} (+{lines_added}/-{lines_removed} lines in hunk)"
    return base


def _parse_patch_symbols(
    patch_text: str,
    package: Optional[str],
) -> tuple[list[str], list[dict[str, Any]], bool]:
    """
    Parse a unified diff and return (files_changed, vulnerable_symbols, is_partial).
    """
    files_changed: list[str] = []
    symbols: list[dict[str, Any]] = []

    try:
        patch_set = PatchSet(patch_text.splitlines(keepends=True))
    except Exception as exc:
        logger.warning("unidiff parse failed: %s", exc)
        return [], [], True

    if len(patch_set) > MAX_FILES_PARTIAL:
        paths = [pf.path for pf in patch_set]
        return paths, [], True

    for patched_file in patch_set:
        path = patched_file.path
        if path.startswith("a/") or path.startswith("b/"):
            path = path[2:]
        files_changed.append(path)

        norm_path = path.replace("\\", "/")
        top = norm_path.split("/")[0].lower() if norm_path else ""
        if (
            top in ("test", "tests", "dummyserver")
            or norm_path.startswith("tests/")
            or "/tests/" in norm_path
            or norm_path.startswith("test_")
            or norm_path.endswith("_test.py")
        ):
            continue

        if norm_path.endswith(".bin") or "/images/" in norm_path:
            continue

        ext = os.path.splitext(path)[1].lower()
        if ext not in (".py",):
            if ext in _CODE_EXTENSIONS:
                short_file = os.path.basename(path)
                symbols.append({
                    "fully_qualified_name": (
                        f"{_PACKAGE_IMPORT_ROOT.get((package or '').lower(), '')}.{short_file}"
                    ),
                    "short_name": short_file,
                    "kind": "file",
                    "file_in_patch": path,
                    "change_classification": "INTERNAL_CHANGE",
                    "before_signature": "",
                    "after_signature": "",
                    "lines_added": sum(1 for h in patched_file for l in h if l.is_added),
                    "lines_removed": sum(1 for h in patched_file for l in h if l.is_removed),
                    "summary": f"Native code change in {path} (Python wrapper may still be affected)",
                })
            continue

        mod_path = _module_path_from_file(path, package)
        section_symbols: dict[str, dict[str, Any]] = {}

        for hunk in patched_file:
            hunk_lines: list[tuple[str, str]] = []
            lines_added = 0
            lines_removed = 0

            for line in hunk:
                if line.is_added:
                    hunk_lines.append(("+", line.value.rstrip("\n")))
                    lines_added += 1
                elif line.is_removed:
                    hunk_lines.append(("-", line.value.rstrip("\n")))
                    lines_removed += 1
                else:
                    hunk_lines.append((".", line.value.rstrip("\n")))

            before_src = _build_side_source(hunk_lines)
            after_src = _build_after_source(hunk_lines)
            before_defs = _extract_defs_from_source(before_src)
            after_defs = _extract_defs_from_source(after_src)

            header_info = _name_from_section_header(hunk.section_header or "")
            if header_info and not before_defs and not after_defs:
                name, kind = header_info
                before_defs[name] = _make_stub_node(name, kind, before_src)
                after_defs[name] = _make_stub_node(name, kind, after_src)

            all_names = sorted(set(before_defs) | set(after_defs))

            for name in all_names:
                before_node = before_defs.get(name)
                after_node = after_defs.get(name)
                if before_node is None and after_node is None:
                    continue

                kind = "class" if isinstance(after_node or before_node, ast.ClassDef) else "function"
                if header_info and header_info[0] == name:
                    kind = header_info[1]
                classification = _classify_ast_change(
                    before_node,
                    after_node,
                    before_name=name,
                    after_name=name,
                )
                if classification == "INTERNAL_CHANGE" and lines_added and _looks_like_hardening(before_src, after_src):
                    classification = "HARDENED_ONLY"
                fqn = f"{mod_path}.{name}"

                entry = {
                    "fully_qualified_name": fqn,
                    "short_name": name,
                    "kind": kind,
                    "file_in_patch": path,
                    "change_classification": classification,
                    "before_signature": _format_signature(before_node) if before_node else (hunk.section_header or ""),
                    "after_signature": _format_signature(after_node) if after_node else (hunk.section_header or ""),
                    "lines_added": lines_added,
                    "lines_removed": lines_removed,
                    "summary": _summarize_symbol(name, classification, lines_added, lines_removed),
                }
                prev = section_symbols.get(name)
                if prev:
                    prev["lines_added"] += lines_added
                    prev["lines_removed"] += lines_removed
                else:
                    section_symbols[name] = entry

        symbols.extend(section_symbols.values())

    return files_changed, symbols, False


def _make_stub_node(name: str, kind: str, source: str) -> ast.AST:
    """Minimal AST node when the diff hunk omits the ``def`` line."""
    if kind == "class":
        return ast.ClassDef(name=name, bases=[], keywords=[], body=[], decorator_list=[])
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return node
    except SyntaxError:
        pass
    return ast.FunctionDef(
        name=name,
        args=ast.arguments(
            posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[],
            defaults=[], vararg=None, kwarg=None,
        ),
        body=[],
        decorator_list=[],
        returns=None,
    )


def _looks_like_hardening(before: str, after: str) -> bool:
    """Heuristic when AST bodies are incomplete: new guards/comments only."""
    guard_tokens = ("if ", "assert ", "raise ", "validate", "strip", "check")
    added = set(after.splitlines()) - set(before.splitlines())
    if not added:
        return False
    return all(any(tok in line for tok in guard_tokens) or line.strip().startswith("#") for line in added)


def _enrich_demo_symbols(
    cve_id: str,
    symbols: list[dict[str, Any]],
    files_changed: list[str],
) -> list[dict[str, Any]]:
    """Add well-known public API symbols for demo CVEs when the patch touches related code."""
    extras = _DEMO_API_SYMBOLS.get(cve_id.upper(), [])
    if not extras:
        return symbols
    existing_fqn = {s.get("fully_qualified_name") for s in symbols}
    existing_short = {s.get("short_name") for s in symbols}
    out = list(symbols)
    for template in extras:
        file_hint = template.get("file_in_patch", "")
        if file_hint and not any(
            file_hint in f.replace("\\", "/") for f in files_changed
        ):
            continue
        fqn = template["fully_qualified_name"]
        short = template.get("short_name")
        if fqn in existing_fqn or short in existing_short:
            continue
        entry = dict(template)
        entry.setdefault("before_signature", "")
        entry.setdefault("after_signature", "")
        entry.setdefault("lines_added", 0)
        entry.setdefault("lines_removed", 0)
        out.append(entry)
        existing_fqn.add(fqn)
        if short:
            existing_short.add(short)
    return out


def _resolve_osv_fix_commit(cve_id: str) -> list[str]:
    """Extra pass: resolve bare SHAs from OSV with repo URL."""
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    try:
        resp = _http_get(url)
    except _NetworkError:
        return []
    if resp.status_code != 200:
        return []
    try:
        body = resp.json()
    except ValueError:
        return []
    urls: list[str] = []
    for affected in body.get("affected", []):
        for rng in affected.get("ranges", []):
            repo = rng.get("repo", "")
            if not repo or "github.com" not in repo:
                continue
            for event in rng.get("events", []):
                if event.get("type") == "fixed" and event.get("commit"):
                    sha = event["commit"]
                    if sha.startswith("http"):
                        urls.append(sha)
                    else:
                        urls.append(f"{repo.rstrip('/')}/commit/{sha}")
    return urls


def fetch_patch(
    cve_id: str,
    package: Optional[str] = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Fetch the patch for one CVE. Returns the schema documented in the module docstring."""
    cve_id = cve_id.upper()
    if not force_refresh:
        cached = load_cache(cve_id)
        if cached and _cache_is_fresh(cached):
            logger.info("Cache hit for %s", cve_id)
            return cached

    result = _empty_result(cve_id, package)
    sources_tried: list[str] = []
    network_failed = False

    try:
        commit_urls = _discover_commit_urls(cve_id, package, sources_tried)
        # OSV often has bare SHAs — merge resolved URLs
        commit_urls = _dedupe_preserve_order(commit_urls + _resolve_osv_fix_commit(cve_id))

        if not commit_urls:
            result["sources_tried"] = sources_tried
            result["status"] = "no_patch_found"
            save_cache(cve_id, result)
            return result

        patch_text: Optional[str] = None
        chosen: Optional[tuple[str, str, str]] = None
        patch_url: Optional[str] = None

        for url in commit_urls:
            parsed = _parse_commit_url(url)
            if not parsed:
                continue
            owner, repo, sha = parsed
            text = _fetch_patch_text(owner, repo, sha)
            if text:
                patch_text = text
                chosen = (owner, repo, sha)
                patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}"
                break

        if not patch_text or not chosen:
            network_failed = True
            cached = load_cache(cve_id)
            if cached:
                cached["status"] = "network_error" if not _cache_is_fresh(cached) else cached.get("status", "partial")
                return cached
            result["sources_tried"] = sources_tried
            result["status"] = "network_error"
            save_cache(cve_id, result)
            return result

        owner, repo, sha = chosen
        files_changed, symbols, is_partial = _parse_patch_symbols(patch_text, package)

        # Deduplicate symbols by FQN
        seen_fqn: set[str] = set()
        unique_symbols: list[dict[str, Any]] = []
        for sym in symbols:
            fqn = sym["fully_qualified_name"]
            if fqn in seen_fqn:
                continue
            seen_fqn.add(fqn)
            unique_symbols.append(sym)

        unique_symbols = _enrich_demo_symbols(cve_id, unique_symbols, files_changed)

        status = "partial" if is_partial or (files_changed and not unique_symbols) else "ok"
        if not files_changed:
            status = "partial"

        result = {
            "cve_id": cve_id,
            "package": package,
            "fetched_at": _utc_now_iso(),
            "status": status,
            "sources_tried": sources_tried,
            "patch_url": patch_url,
            "patch_commit": sha,
            "patch_repo": f"{owner}/{repo}",
            "files_changed": sorted(set(files_changed)),
            "vulnerable_symbols": sorted(unique_symbols, key=lambda s: s["fully_qualified_name"]),
            "import_aliases": _generate_import_aliases(unique_symbols, package),
        }
        save_cache(cve_id, result)
        return result

    except Exception as exc:
        logger.exception("Unexpected error fetching %s: %s", cve_id, exc)
        cached = load_cache(cve_id)
        if cached:
            return cached
        result["sources_tried"] = sources_tried
        result["status"] = "network_error" if network_failed else "no_patch_found"
        save_cache(cve_id, result)
        return result


def fetch_patches_batch(
    cve_list: list[dict[str, Any]] | list[str],
    max_workers: int = 4,
) -> dict[str, dict[str, Any]]:
    """Fetch patches for multiple CVEs in parallel. Returns dict keyed by cve_id."""
    items: list[tuple[str, Optional[str]]] = []
    for entry in cve_list:
        if isinstance(entry, str):
            items.append((entry.upper(), None))
        else:
            items.append((str(entry.get("cve_id", entry.get("cve", ""))).upper(), entry.get("package")))

    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(fetch_patch, cve, pkg): cve
            for cve, pkg in items
            if cve
        }
        for fut in as_completed(futures):
            cve = futures[fut]
            try:
                results[cve] = fut.result()
            except Exception as exc:
                logger.error("Batch fetch failed for %s: %s", cve, exc)
                results[cve] = _empty_result(cve)
    return results


def get_vulnerable_symbols(cve_id: str) -> list[dict[str, Any]]:
    """Return just the symbol list for a cached CVE. Used by Symbol Scanner downstream."""
    data = load_cache(cve_id.upper())
    if not data:
        return []
    return list(data.get("vulnerable_symbols") or [])

"""Shared constants for Pipeline A.

Single source of truth for CWE-to-family mappings, language maps, and
directory skip-lists. Import from here — never duplicate these tables.
"""

# ── CWE → Vulnerability Family ─────────────────────────────────────
# Many CVEs share the same CWE; many CWEs share the same *family*.
# One good Semgrep rule per family covers every CVE in that cluster.
CWE_FAMILY_MAP = {
    # SQL Injection
    "CWE-89":  "sql_injection",
    "CWE-564": "sql_injection",
    # XSS
    "CWE-79":  "xss",
    "CWE-87":  "xss",
    # Path Traversal
    "CWE-22":  "path_traversal",
    "CWE-23":  "path_traversal",
    "CWE-36":  "path_traversal",
    # OS Command Injection
    "CWE-78":  "os_command_injection",
    "CWE-77":  "os_command_injection",
    # Code / Generic Injection
    "CWE-94":  "code_injection",
    "CWE-95":  "code_injection",
    "CWE-74":  "injection",
    # Deserialization
    "CWE-502": "deserialization",
    # XXE
    "CWE-611": "xxe",
    # Input Validation
    "CWE-20":  "input_validation",
    # Credentials
    "CWE-798": "hardcoded_credentials",
    "CWE-522": "weak_credentials",
    # Resource Exhaustion
    "CWE-400": "resource_exhaustion",
    "CWE-770": "resource_exhaustion",
    "CWE-674": "resource_exhaustion",
    "CWE-407": "resource_exhaustion",
    # Auth
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-862": "missing_authorization",
    "CWE-276": "incorrect_permissions",
    # Memory safety (C/C++ — usually irrelevant for Python projects)
    "CWE-120": "buffer_overflow",
    "CWE-125": "buffer_overflow",
    "CWE-787": "buffer_overflow",
    "CWE-190": "integer_overflow",
    "CWE-476": "null_dereference",
    # Web / Session
    "CWE-640": "weak_password_recovery",
    "CWE-319": "cleartext_transmission",
    "CWE-539": "session_management",
    "CWE-524": "information_exposure",
    "CWE-203": "information_exposure",
    # Misc
    "CWE-1321": "prototype_pollution",
    "CWE-494":  "integrity_check",
    "CWE-117":  "log_injection",
    "CWE-843":  "type_confusion",
    "CWE-385":  "timing_attack",
}

# ── Human-readable CWE names (for prompts & reports) ───────────────
CWE_NAMES = {
    "CWE-89":  "SQL Injection",
    "CWE-79":  "Cross-Site Scripting",
    "CWE-22":  "Path Traversal",
    "CWE-78":  "OS Command Injection",
    "CWE-94":  "Code Injection",
    "CWE-611": "XXE Injection",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-20":  "Improper Input Validation",
    "CWE-287": "Improper Authentication",
    "CWE-798": "Hard-coded Credentials",
    "CWE-306": "Missing Authentication",
    "CWE-862": "Missing Authorization",
    "CWE-74":  "Injection",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-120": "Buffer Copy without Checking Size",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-190": "Integer Overflow",
    "CWE-476": "NULL Pointer Dereference",
}

# ── File extension → Semgrep language ──────────────────────────────
LANG_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "javascript",
    ".java": "java",
    ".go":   "go",
    ".rb":   "ruby",
    ".cpp":  "cpp",
    ".c":    "cpp",
    ".cs":   "csharp",
}

# Directories to skip when detecting project language
SKIP_DIRS = {"venv", "node_modules", ".git", "codeql", "__pycache__", "semgrep-rules"}

# ── Package → common application-level Semgrep sink patterns ───────
# Registry rules often miss bare calls like yaml.load(x) without Loader=.
PACKAGE_APP_SINKS: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml.load(...)",),
    "requests": ("rebuild_auth(...)",),
    "pillow": ("Image.open(...)",),
    "jinja2": ("render_template_string(...)",),
    "flask": ("request.get_json(...)", "render_template_string(...)"),
}

# ── Package → public *vulnerable* API entry points (reachability) ──
# A patch diff identifies the internal function that was fixed (e.g.
# ``construct_python_object_new``), but application code reaches that code
# through a public API (``yaml.load``). The symbol scanner cannot bridge the
# two from the diff alone, so this curated map declares the public call sites
# that expose a package's vulnerable surface. These are matched by *exact*
# resolved FQN only (never by bare short name) to avoid false positives on
# unrelated calls such as ``json.load`` or ``os.environ.get``.
#
# Keys are normalised package names (see ``normalize_package``). Only include
# APIs whose invocation *is* the vulnerable surface — do NOT add generic input
# sources (e.g. ``request.get_json``) or symbols a package exposes safely, so
# that imported-but-unreached vulnerabilities stay correctly suppressed.
PACKAGE_REACHABILITY_SINKS: dict[str, tuple[str, ...]] = {
    # yaml.load() without SafeLoader -> arbitrary object construction (RCE).
    "pyyaml": ("yaml.load",),
    # requests verbs follow redirects by default and leak auth headers/creds.
    "requests": (
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.request",
    ),
    # Pillow decodes untrusted images through Image.open.
    "pillow": ("PIL.Image.open",),
}

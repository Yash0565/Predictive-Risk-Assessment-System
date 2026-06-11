"""Phase 2 — Triple-Check Rule Resolver.

For every vulnerability family, asks three questions in order:

  A) Is the rule already in our local cache (rules_db.json)?      → $0
  B) Does the official Semgrep registry have one?                  → $0
  C) Does LLM need to build it?  (triage → deep-gen)              → $$$

Only C costs API tokens, and it only fires when A and B miss.
Supports both Gemini (cloud) and Ollama (local) as LLM backends.
"""

import asyncio
import json
import os
import re
import time

import requests

from src.config import CWE_NAMES
from src.registry_matcher import find_best_rule_for_family
from src.semgrep_tools import (
    check_semgrep_available,
    semgrep_example_template,
    validate_rule_file,
    validate_rule_yaml,
)

# ── Cache I/O ───────────────────────────────────────────────────────

_DB_PATH = os.path.join("data", "rules_db.json")


def _load_db():
    if os.path.exists(_DB_PATH):
        with open(_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_db(db):
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    with open(_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


# ── LLM call abstraction ───────────────────────────────────────────

def _llm_call(prompt, llm_backend, api_key=None, ollama_model=None,
              system_instruction=None, max_tokens=2048):
    """Send a prompt to Gemini or Ollama.  Returns the raw text response."""
    if llm_backend == "ollama":
        return _ollama_call(prompt, ollama_model or "qwen2.5:3b",
                            system_instruction, max_tokens)
    else:
        return _gemini_call(prompt, api_key, system_instruction, max_tokens)


def _ollama_call(prompt, model, system_instruction=None, max_tokens=2048):
    """Call Ollama's local API (no rate limits, no cost)."""
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": max_tokens},
    }
    if system_instruction:
        payload["system"] = system_instruction

    resp = requests.post(url, json=payload, timeout=120)
    resp.raise_for_status()
    return resp.json()["response"].strip()


def _gemini_call(prompt, api_key, system_instruction=None, max_tokens=2048):
    """Call Google Gemini API."""
    from google import genai

    client = genai.Client(api_key=api_key)
    config = genai.types.GenerateContentConfig(max_output_tokens=max_tokens)
    if system_instruction:
        config = genai.types.GenerateContentConfig(
            system_instruction=system_instruction,
            max_output_tokens=max_tokens,
        )
    resp = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt, config=config,
    )
    return resp.text.strip()


def _strip_markdown_fences(text):
    """Remove ```yaml ... ``` wrappers from LLM output."""
    if text.startswith("```"):
        return "\n".join(
            l for l in text.split("\n") if not l.strip().startswith("```")
        )
    return text


# ── Public API ──────────────────────────────────────────────────────

async def resolve_rules(families, language, registry_index, api_key,
                        rules_dir, max_concurrent=4,
                        llm_backend="ollama", ollama_model="qwen2.5:3b",
                        skip_llm=False, quiet=False):
    """Resolve a rule for every family.  Returns { family: resolved_info }."""
    os.makedirs(rules_dir, exist_ok=True)
    db = _load_db()
    resolved = {}
    needs_llm = []

    if not quiet:
        print("\n" + "=" * 60)
        print("PHASE 2: Triple-Check Rule Strategy")
        print("=" * 60)

    for name, cluster in families.items():
        # ── Step A: local cache ─────────────────────────────────
        cached = db.get(name)
        cached_path = cached.get("rule_path", "") if cached else ""
        if cached and cached_path and os.path.exists(cached_path):
            ok, err = validate_rule_file(cached_path)
            if ok:
                if not quiet:
                    print(f"  [A] CACHE  hit  → {name}")
                resolved[name] = cached
                continue
            if not quiet:
                print(f"  [A] CACHE  stale → {name} ({err}); re-resolving...")

        # ── Step B: official registry ───────────────────────────
        match = find_best_rule_for_family(cluster.cwe_ids, language,
                                          registry_index)
        if match and os.path.exists(match["path"]):
            info = {
                "source": "registry",
                "rule_path": match["path"],
                "rule_id": match["rule_id"],
                "cwe_ids": sorted(cluster.cwe_ids),
            }
            resolved[name] = info
            db[name] = info
            if not quiet:
                print(f"  [B] REGISTRY hit → {name}  ({match['rule_id']})")
            continue

        # ── Step C: LLM needed ──────────────────────────────────
        if skip_llm:
            if not quiet:
                print(f"  [C] SKIP (no LLM) → {name}")
            resolved[name] = {"source": "none", "rule_path": "", "cwe_ids": sorted(cluster.cwe_ids)}
            continue
        needs_llm.append((name, cluster))
        if not quiet:
            print(f"  [C] LLM queue   → {name}")

    # Run all LLM calls concurrently (rate-limited by semaphore)
    if needs_llm and not skip_llm:
        backend_label = f"Ollama ({ollama_model})" if llm_backend == "ollama" else "Gemini"
        if not quiet:
            print(f"\n  [*] Sending {len(needs_llm)} families to {backend_label} "
                  f"(max {max_concurrent} concurrent)...")
        llm_results = await _run_llm_batch(
            needs_llm, language, api_key, rules_dir, max_concurrent,
            llm_backend, ollama_model, quiet=quiet,
        )
        for name, info in llm_results.items():
            if info:
                resolved[name] = info
                db[name] = info

    _save_db(db)

    cached_n = sum(1 for r in resolved.values() if r.get("source") == "cache")
    reg_n    = sum(1 for r in resolved.values() if r.get("source") == "registry")
    llm_n    = sum(1 for r in resolved.values() if r.get("source") in ("gemini", "ollama"))
    skipped_n = sum(1 for r in resolved.values() if r.get("source") == "none")

    if quiet:
        from src.pipeline_console import print_rule_resolution_summary
        print_rule_resolution_summary(
            total=len(resolved),
            cache=cached_n,
            registry=reg_n,
            llm=llm_n,
            skipped=skipped_n,
        )
    else:
        print(f"\n  Summary: {len(resolved)} families resolved  "
              f"(cache={cached_n}, registry={reg_n}, llm={llm_n})")
    return resolved


# ── LLM batch runner (async, semaphore-gated) ───────────────────────

async def _run_llm_batch(items, language, api_key, rules_dir, max_concurrent,
                         llm_backend, ollama_model, quiet=False):
    """Fire triage+deep-gen for each family, limited by a semaphore."""
    sem = asyncio.Semaphore(max_concurrent)
    tasks = [
        _llm_for_family(sem, name, cluster, language, api_key, rules_dir,
                        llm_backend, ollama_model, quiet=quiet)
        for name, cluster in items
    ]
    pairs = await asyncio.gather(*tasks, return_exceptions=True)
    results = {}
    for pair in pairs:
        if isinstance(pair, Exception):
            kind = type(pair).__name__
            msg = str(pair)
            if "semgrep" in msg.lower() or "WinError 1455" in msg or "paging file" in msg.lower():
                print(f"  [!] Semgrep subprocess failure ({kind}): {msg}")
            else:
                print(f"  [!] LLM rule-gen error ({kind}): {msg}")
            continue
        if pair:
            name, info = pair
            results[name] = info
    return results


async def _llm_for_family(sem, name, cluster, language, api_key, rules_dir,
                          llm_backend, ollama_model, quiet=False):
    """Triage → Deep-gen for one family, gated by semaphore."""
    async with sem:
        if not quiet:
            print(f"  [C] Triage → {name} (calling {llm_backend}...)")
        triage = await asyncio.to_thread(
            _triage, name, cluster, language, llm_backend, api_key, ollama_model
        )
        if not triage.get("worth_scanning", True):
            if not quiet:
                print(f"  [C] SKIP (triage) → {name}: {triage.get('reason','')}")
            return None

        if not quiet:
            print(f"  [C] Deep-gen → {name} (generating YAML rule...)")
        rule_path = await asyncio.to_thread(
            _deep_gen, name, cluster, language, rules_dir,
            llm_backend, api_key, ollama_model, quiet=quiet,
        )
        if rule_path:
            info = {
                "source": llm_backend,
                "rule_path": rule_path,
                "cwe_ids": sorted(cluster.cwe_ids),
            }
            if not quiet:
                print(f"  [C] GENERATED    → {name}  ({os.path.basename(rule_path)})")
            return name, info
        return None


# ── Triage & Deep-gen (synchronous, run inside asyncio.to_thread) ───

def _triage(name, cluster, language, llm_backend, api_key, ollama_model):
    """Quick LLM check: is this family worth scanning for *language*?"""
    cwe_desc = ", ".join(
        f"{c} ({CWE_NAMES.get(c, c)})" for c in sorted(cluster.cwe_ids)
    )
    prompt = (
        f"You are a security triage expert.\n"
        f"CWE family '{name}' covers: {cwe_desc}.\n"
        f"Target language: {language}.\n"
        f"Packages involved: {', '.join(sorted(cluster.packages))}.\n\n"
        f"Is it worth writing a Semgrep rule to detect this family in "
        f"{language} code?  Reply with ONLY valid JSON:\n"
        f'{{"worth_scanning": true/false, "reason": "...", '
        f'"patterns": ["example_sink()"]}}'
    )
    try:
        text = _llm_call(prompt, llm_backend, api_key, ollama_model,
                         max_tokens=512)
        text = _strip_markdown_fences(text)
        return json.loads(text)
    except Exception as e:
        # On failure, default to "worth scanning" to avoid losing coverage
        return {"worth_scanning": True, "reason": f"triage error: {e}"}


def _deep_gen(name, cluster, language, rules_dir,
              llm_backend, api_key, ollama_model, retries=3, quiet=False):
    """Generate a full Semgrep YAML rule for this family."""
    cwe_desc = ", ".join(
        f"{c} ({CWE_NAMES.get(c, c)})" for c in sorted(cluster.cwe_ids)
    )
    pkgs = ", ".join(sorted(cluster.packages))
    rule_id = f"detect-{name}-{language}"

    ok, semgrep_detail, _ = check_semgrep_available()
    if not ok:
        if not quiet:
            print(f"  [!] Semgrep unavailable for rule validation: {semgrep_detail}")

    system = (
        "You are a static analysis expert. Output ONLY raw Semgrep YAML. "
        "The document MUST have a top-level 'rules:' list. Each rule MUST "
        "include id, languages, message, severity, and pattern (or patterns). "
        "No markdown. No commentary."
    )
    example = semgrep_example_template(rule_id, language)
    prompt = (
        f"Generate a Semgrep rule to detect the '{name}' vulnerability family.\n"
        f"CWEs covered: {cwe_desc}\n"
        f"Packages: {pkgs}\n"
        f"Language: {language}\n"
        f"Rule ID: {rule_id}\n"
        f"Focus on common sinks and patterns for these CWEs in {pkgs}.\n\n"
        f"Use exactly this structure (replace pattern with a real sink):\n"
        f"{example}\n"
        f"Output ONLY valid Semgrep YAML. No explanation. No markdown fences."
    )

    path = os.path.join(rules_dir, f"{name}_{language}.yaml")

    for attempt in range(retries):
        try:
            raw = _llm_call(prompt, llm_backend, api_key, ollama_model,
                            system_instruction=system, max_tokens=2048)
            raw = _strip_markdown_fences(raw)

            ok, err = validate_rule_yaml(raw)
            if not ok:
                raise ValueError(err)

            with open(path, "w", encoding="utf-8") as f:
                f.write(raw)

            ok, err = validate_rule_file(path)
            if not ok:
                raise ValueError(err)

            return path

        except Exception as e:
            wait = _backoff_seconds(e, attempt)
            if attempt < retries - 1:
                if not quiet:
                    print(f"  [~] Retry {attempt+1}/{retries-1} for {name} "
                          f"(waiting {wait}s)...", flush=True)
                time.sleep(wait)
            else:
                if not quiet:
                    print(f"  [!] FAILED to generate rule for {name}: {e}")
    return None


def _backoff_seconds(err, attempt):
    """Compute back-off: respect Gemini retry hints when possible."""
    err_str = str(err)
    if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
        m = re.search(r"retryDelay.*?(\d+)", err_str)
        return (int(m.group(1)) + 2) if m else 15 * (attempt + 1)
    return 5 * (attempt + 1)

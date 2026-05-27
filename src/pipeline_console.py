"""Rich terminal presentation for Pipeline A (demo-friendly output)."""

from __future__ import annotations

import os
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

_console: Optional[Console] = None
_plain: bool = False


def configure(*, plain: bool = False) -> None:
    global _console, _plain
    _plain = plain
    _console = Console(force_terminal=not plain, no_color=plain, highlight=not plain)


def get_console() -> Console:
    global _console
    if _console is None:
        configure(plain=_plain)
    return _console


def verdict_style(rec: str) -> str:
    rec = (rec or "PROCEED").upper()
    if rec == "BLOCK":
        return "bold red"
    if rec == "REVIEW":
        return "bold yellow"
    return "bold green"


def source_style(source: str) -> str:
    src = (source or "none").lower()
    if src in ("registry", "cache"):
        return "cyan"
    if src in ("symbol", "demo"):
        return "magenta"
    if src in ("gemini", "ollama", "llm"):
        return "blue"
    return "dim"


def print_artifact_saved(label: str, path: str) -> None:
    get_console().print(f"  [green]✓[/green] {label} → [dim]{path}[/dim]")


def print_banner(
    *,
    project_dir: str,
    output_dir: str,
    started_at: str,
    use_graph: bool,
    use_neo4j: bool,
    llm_backend: str,
    skip_llm: bool,
    input_path: str,
) -> None:
    c = get_console()
    title = Text("Pre-Upgrade Risk Detection", style="bold white")
    subtitle = Text("Pipeline A — CVE → Patch → Reachability → Upgrade → Score", style="dim")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan", justify="right")
    grid.add_column(style="white")
    grid.add_row("Started", started_at)
    grid.add_row("Target", project_dir)
    grid.add_row("Output", output_dir)
    grid.add_row("Trivy input", input_path)
    grid.add_row("Graph", "enabled" if use_graph else "skipped (--no-graph)")
    grid.add_row("Neo4j", "connecting" if use_neo4j else "in-memory snapshot")
    grid.add_row("LLM rules", f"{llm_backend} ({'off' if skip_llm else 'on'})")
    c.print()
    c.print(Panel(grid, title=title, subtitle=subtitle, border_style="blue", padding=(1, 2)))


def print_phase(phase: str, title: str) -> None:
    c = get_console()
    c.print()
    c.print(Rule(f"[bold blue]{phase}[/bold blue]  [white]{title}[/white]", style="blue"))


def print_stat_row(label: str, value: Any, *, style: str = "green") -> None:
    c = get_console()
    c.print(f"  [cyan]{label:.<32}[/cyan] [{style}]{value}[/{style}]")


def print_stats_table(rows: list[tuple[str, Any, str]]) -> None:
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1), expand=False)
    t.add_column("Metric", style="cyan", min_width=28)
    t.add_column("Value", justify="right")
    for label, value, style in rows:
        t.add_row(label, Text(str(value), style=style))
    get_console().print(t)


def print_hero_fraction(reachable: int, total: int, *, noise_pct: float = 0.0) -> None:
    c = get_console()
    hero = Text()
    hero.append(f"{reachable}", style="bold white on blue")
    hero.append(f"  of  {total}", style="bold blue")
    hero.append("\nCVEs reachable in your code", style="dim")
    if total and noise_pct:
        hero.append(f"\n{noise_pct:.1f}% transitive noise filtered", style="green")
    c.print(Panel(hero, border_style="blue", padding=(1, 4)))


def print_families_table(families: dict[str, Any], limit: int = 12) -> None:
    t = Table(title="Top vulnerability families", box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Family", style="white")
    t.add_column("CVEs", justify="right", style="yellow")
    t.add_column("CWEs", style="dim")
    items = sorted(families.items(), key=lambda x: -len(x[1].cves))[:limit]
    for name, cluster in items:
        t.add_row(name, str(len(cluster.cves)), ", ".join(sorted(cluster.cwe_ids)[:3]))
    if len(families) > limit:
        t.add_row("…", f"+{len(families) - limit} more", "", style="dim")
    get_console().print(t)


def print_rule_resolution_summary(
    *,
    total: int,
    cache: int,
    registry: int,
    llm: int,
    skipped: int,
) -> None:
    t = Table(title="Rule resolution summary", box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Source", style="white")
    t.add_column("Count", justify="right")
    rows = [
        ("Cache", cache, "cyan"),
        ("Registry", registry, "green"),
        ("LLM generated", llm, "blue"),
        ("Skipped (no rule)", skipped, "dim"),
        ("Total families", total, "bold white"),
    ]
    for label, count, style in rows:
        t.add_row(label, Text(str(count), style=style))
    get_console().print(t)


def print_symbol_enrichment(count: int) -> None:
    if count:
        get_console().print(
            f"  [green]✓[/green] Patch-aware sink rules applied to "
            f"[bold]{count}[/bold] families"
        )
    else:
        get_console().print("  [dim]No patch-aware sink rules generated[/dim]")


def print_semgrep_scan_results(
    results: dict[str, list],
    *,
    semgrep_version: str,
    skipped: int,
    scanned: int,
    quiet: bool = False,
) -> None:
    """Live Semgrep scan summary (compact table unless verbose)."""
    c = get_console()
    if not quiet:
        c.print(f"  [cyan]Semgrep[/cyan] {semgrep_version} · "
                f"[green]{scanned}[/green] families scanned · "
                f"[dim]{skipped} skipped[/dim]")

    rows: list[tuple[str, str, str]] = []
    for family, matches in sorted(results.items(), key=lambda x: -len(x[1])):
        if matches:
            rows.append((family, str(len(matches)), "green"))
        else:
            rows.append((family, "0", "dim"))

    if not rows:
        c.print("  [yellow]No valid Semgrep rules to scan.[/yellow]")
        return

    # Show families with hits + top few zeros in quiet mode
    hits = [(f, h, s) for f, h, s in rows if h != "0"]
    if quiet:
        display = hits[:15]
    else:
        display = hits + [(f, h, s) for f, h, s in rows if h == "0"][:5]

    t = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
    t.add_column("Family", min_width=20)
    t.add_column("Matches", justify="right")
    t.add_column("", width=8)
    for fam, cnt, style in display:
        bar = "█" * min(int(cnt) if cnt.isdigit() else 0, 20)
        t.add_row(fam, Text(cnt, style=style), Text(bar, style=style))
    if quiet and len(hits) > 15:
        t.add_row("…", f"+{len(hits)-15} more", "", style="dim")
    c.print(t)
    total = sum(len(m) for m in results.values())
    c.print(f"  [bold green]Total Semgrep matches: {total}[/bold green]")


def print_semgrep_report_table(report: list[dict[str, Any]], *, hits_only: bool = False) -> None:
    display = [r for r in report if r.get("semgrep_matches")] if hits_only else report
    title = "Semgrep hits by family" if hits_only else "Semgrep results by family"
    t = Table(title=title, box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Family", min_width=22)
    t.add_column("Source")
    t.add_column("Hits", justify="right")
    t.add_column("CodeQL?", justify="center")

    for r in display:
        hits = len(r.get("semgrep_matches") or [])
        src = r.get("rule_source") or "none"
        hit_style = "bold green" if hits else "dim"
        codeql = "[green]YES[/green]" if hits else "[dim]—[/dim]"
        t.add_row(
            r.get("family", ""),
            Text(src, style=source_style(src)),
            Text(str(hits), style=hit_style),
            codeql,
        )

    actionable = sum(1 for r in report if r.get("ready_for_codeql"))
    get_console().print(t)
    get_console().print(
        f"  [green]{actionable}[/green] / {len(report)} families with Semgrep hits"
    )


def print_reachable_cves(
    symbol_findings: dict[str, Any],
    assessment: Optional[dict[str, Any]] = None,
    limit: int = 10,
) -> None:
    summary = symbol_findings.get("summary") or {}
    reachable: list[str] = list(summary.get("reachable_cves") or [])
    if not reachable:
        get_console().print("  [dim]No reachable CVEs in application code.[/dim]")
        return

    rec_by_cve: dict[str, str] = {}
    if assessment:
        for row in assessment.get("cves") or []:
            rec_by_cve[row.get("cve_id", "")] = row.get("recommendation", "REVIEW")

    t = Table(title="Reachable CVEs (in your code)", box=box.ROUNDED, header_style="bold green")
    t.add_column("CVE", style="white")
    t.add_column("Verdict", justify="center")
    t.add_column("Location", style="dim")

    findings = symbol_findings.get("findings_by_cve") or {}
    for cve in reachable[:limit]:
        rec = rec_by_cve.get(cve, "—")
        refs = (findings.get(cve) or {}).get("references") or []
        loc = "—"
        if refs:
            r0 = refs[0]
            loc = f"{r0.get('file', '?')}:{r0.get('line', '?')}"
        t.add_row(cve, Text(rec, style=verdict_style(rec)), loc)

    if len(reachable) > limit:
        t.add_row(f"… +{len(reachable) - limit} more", "", "", style="dim")
    get_console().print(t)


def print_upgrade_table(upgrade_sim: dict[str, Any]) -> None:
    if not upgrade_sim:
        return
    summary = upgrade_sim.get("summary") or {}
    verdict = summary.get("verdict", "?")
    vstyle = "green" if "PROCEED" in str(verdict).upper() else "yellow"

    t = Table(title="Upgrade simulation", box=box.ROUNDED, header_style="bold yellow")
    t.add_column("Field", style="cyan")
    t.add_column("Value")
    t.add_row("Verdict", Text(str(verdict), style=vstyle))
    t.add_row("Conflicts", str(len(upgrade_sim.get("conflicts") or [])))
    t.add_row("Cascade steps", str(len((upgrade_sim.get("cascade") or {}).get("chain") or [])))
    get_console().print(t)

    steps = (upgrade_sim.get("resolution_plan") or {}).get("steps") or []
    if not steps:
        return
    st = Table(title="Recommended upgrade order", box=box.SIMPLE_HEAVY, header_style="bold")
    st.add_column("#", justify="right", style="dim")
    st.add_column("Package", style="white")
    st.add_column("Upgrade", style="green")
    st.add_column("Reason", style="dim", max_width=50)
    for step in steps[:8]:
        st.add_row(
            str(step.get("order", "")),
            step.get("package", ""),
            f"{step.get('from', '?')} → {step.get('to', '?')}",
            (step.get("reason") or "")[:80],
        )
    get_console().print(st)


def print_risk_summary(assessment: dict[str, Any]) -> None:
    summary = assessment.get("summary") or {}
    rec = summary.get("overall_recommendation", "PROCEED")
    score = summary.get("overall_raw_risk", 0)
    block = summary.get("block_count", 0)
    review = summary.get("review_count", 0)
    total = summary.get("total_cves_scored", len(assessment.get("cves") or []))

    t = Table(title="Risk assessment (deterministic scorer)", box=box.DOUBLE_EDGE, header_style="bold")
    t.add_column("Metric", style="cyan")
    t.add_column("Value", justify="right")
    t.add_row("Overall recommendation", Text(rec, style=verdict_style(rec)))
    t.add_row("Risk score", f"{score}/100")
    t.add_row("CVEs scored", str(total))
    t.add_row("BLOCK", Text(str(block), style="red"))
    t.add_row("REVIEW", Text(str(review), style="yellow"))
    get_console().print(t)

    ranked = sorted(
        assessment.get("cves") or [],
        key=lambda c: (-(c.get("scores") or {}).get("raw_risk", 0), c.get("cve_id", "")),
    )[:8]
    if not ranked:
        return
    top = Table(title="Top risk CVEs", box=box.ROUNDED, header_style="bold red")
    top.add_column("CVE")
    top.add_column("Package")
    top.add_column("Score", justify="right")
    top.add_column("Verdict", justify="center")
    top.add_column("CVSS", justify="right")
    for row in ranked:
        rec_r = row.get("recommendation", "REVIEW")
        top.add_row(
            row.get("cve_id", ""),
            row.get("package", ""),
            str((row.get("scores") or {}).get("raw_risk", 0)),
            Text(rec_r, style=verdict_style(rec_r)),
            str(row.get("cvss_score", "—")),
        )
    get_console().print(top)


def print_graph_stats(graph_summary: dict[str, Any], *, neo4j: bool) -> None:
    t = Table(title="Knowledge graph", box=box.ROUNDED, header_style="bold magenta")
    t.add_column("Entity", style="cyan")
    t.add_column("Count", justify="right", style="white")
    for key in ("packages", "cves", "functions", "services", "edges"):
        t.add_row(key.capitalize(), str(graph_summary.get(key, 0)))
    t.add_row("Neo4j", "connected" if neo4j else "snapshot only")
    get_console().print(t)


def print_outputs_table(output_dir: str, report_path: Optional[str] = None) -> None:
    artifacts = [
        "pipeline_a_report.json",
        "patches.json",
        "symbol_scan.json",
        "upgrade_simulation.json",
        "graph_snapshot.json",
        "risk_assessment.json",
        "explanations.json",
        "risk_report.html",
    ]
    t = Table(title="Generated artifacts", box=box.ROUNDED, header_style="bold green")
    t.add_column("Status", justify="center", width=6)
    t.add_column("File", style="white")
    t.add_column("Path", style="dim")
    for name in artifacts:
        p = os.path.join(output_dir, name)
        ok = os.path.isfile(p)
        t.add_row(
            Text("✓" if ok else "·", style="green" if ok else "dim"),
            name,
            p if ok else "—",
        )
    get_console().print(t)
    html = report_path or os.path.join(output_dir, "risk_report.html")
    if os.path.isfile(html):
        get_console().print(Panel(
            f"[bold white]{html}[/bold white]\n[dim]Open in browser for the presentation report[/dim]",
            title="[green]HTML Report[/green]",
            border_style="green",
        ))


def print_final_story(
    *,
    total_cves: int,
    reachable: int,
    noise_pct: float,
    recommendation: str,
    risk_score: int,
    semgrep_hits: int,
    elapsed_sec: Optional[float] = None,
) -> None:
    c = get_console()
    c.print()
    lines = Table.grid(padding=(0, 2))
    lines.add_column(style="cyan", justify="right")
    lines.add_column()
    lines.add_row("Story", f"[bold]{reachable}[/bold] of [bold]{total_cves}[/bold] CVEs touch your code")
    lines.add_row("Verdict", Text(recommendation, style=verdict_style(recommendation)))
    lines.add_row("Risk score", f"{risk_score}/100")
    lines.add_row("Semgrep hits", str(semgrep_hits))
    lines.add_row("Noise cut", f"{noise_pct:.1f}%")
    if elapsed_sec is not None:
        lines.add_row("Runtime", f"{elapsed_sec:.1f}s")
    c.print(Panel(lines, title="[bold blue]Executive summary[/bold blue]", border_style="blue"))

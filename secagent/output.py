import json
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .scanner import ScanResult
from .checks.headers import Finding

console = Console()

SEVERITY_COLORS = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "green",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _severity_label(severity: str) -> Text:
    color = SEVERITY_COLORS.get(severity, "white")
    return Text(f"[{severity}]", style=f"bold {color}")


def print_results(result: ScanResult, ai_analysis: str | None = None) -> None:
    console.print()
    console.print(Panel.fit("[bold cyan]SecAgent[/bold cyan]  |  [dim]authorized security testing only[/dim]"))
    console.print(f"[bold]Target:[/bold] {result.target}")
    if result.status_code:
        console.print(f"[bold]Status:[/bold] {result.status_code}")
    if result.server:
        console.print(f"[bold]Server:[/bold] {result.server}")
    console.print()

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        return

    if result.technologies:
        for tech in result.technologies:
            console.print(f"[green][+][/green] Technology: {tech}")
        console.print()

    sorted_findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    for finding in sorted_findings:
        label = _severity_label(finding.severity)
        console.print(label, finding.title)
        if finding.detail:
            console.print(f"    [dim]{finding.detail}[/dim]")

    console.print()
    console.print(f"[bold]Endpoints discovered:[/bold] {len(result.endpoints)}")
    console.print(f"[bold]Parameters found:[/bold] {len(result.parameters)}")
    console.print(f"[bold]Findings:[/bold] {len(result.findings)}")

    if ai_analysis:
        console.print()
        console.print(Panel(ai_analysis, title="[bold cyan]AI Analysis[/bold cyan]", border_style="cyan"))


def to_json(result: ScanResult, ai_analysis: str | None = None) -> str:
    data = {
        "meta": {
            "tool": "SecAgent",
            "version": "0.1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "target": result.target,
        "status_code": result.status_code,
        "server": result.server,
        "technologies": result.technologies,
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "detail": f.detail,
                "remediation": f.remediation,
                "impact": f.impact,
                "cwe": f.cwe,
                "owasp": f.owasp,
            }
            for f in result.findings
        ],
        "endpoints": result.endpoints,
        "parameters": result.parameters,
        "summary": {
            "total_findings": len(result.findings),
            "by_severity": {
                sev: sum(1 for f in result.findings if f.severity == sev)
                for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
            },
        },
    }
    if ai_analysis:
        data["ai_analysis"] = ai_analysis
    return json.dumps(data, indent=2)


def to_markdown(result: ScanResult, ai_analysis: str | None = None) -> str:
    lines = [
        "# SecAgent Security Report",
        "",
        f"**Target:** {result.target}  ",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Status:** {result.status_code}  ",
        "",
        "## Technologies Detected",
        "",
    ]
    for tech in result.technologies or ["None detected"]:
        lines.append(f"- {tech}")

    lines += ["", "## Findings", ""]
    sorted_findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    for f in sorted_findings:
        lines.append(f"### [{f.severity}] {f.title}")
        if f.description:
            lines.append(f"**Description:** {f.description}  ")
        if f.impact:
            lines.append(f"**Impact:** {f.impact}  ")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}  ")
        if f.cwe:
            lines.append(f"**CWE:** {f.cwe} | **OWASP:** {f.owasp}  ")
        if f.detail:
            lines.append(f"**Detail:** {f.detail}  ")
        lines.append("")

    lines += ["## Endpoints Discovered", ""]
    for ep in result.endpoints[:50]:
        lines.append(f"- `{ep}`")
    if len(result.endpoints) > 50:
        lines.append(f"- ... and {len(result.endpoints) - 50} more")

    lines += ["", "## Summary", ""]
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        count = sum(1 for f in result.findings if f.severity == sev)
        lines.append(f"| {sev} | {count} |")

    if ai_analysis:
        lines += ["", "## AI Analysis", "", ai_analysis]

    return "\n".join(lines)

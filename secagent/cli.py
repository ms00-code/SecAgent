import asyncio
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

load_dotenv()

from .scanner import run_scan
from .output import print_results, to_json, to_markdown, console
from .ai import analyze_findings

app = typer.Typer(
    name="secagent",
    help="AI-assisted web security reconnaissance CLI — authorized testing only",
    add_completion=False,
)


def _format_findings_for_ai(result) -> str:
    lines = [f"Target: {result.target}", f"Status: {result.status_code}", ""]
    for f in result.findings:
        lines.append(f"[{f.severity}] {f.title}")
        if f.detail:
            lines.append(f"  Detail: {f.detail}")
    lines.append(f"\nEndpoints: {len(result.endpoints)}")
    lines.append(f"Technologies: {', '.join(result.technologies)}")
    return "\n".join(lines)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan (e.g. https://example.com)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results to file (.json or .md)"),
    markdown: bool = typer.Option(False, "--markdown", "--md", help="Output results as Markdown"),
    no_paths: bool = typer.Option(False, "--no-paths", help="Skip interesting path discovery"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI analysis of findings (requires API key)"),
    rate_delay: float = typer.Option(0.5, "--rate-delay", help="Delay between requests in seconds"),
) -> None:
    """Scan a target URL for web security issues (authorized testing only)."""

    if not json_output:
        console.print(f"[dim]Scanning {target} ...[/dim]")

    result = asyncio.run(run_scan(target, check_paths=not no_paths, rate_delay=rate_delay))

    ai_analysis = None
    if ai and result.findings:
        if not json_output:
            console.print("[dim]Running AI analysis...[/dim]")
        ai_analysis = asyncio.run(analyze_findings(_format_findings_for_ai(result)))

    if output:
        suffix = output.suffix.lower()
        if suffix == ".md":
            content = to_markdown(result, ai_analysis)
        else:
            content = to_json(result, ai_analysis)
        output.write_text(content, encoding="utf-8")
        if not json_output:
            console.print(f"[green]Report saved to {output}[/green]")

    if json_output:
        print(to_json(result, ai_analysis))
    elif markdown:
        print(to_markdown(result, ai_analysis))
    else:
        print_results(result, ai_analysis)


@app.command()
def version() -> None:
    """Show SecAgent version."""
    from . import __version__
    console.print(f"SecAgent {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

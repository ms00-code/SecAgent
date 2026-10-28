import httpx
from .headers import Finding


async def check_robots(client: httpx.AsyncClient, base_url: str, rate_limiter) -> tuple[list[Finding], list[str]]:
    findings = []
    discovered = []

    for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        rate_limiter.wait()
        try:
            r = await client.get(f"{base_url}{path}", follow_redirects=True)
            if r.status_code == 200:
                findings.append(Finding(
                    severity="INFO",
                    title=f"{path} discovered",
                    description=f"Found {path}",
                    detail=f"HTTP {r.status_code}, {len(r.content)} bytes",
                ))
                discovered.append(f"{base_url}{path}")
                if path == "/robots.txt":
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                endpoint = parts[1].strip()
                                if endpoint and endpoint != "/":
                                    discovered.append(endpoint)
        except httpx.RequestError:
            pass

    return findings, discovered

import httpx
from .headers import Finding
from ..utils import RateLimiter

INTERESTING_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.backup",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/wp-config.php",
    "/phpinfo.php",
    "/admin",
    "/admin/",
    "/wp-admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/openapi.json",
    "/swagger-ui.html",
    "/api/v1/",
    "/graphql",
    "/.well-known/security.txt",
    "/security.txt",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
]


async def check_interesting_paths(
    client: httpx.AsyncClient, base_url: str, rate_limiter: RateLimiter
) -> list[Finding]:
    findings = []
    for path in INTERESTING_PATHS:
        rate_limiter.wait()
        try:
            r = await client.get(f"{base_url}{path}", follow_redirects=False)
            if r.status_code in (200, 403):
                severity = "HIGH" if r.status_code == 200 else "MEDIUM"
                findings.append(Finding(
                    severity=severity,
                    title=f"Interesting path accessible: {path}",
                    description=f"{path} returned HTTP {r.status_code}",
                    detail=f"Size: {len(r.content)} bytes",
                    remediation=f"Restrict access to {path}",
                    cwe="CWE-538" if ".env" in path or ".git" in path else "CWE-200",
                    owasp="A01:2021",
                ))
        except httpx.RequestError:
            pass
    return findings

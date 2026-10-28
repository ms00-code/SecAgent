from dataclasses import dataclass, field
import httpx

from .checks.headers import check_security_headers, Finding
from .checks.cookies import check_cookies
from .checks.tech import detect_technologies
from .checks.robots import check_robots
from .checks.endpoints import extract_endpoints, extract_parameters
from .checks.paths import check_interesting_paths
from .checks.info import check_information_disclosure
from .utils import normalize_url, RateLimiter


@dataclass
class ScanResult:
    target: str
    status_code: int = 0
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    error: str = ""


async def run_scan(
    url: str,
    check_paths: bool = True,
    rate_delay: float = 0.5,
) -> ScanResult:
    target = normalize_url(url)
    result = ScanResult(target=target)
    rate_limiter = RateLimiter(rate_delay)

    headers = {
        "User-Agent": "SecAgent/0.1 (authorized security testing)",
        "Accept": "text/html,application/xhtml+xml,*/*",
    }

    async with httpx.AsyncClient(
        timeout=15,
        headers=headers,
        follow_redirects=True,
        verify=True,
    ) as client:
        try:
            rate_limiter.wait()
            resp = await client.get(target)
            result.status_code = resp.status_code
            result.server = resp.headers.get("server", "")
        except httpx.RequestError as exc:
            result.error = str(exc)
            return result

        body = resp.text
        resp_headers = dict(resp.headers)

        result.findings += check_security_headers(resp_headers)
        result.findings += check_cookies(resp.cookies)
        result.technologies = detect_technologies(resp_headers, body)

        robots_findings, discovered = await check_robots(client, target, rate_limiter)
        result.findings += robots_findings

        result.endpoints = extract_endpoints(target, body)
        result.parameters = extract_parameters(body)
        result.findings += check_information_disclosure(body, resp_headers)

        if check_paths:
            result.findings += await check_interesting_paths(client, target, rate_limiter)

    return result

import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from ..utils import same_origin


def extract_endpoints(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    endpoints: set[str] = set()

    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full = urljoin(base_url, href)
        if same_origin(base_url, full):
            endpoints.add(urlparse(full).path)

    for form in soup.find_all("form", action=True):
        action = form["action"]
        full = urljoin(base_url, action)
        if same_origin(base_url, full):
            endpoints.add(urlparse(full).path)

    for script in soup.find_all("script", src=True):
        src = script["src"]
        full = urljoin(base_url, src)
        if same_origin(base_url, full):
            endpoints.add(urlparse(full).path)

    api_pattern = re.compile(r'["\'](/(?:api|v\d|rest|graphql)[/\w-]*)["\']')
    for match in api_pattern.finditer(html):
        endpoints.add(match.group(1))

    return sorted(endpoints)


def extract_parameters(html: str) -> list[str]:
    params: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    for inp in soup.find_all(["input", "textarea", "select"]):
        name = inp.get("name") or inp.get("id")
        if name:
            params.add(name)
    return sorted(params)

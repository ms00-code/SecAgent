import pytest
import httpx
import respx

from secagent.scanner import run_scan


@respx.mock
@pytest.mark.asyncio
async def test_scan_basic():
    respx.get("https://example-test.com").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/html", "server": "nginx"},
            text="<html><body><a href='/about'>About</a></body></html>",
        )
    )
    respx.get("https://example-test.com/robots.txt").mock(return_value=httpx.Response(404))
    respx.get("https://example-test.com/sitemap.xml").mock(return_value=httpx.Response(404))
    respx.get("https://example-test.com/sitemap_index.xml").mock(return_value=httpx.Response(404))

    result = await run_scan("https://example-test.com", check_paths=False)

    assert result.status_code == 200
    assert result.error == ""
    assert any(f.severity in ("LOW", "MEDIUM", "HIGH", "INFO") for f in result.findings)


@respx.mock
@pytest.mark.asyncio
async def test_scan_connection_error():
    respx.get("https://unreachable-host-xyz.com").mock(side_effect=httpx.ConnectError("unreachable"))

    result = await run_scan("https://unreachable-host-xyz.com", check_paths=False)

    assert result.error != ""
    assert result.status_code == 0

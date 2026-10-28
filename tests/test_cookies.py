import http.cookiejar
import httpx
from secagent.checks.cookies import check_cookies


def _make_cookies(attrs: dict) -> httpx.Cookies:
    jar = http.cookiejar.CookieJar()
    cookie = http.cookiejar.Cookie(
        version=0,
        name=attrs.get("name", "session"),
        value="test",
        port=None,
        port_specified=False,
        domain="example.com",
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=attrs.get("secure", False),
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": ""} if attrs.get("httponly", False) else {},
    )
    jar.set_cookie(cookie)
    cookies = httpx.Cookies()
    cookies.jar = jar
    return cookies


def test_insecure_cookie():
    cookies = _make_cookies({"name": "session", "secure": False, "httponly": False})
    findings = check_cookies(cookies)
    titles = [f.title for f in findings]
    assert any("Secure" in t for t in titles)


def test_secure_httponly_cookie():
    cookies = _make_cookies({"name": "session", "secure": True, "httponly": True})
    findings = check_cookies(cookies)
    secure_findings = [f for f in findings if "Secure flag" in f.title]
    assert len(secure_findings) == 0

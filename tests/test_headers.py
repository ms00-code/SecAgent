from secagent.checks.headers import check_security_headers


def test_all_headers_present():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    findings = check_security_headers(headers)
    security_findings = [f for f in findings if "Missing" in f.title]
    assert len(security_findings) == 0


def test_missing_csp():
    headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    findings = check_security_headers(headers)
    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)


def test_leaky_server_header():
    headers = {"Server": "nginx/1.18.0"}
    findings = check_security_headers(headers)
    assert any("Server" in f.title for f in findings)


def test_missing_all_headers():
    findings = check_security_headers({})
    missing = [f for f in findings if "Missing" in f.title]
    assert len(missing) >= 6

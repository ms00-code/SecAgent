from .headers import Finding


def check_cookies(cookies) -> list[Finding]:
    findings = []
    for cookie in cookies.jar:
        name = cookie.name
        if not cookie.secure:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"Cookie '{name}' missing Secure flag",
                description=f"Cookie '{name}' is not marked Secure",
                impact="Cookie may be transmitted over HTTP",
                remediation=f"Set Secure flag on cookie '{name}'",
                cwe="CWE-614",
                owasp="A02:2021",
            ))
        if "HttpOnly" not in getattr(cookie, "_rest", {}):
            findings.append(Finding(
                severity="MEDIUM",
                title=f"Cookie '{name}' missing HttpOnly flag",
                description=f"Cookie '{name}' is accessible via JavaScript",
                impact="Cookie may be stolen via XSS",
                remediation=f"Set HttpOnly flag on cookie '{name}'",
                cwe="CWE-1004",
                owasp="A07:2021",
            ))
        samesite = cookie._rest.get("SameSite", "").lower() if hasattr(cookie, "_rest") else ""
        if samesite not in ("strict", "lax"):
            findings.append(Finding(
                severity="LOW",
                title=f"Cookie '{name}' missing or weak SameSite attribute",
                description=f"Cookie '{name}' SameSite is '{samesite or 'not set'}'",
                impact="Cookie may be sent in cross-site requests (CSRF risk)",
                remediation=f"Set SameSite=Lax or SameSite=Strict on cookie '{name}'",
                cwe="CWE-352",
                owasp="A01:2021",
            ))
    return findings

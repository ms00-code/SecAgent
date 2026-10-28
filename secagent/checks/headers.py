from dataclasses import dataclass, field


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "Missing Content-Security-Policy header",
        "impact": "Increases risk of XSS and data injection attacks",
        "remediation": "Define a strict CSP policy: Content-Security-Policy: default-src 'self'",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options header",
        "impact": "Site may be vulnerable to clickjacking",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Missing X-Content-Type-Options header",
        "impact": "Browser may MIME-sniff responses, enabling attacks",
        "remediation": "Add X-Content-Type-Options: nosniff",
        "cwe": "CWE-16",
        "owasp": "A05:2021",
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": "Missing Strict-Transport-Security (HSTS) header",
        "impact": "Site susceptible to protocol downgrade and MITM attacks",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
        "owasp": "A02:2021",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Missing Referrer-Policy header",
        "impact": "Referrer information may leak to third parties",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
        "owasp": "A01:2021",
    },
    "Permissions-Policy": {
        "severity": "INFO",
        "description": "Missing Permissions-Policy header",
        "impact": "Browser features (camera, mic, geolocation) not explicitly restricted",
        "remediation": "Add Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "cwe": "CWE-16",
        "owasp": "A05:2021",
    },
}

LEAKY_HEADERS = {
    "Server": "Server header discloses software version",
    "X-Powered-By": "X-Powered-By header discloses technology stack",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-Generator": "Generator header discloses CMS/framework",
}


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    detail: str = ""
    remediation: str = ""
    impact: str = ""
    cwe: str = ""
    owasp: str = ""


def check_security_headers(headers: dict) -> list[Finding]:
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in lower_headers:
            findings.append(Finding(
                severity=meta["severity"],
                title=meta["description"],
                description=meta["description"],
                impact=meta["impact"],
                remediation=meta["remediation"],
                cwe=meta["cwe"],
                owasp=meta["owasp"],
            ))

    for header, msg in LEAKY_HEADERS.items():
        val = lower_headers.get(header.lower())
        if val:
            findings.append(Finding(
                severity="LOW",
                title=msg,
                description=msg,
                detail=f"Value: {val}",
                remediation=f"Remove or sanitize the {header} response header",
                cwe="CWE-200",
                owasp="A01:2021",
            ))

    return findings

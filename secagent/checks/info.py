import re
from .headers import Finding


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
IP_RE = re.compile(r"\b(?:10|172(?:\.(?:1[6-9]|2\d|3[01]))|192\.168)\.\d{1,3}\.\d{1,3}\b")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


def check_information_disclosure(html: str, headers: dict) -> list[Finding]:
    findings = []

    emails = EMAIL_RE.findall(html)
    if emails:
        findings.append(Finding(
            severity="LOW",
            title="Email addresses found in page source",
            description="Email addresses exposed in HTML source",
            detail=", ".join(set(emails[:5])),
            remediation="Remove or obfuscate email addresses in HTML",
            cwe="CWE-200",
            owasp="A01:2021",
        ))

    ips = IP_RE.findall(html)
    if ips:
        findings.append(Finding(
            severity="MEDIUM",
            title="Internal IP addresses found in page source",
            description="Private/internal IPs exposed in HTML",
            detail=", ".join(set(ips[:5])),
            remediation="Remove internal IP references from public responses",
            cwe="CWE-200",
            owasp="A01:2021",
        ))

    comments = COMMENT_RE.findall(html)
    sensitive_comments = [c.strip() for c in comments if any(
        kw in c.lower() for kw in ("todo", "password", "secret", "key", "token", "fixme", "hack", "debug")
    )]
    if sensitive_comments:
        findings.append(Finding(
            severity="LOW",
            title="Sensitive keywords found in HTML comments",
            description="HTML comments contain potentially sensitive information",
            detail="; ".join(sensitive_comments[:3])[:200],
            remediation="Remove sensitive information from HTML comments before deployment",
            cwe="CWE-615",
            owasp="A01:2021",
        ))

    debug_headers = ["X-Debug", "X-Debug-Token", "X-Symfony-Debug", "X-Application-Context"]
    for h in debug_headers:
        if h.lower() in {k.lower() for k in headers}:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"Debug header present: {h}",
                description=f"Server returns debug header {h}",
                remediation=f"Disable debug mode and remove {h} header in production",
                cwe="CWE-489",
                owasp="A05:2021",
            ))

    return findings

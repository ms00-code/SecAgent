import os
import httpx


def _get_client_config() -> tuple[str, str, str] | None:
    """Return (api_key, base_url, provider) or None if no key configured."""
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    openai_base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    if anthropic_key:
        return (anthropic_key, "https://api.anthropic.com/v1", "anthropic")
    if openai_key:
        return (openai_key, openai_base, "openai")
    return None


async def analyze_findings(findings_text: str) -> str | None:
    cfg = _get_client_config()
    if not cfg:
        return None

    api_key, base_url, provider = cfg
    model = os.getenv("AI_MODEL", "claude-sonnet-4-6" if provider == "anthropic" else "gpt-4o-mini")

    prompt = f"""You are a web application security expert. Analyze these security findings and provide:
1. Overall risk assessment
2. Most critical issues and their impact
3. Prioritized remediation steps
4. Relevant CWE/OWASP references

Findings:
{findings_text}

Be concise and actionable. Focus on what matters most."""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            if provider == "anthropic":
                resp = await client.post(
                    f"{base_url}/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 1024,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                resp.raise_for_status()
                return resp.json()["content"][0]["text"]
            else:
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 1024,
                    },
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
    except Exception as exc:
        return f"AI analysis unavailable: {exc}"

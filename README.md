# SecAgent

AI-assisted web security reconnaissance CLI for authorized security testing.

```text
SecAgent
Target: https://example.com

[+] Technology: Nginx
[+] Technology: React

[MEDIUM] Missing Content-Security-Policy
[MEDIUM] Missing X-Frame-Options
[LOW]    Missing X-Content-Type-Options
[INFO]   robots.txt discovered

Endpoints discovered: 12
Findings: 4
```

## Installation

```bash
git clone https://github.com/ms00-code/secagent
cd secagent
pip install -e .
```

## Usage

```bash
# Basic scan
secagent scan https://example.com

# JSON output
secagent scan https://example.com --json

# Save report (JSON or Markdown)
secagent scan https://example.com --output report.json
secagent scan https://example.com --output report.md

# AI analysis (requires ANTHROPIC_API_KEY or OPENAI_API_KEY)
secagent scan https://example.com --ai

# Skip interesting path discovery (faster, fewer requests)
secagent scan https://example.com --no-paths

# Adjust request rate (default: 0.5s between requests)
secagent scan https://example.com --rate-delay 1.0
```

## Checks performed

- HTTP response status and server information
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie security flags (Secure, HttpOnly, SameSite)
- Technology fingerprinting (server, framework, CMS, CDN)
- robots.txt and sitemap discovery
- Link, form, and API endpoint extraction
- Interesting path detection (.env, .git, admin panels, API docs, backup files)
- Information disclosure (internal IPs, emails, sensitive HTML comments, debug headers)

## AI integration

Set one of these environment variables, then pass `--ai`:

```bash
# Anthropic (Claude)
export ANTHROPIC_API_KEY=sk-ant-...

# OpenAI or any compatible API
export OPENAI_API_KEY=sk-...
export OPENAI_BASE_URL=https://api.openai.com/v1  # optional

# Override the model
export AI_MODEL=claude-sonnet-4-6
```

The tool works fully without an API key. `--ai` is optional and adds remediation guidance.

## Environment variables

```bash
cp .env.example .env
# edit .env with your API key
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Requirements

- Python 3.12+
- httpx, beautifulsoup4, typer, rich, python-dotenv

## Legal

**For authorized security testing only.** You are responsible for obtaining proper written
authorization before scanning any target you do not own. Unauthorized testing may violate
computer crime laws in your jurisdiction.

## License

MIT — see [LICENSE](LICENSE)

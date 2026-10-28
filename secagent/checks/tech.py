import re


SIGNATURES = [
    ("Server", r"nginx", "Nginx"),
    ("Server", r"apache", "Apache"),
    ("Server", r"iis", "IIS"),
    ("Server", r"litespeed", "LiteSpeed"),
    ("X-Powered-By", r"php", "PHP"),
    ("X-Powered-By", r"asp\.net", "ASP.NET"),
    ("X-Powered-By", r"express", "Express.js"),
    ("X-Generator", r"wordpress", "WordPress"),
    ("X-Generator", r"drupal", "Drupal"),
    ("X-Generator", r"joomla", "Joomla"),
]

BODY_SIGNATURES = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"Joomla!", "Joomla"),
    (r'<meta name="generator" content="Drupal', "Drupal"),
    (r"React", "React"),
    (r"__vue_app__", "Vue.js"),
    (r"ng-version|angular", "Angular"),
    (r"next/static|__NEXT_DATA__", "Next.js"),
    (r"nuxt", "Nuxt.js"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
    (r"cdn\.shopify", "Shopify"),
    (r"cloudflare", "Cloudflare"),
]


def detect_technologies(headers: dict, body: str) -> list[str]:
    techs: set[str] = set()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

    for header, pattern, name in SIGNATURES:
        val = lower_headers.get(header.lower(), "")
        if re.search(pattern, val, re.IGNORECASE):
            techs.add(name)

    for pattern, name in BODY_SIGNATURES:
        if re.search(pattern, body, re.IGNORECASE):
            techs.add(name)

    return sorted(techs)

"""Target parser — IP, domain, URL, CIDR."""
import ipaddress
import re
from urllib.parse import urlparse


def parse_target(target):
    if not target or not target.strip():
        raise ValueError("Target cannot be empty")

    target = target.strip()

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: {target}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return {
            "raw": target, "type": "url",
            "host": parsed.hostname,
            "scheme": parsed.scheme, "port": port,
            "url": target, "nmap_target": parsed.hostname,
        }

    try:
        ipaddress.ip_network(target, strict=False)
        return {
            "raw": target,
            "type": "cidr" if "/" in target else "ip",
            "host": target, "scheme": None, "port": None,
            "url": None, "nmap_target": target,
        }
    except ValueError:
        pass

    domain_regex = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
    if re.match(domain_regex, target):
        return {
            "raw": target, "type": "domain",
            "host": target, "scheme": "https", "port": 443,
            "url": f"https://{target}", "nmap_target": target,
        }

    raise ValueError(
        f"Cannot parse '{target}'. Use IP, domain, or URL."
    )


def detect_waf(url, timeout=10):
    """Detect WAF via headers. Returns dict always."""
    try:
        import requests
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        headers_str = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
        signatures = {
            "cloudflare": ["cloudflare", "cf-ray"],
            "akamai": ["akamai", "akamaighost"],
            "imperva": ["incap_ses", "visid_incap"],
            "sucuri": ["x-sucuri-id", "sucuri"],
            "aws-cloudfront": ["x-amz-cf-id", "cloudfront"],
            "fastly": ["x-fastly", "fastly"],
            "azure-front-door": ["x-azure-ref"],
        }
        detected = [
            waf for waf, sigs in signatures.items()
            if any(sig in headers_str for sig in sigs)
        ]
        return {
            "status_code": r.status_code,
            "server": r.headers.get("Server", "unknown"),
            "waf_detected": detected,
            "final_url": r.url,
        }
    except Exception as e:
        return {"error": str(e), "waf_detected": []}

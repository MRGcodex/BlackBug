"""Vulnerability detection across all endpoints."""
from modules.web_scanner import run_nuclei, run_sqlmap


def detect_vulnerabilities(target_info, recon, runner, tool_status, verbose=False):
    print(f"\n[MRGcodex] Phase 2: Vulnerability Detection")

    urls = []
    if target_info.get("url"):
        urls.append(target_info["url"])

    if recon.get("status") == "success":
        for r in recon.get("results", []):
            if (r.get("service") in ("http", "https", "http-proxy", "https-alt")
                    or r.get("port") in (80, 443, 8080, 8443, 8000, 8888)):
                scheme = (
                    "https" if ("https" in r["service"]
                                or r["port"] in (443, 8443)) else "http"
                )
                url = f"{scheme}://{r['host']}:{r['port']}"
                if url not in urls:
                    urls.append(url)

    # Fallback: if IP/CIDR given without URL and recon yielded nothing
    if not urls and target_info.get("host"):
        host = target_info["host"]
        if target_info["type"] in ("ip", "domain"):
            urls.append(f"http://{host}")
            if target_info["type"] == "domain":
                urls.append(f"https://{host}")

    if not urls:
        print("[MRGcodex] No web endpoints — skipping")
        return []

    print(f"[MRGcodex] Scanning {len(urls)} web endpoint(s)")
    vulns = []

    for url in urls:
        print(f"\n{'─' * 70}\n[MRGcodex] {url}\n{'─' * 70}")

        if tool_status.get("nuclei"):
            nuc = run_nuclei(url, runner)
            for f in nuc.get("findings", []):
                info = f.get("info", {})
                cls = info.get("classification", {}) or {}
                cve_ids = cls.get("cve-id", [])
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids]
                v = {
                    "type": "nuclei", "url": url,
                    "name": info.get("name", "Unknown"),
                    "severity": info.get("severity", "unknown").lower(),
                    "cve_id": cve_ids[0] if cve_ids else None,
                    "template": f.get("template-id"),
                    "matched_at": f.get("matched-at", url),
                }
                vulns.append(v)
                print(f"[MRGcodex] VULN {v['severity'].upper()}: {v['name']}")
                if v["cve_id"]:
                    print(f"          CVE: {v['cve_id']}")
        else:
            print("[MRGcodex] nuclei not installed — skipped")

        if tool_status.get("sqlmap"):
            sqli = run_sqlmap(url, runner)
            if sqli.get("injectable"):
                vulns.append({
                    "type": "sql_injection", "url": url,
                    "name": "SQL Injection", "severity": "critical",
                    "cve_id": None,
                })
        else:
            print("[MRGcodex] sqlmap not installed — skipped")

    print(f"\n[MRGcodex] Total vulnerabilities: {len(vulns)}")
    return vulns

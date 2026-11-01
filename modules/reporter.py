"""JSON report — MRGcodex"""
import json
import os
from datetime import datetime, timezone

BRAND = {
    "tool": "BlackBug",
    "version": "2.3.0",
    "author": "MRGcodex",
    "github": "https://github.com/MRGcodex/BlackBug",
    "license": "MIT with Ethical Use Clause",
}


def generate_report(target, target_info, recon, vulns, exploit_map,
                    cve_intel_map, exploitation_results, cmd_history):
    ts = datetime.now(timezone.utc)

    report = {
        "brand": "MRGcodex",
        "tool": BRAND["tool"],
        "version": BRAND["version"],
        "author": BRAND["author"],
        "github": BRAND["github"],
        "license": BRAND["license"],
        "disclaimer": "EDUCATIONAL USE ONLY. Authorized testing only.",

        "scan_metadata": {
            "target": target,
            "target_type": target_info.get("type"),
            "host": target_info.get("host"),
            "url": target_info.get("url"),
            "timestamp": ts.isoformat(),
            "purpose": "Educational / Authorized Security Testing",
            "warning": "Unauthorized use is illegal. You are solely responsible.",
        },

        "reconnaissance": recon,
        "vulnerabilities": vulns,
        "cve_intelligence": cve_intel_map,
        "exploits_found": exploit_map,
        "exploitation_results": exploitation_results,
        "command_history": cmd_history,

        "summary": {
            "total_vulns": len(vulns),
            "critical": sum(1 for v in vulns if v.get("severity") == "critical"),
            "high": sum(1 for v in vulns if v.get("severity") == "high"),
            "medium": sum(1 for v in vulns if v.get("severity") == "medium"),
            "total_exploits_found": sum(len(e) for e in exploit_map.values()),
            "successful_exploits": sum(
                1 for r in exploitation_results if r.get("success")
            ),
            "cves_enriched": len(cve_intel_map),
            "cves_exploited_in_wild": sum(
                1 for v in cve_intel_map.values()
                if v.get("merged", {}).get("exploited_in_wild")
            ),
        },
    }

    os.makedirs("reports", exist_ok=True)
    safe = (
        str(target)
        .replace(".", "_").replace("/", "_")
        .replace(":", "_").replace(" ", "_")
    )
    filename = f"reports/MRGcodex_{safe}_{int(ts.timestamp())}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print(f"\n[MRGcodex] Report: {filename}")
    return filename

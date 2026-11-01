"""Multi-source CVE intelligence — no API keys.

Sources:
  - NVD (primary)
  - CISA KEV (exploited-in-wild flag, cached 24h)
  - EPSS (exploit probability)
  - GitHub Security Advisories
  - CIRCL CVE mirror
"""
import json
import os
import time

import requests

CACHE_DIR = os.path.expanduser("~/.cache/blackbug")
KEV_CACHE = os.path.join(CACHE_DIR, "kev.json")
KEV_TTL_HOURS = 24
UA = {"User-Agent": "BlackBug-MRGcodex/2.3"}


def _ensure_cache():
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except Exception:
        pass


def clear_kev_cache():
    try:
        if os.path.exists(KEV_CACHE):
            os.unlink(KEV_CACHE)
            print("[MRGcodex] KEV cache cleared")
    except Exception:
        pass


def get_cve_intel(cve_id, verbose=False):
    cve_id = cve_id.upper()
    print(f"\n[MRGcodex] CVE intel: {cve_id}")

    intel = {
        "cve_id": cve_id,
        "sources": {},
        "merged": {
            "description": None, "cvss_score": None, "cvss_vector": None,
            "severity": None, "published": None, "modified": None,
            "exploited_in_wild": False,
            "epss_score": None, "epss_percentile": None,
            "references": [], "cwe": [],
        },
    }

    # 1. NVD
    try:
        nvd = _fetch_nvd(cve_id)
        if nvd:
            intel["sources"]["nvd"] = nvd
            intel["merged"].update(_extract_nvd(nvd))
            print(f"  ✓ NVD")
    except Exception as e:
        if verbose:
            print(f"  [!] NVD: {e}")

    # 2. CISA KEV
    try:
        kev = _check_kev(cve_id)
        if kev is not None and kev is not False:
            intel["sources"]["cisa_kev"] = kev
            intel["merged"]["exploited_in_wild"] = True
            print(f"  ✓ CISA KEV — EXPLOITED IN WILD")
        elif kev is False:
            intel["sources"]["cisa_kev"] = {"status": "not_listed"}
            print(f"  ✓ CISA KEV (not listed)")
    except Exception as e:
        if verbose:
            print(f"  [!] KEV: {e}")

    # 3. EPSS
    try:
        epss = _fetch_epss(cve_id)
        if epss:
            intel["sources"]["epss"] = epss
            intel["merged"]["epss_score"] = epss.get("epss")
            intel["merged"]["epss_percentile"] = epss.get("percentile")
            print(f"  ✓ EPSS score: {epss.get('epss', 'N/A')}")
    except Exception as e:
        if verbose:
            print(f"  [!] EPSS: {e}")

    # 4. GitHub Advisory
    try:
        gh = _fetch_github(cve_id)
        if gh:
            intel["sources"]["github_advisory"] = gh
            print(f"  ✓ GitHub Advisory")
    except Exception as e:
        if verbose:
            print(f"  [!] GH: {e}")

    # 5. CIRCL
    try:
        circl = _fetch_circl(cve_id)
        if circl:
            intel["sources"]["circl"] = circl
            refs = circl.get("references", [])
            if isinstance(refs, list):
                intel["merged"]["references"].extend(refs[:10])
            # Fill CVSS if NVD missing
            if not intel["merged"]["cvss_score"] and circl.get("cvss"):
                intel["merged"]["cvss_score"] = circl["cvss"]
            print(f"  ✓ CIRCL")
    except Exception as e:
        if verbose:
            print(f"  [!] CIRCL: {e}")

    return intel


def _fetch_nvd(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=20, headers=UA)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 403 and attempt < 2:
                time.sleep(6)
                continue
        except requests.Timeout:
            if attempt < 2:
                continue
    return None


def _extract_nvd(nvd):
    out = {}
    vulns = nvd.get("vulnerabilities", [])
    if not vulns:
        return out
    cve = vulns[0].get("cve", {})

    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            out["description"] = d.get("value")
            break

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            out["cvss_score"] = m.get("baseScore")
            out["cvss_vector"] = m.get("vectorString")
            out["severity"] = m.get("baseSeverity")
            break

    out["published"] = cve.get("published")
    out["modified"] = cve.get("lastModified")
    out["references"] = [
        r.get("url") for r in cve.get("references", []) if r.get("url")
    ][:10]
    out["cwe"] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                out["cwe"].append(val)
    return out


def _check_kev(cve_id):
    """Returns dict if listed, False if checked-not-found, None if unchecked."""
    _ensure_cache()
    data = None

    if os.path.exists(KEV_CACHE):
        try:
            age_h = (time.time() - os.path.getmtime(KEV_CACHE)) / 3600
            if age_h < KEV_TTL_HOURS:
                with open(KEV_CACHE, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except Exception:
            pass

    if data is None:
        try:
            r = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json",
                timeout=30, headers=UA,
            )
            if r.status_code == 200:
                data = r.json()
                try:
                    with open(KEV_CACHE, "w", encoding="utf-8") as f:
                        json.dump(data, f)
                except Exception:
                    pass
        except Exception:
            if os.path.exists(KEV_CACHE):
                try:
                    with open(KEV_CACHE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass

    if data is None:
        return None

    target = cve_id.upper()
    for v in data.get("vulnerabilities", []):
        if v.get("cveID", "").upper() == target:
            return v
    return False


def _fetch_epss(cve_id):
    try:
        r = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            timeout=10, headers=UA,
        )
        if r.status_code == 200:
            data = r.json()
            rows = data.get("data", [])
            if rows:
                return {
                    "epss": rows[0].get("epss"),
                    "percentile": rows[0].get("percentile"),
                }
    except Exception:
        pass
    return None


def _fetch_github(cve_id):
    try:
        r = requests.get(
            f"https://api.github.com/advisories?cve_id={cve_id}",
            timeout=10, headers={**UA, "Accept": "application/vnd.github+json"},
        )
        if r.status_code == 200:
            data = r.json()
            if data:
                return data[0] if isinstance(data, list) else data
    except Exception:
        pass
    return None


def _fetch_circl(cve_id):
    try:
        r = requests.get(
            f"https://cve.circl.lu/api/cve/{cve_id}",
            timeout=10, headers=UA,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

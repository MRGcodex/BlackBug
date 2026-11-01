#!/usr/bin/env python3
"""BlackBug v2.3.0 — MRGcodex"""
import argparse
import os
import shutil
import sys
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    C, G, Y, R, B, RS = (
        Fore.CYAN, Fore.GREEN, Fore.YELLOW,
        Fore.RED, Style.BRIGHT, Style.RESET_ALL
    )
except ImportError:
    C = G = Y = R = B = RS = ""

from modules.target_parser import parse_target, detect_waf
from modules.command_runner import CommandRunner
from modules.tool_manager import (
    detect_tools, print_tool_status, suggest_install,
    install_python_deps, check_python_imports,
)
from modules.recon import run_recon
from modules.vuln_detector import detect_vulnerabilities
from modules.cve_intel import get_cve_intel, clear_kev_cache
from modules.exploit_finder import find_exploits_for_cve
from modules.exploit_engine import attempt_exploitation
from modules.reporter import generate_report, BRAND


def banner():
    print(C + r"""
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗ ██╗   ██╗ ██████╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║   ██║██╔════╝
    ██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║██║  ███╗
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║██║   ██║
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝╚██████╔╝
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝
    """ + RS)
    print(f"  {B}{C}MRGcodex{RS}  |  {B}BlackBug v{BRAND['version']}{RS}")
    print(f"  {Y}EDUCATIONAL USE ONLY — Authorized testing only{RS}\n")


def show_disclaimer():
    print("=" * 70)
    print(f"  {R}{B}BLACKBUG — MRGcodex{RS}")
    print("=" * 70)
    print("  This tool AUTOMATICALLY EXPLOITS discovered vulnerabilities.")
    print("  Using it on systems you don't own is ILLEGAL.")
    print("  You MUST have WRITTEN PERMISSION before proceeding.")
    print("=" * 70)
    try:
        consent = input(f"  Type {B}'I AGREE'{RS} to continue: ").strip()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
    if consent != "I AGREE":
        print(f"  {R}[!] Consent not given. Exiting.{RS}")
        sys.exit(0)


def update_databases(runner):
    print(f"\n[MRGcodex] Updating databases...")
    if shutil.which("nuclei"):
        runner.run(["nuclei", "-update-templates"], timeout=300, label="nuclei-update")
    if shutil.which("msfupdate"):
        runner.run(["msfupdate"], timeout=600, label="msf-update")
    if shutil.which("searchsploit"):
        runner.run(["searchsploit", "-u"], timeout=300, label="edb-update")
    clear_kev_cache()
    print(f"[MRGcodex] All databases updated.")


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="BlackBug v2.3 — MRGcodex",
        epilog="Example: python blackbug.py -t https://example.com",
    )
    parser.add_argument("-t", "--target", help="IP / domain / URL / CIDR")
    parser.add_argument("-c", "--cve", help="Extra CVE to investigate")
    parser.add_argument("--install", action="store_true", help="Install Python deps")
    parser.add_argument("--check", action="store_true", help="Verify all imports")
    parser.add_argument("--update", action="store_true", help="Update all databases")
    parser.add_argument("--no-consent", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show commands but don't execute exploits")
    parser.add_argument("--no-exploit", action="store_true",
                        help="Detect vulns only, no exploitation")
    parser.add_argument("--no-cve-intel", action="store_true",
                        help="Skip multi-source CVE intel")
    parser.add_argument("--web-only", action="store_true",
                        help="Skip recon, only web scan")
    parser.add_argument("--skip-web", action="store_true")
    parser.add_argument("--skip-recon", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    # Utility modes
    if args.install:
        install_python_deps()
        return
    if args.check:
        ok = check_python_imports()
        sys.exit(0 if ok else 1)
    if args.update:
        runner = CommandRunner(verbose=True)
        update_databases(runner)
        return
    if not args.target:
        parser.print_help()
        sys.exit(1)
    if not args.no_consent:
        show_disclaimer()

    # ---- Parse target ----
    print(f"\n{C}{'=' * 70}{RS}\n{C}TARGET{RS}\n{C}{'=' * 70}{RS}")
    try:
        info = parse_target(args.target)
        print(f"  Input:  {info['raw']}")
        print(f"  Type:   {info['type']}")
        print(f"  Host:   {info['host']}")
        if info["url"]:
            print(f"  URL:    {info['url']}")
    except ValueError as e:
        print(f"{R}[!] {e}{RS}")
        sys.exit(1)

    if info["url"]:
        waf = detect_waf(info["url"])
        detected = waf.get("waf_detected", [])
        if detected:
            print(f"  {Y}WAF: {', '.join(detected)} — may block scans{RS}")

    # ---- Tools ----
    status = detect_tools()
    print_tool_status(status)
    for tool, avail in status.items():
        if not avail:
            suggest_install(tool)

    # ---- Runner ----
    os.makedirs("reports", exist_ok=True)
    log_file = f"reports/MRGcodex_log_{int(datetime.now().timestamp())}.txt"
    runner = CommandRunner(log_file=log_file, verbose=True)

    # ---- Phase 1: Recon ----
    recon = {"status": "skipped"}
    if not args.skip_recon and not args.web_only:
        if status.get("nmap"):
            recon = run_recon(info["nmap_target"], runner)
            if recon["status"] == "error":
                print(f"{R}[!] Recon: {recon.get('message')}{RS}")
        else:
            print(f"{Y}[!] nmap missing — skipping recon{RS}")

    # ---- Phase 2: Vuln detection ----
    vulns = []
    if not args.skip_web:
        vulns = detect_vulnerabilities(info, recon, runner, status,
                                       verbose=args.verbose)

    # ---- CVEs ----
    all_cves = {v["cve_id"] for v in vulns if v.get("cve_id")}
    if args.cve:
        args.cve = args.cve.upper()
        if not args.cve.startswith("CVE-"):
            print(f"{R}[!] CVE format: CVE-YYYY-NNNNN{RS}")
            sys.exit(1)
        all_cves.add(args.cve)

    # ---- CVE Intel ----
    cve_intel_map = {}
    if all_cves and not args.no_cve_intel:
        print(f"\n{C}{'=' * 70}{RS}\n{C}CVE INTELLIGENCE{RS}\n{C}{'=' * 70}{RS}")
        for cve in all_cves:
            cve_intel_map[cve] = get_cve_intel(cve, verbose=args.verbose)

    # ---- Find exploits ----
    exploit_map = {}
    if all_cves:
        print(f"\n{C}{'=' * 70}{RS}\n{C}EXPLOIT LOOKUP{RS}\n{C}{'=' * 70}{RS}")
        for cve in all_cves:
            ex = find_exploits_for_cve(cve, runner, verbose=args.verbose)
            if ex:
                exploit_map[cve] = ex
                if not any(v.get("cve_id") == cve for v in vulns):
                    vulns.append({
                        "type": "cve_direct", "name": cve,
                        "cve_id": cve, "severity": "unknown",
                        "url": info.get("url"),
                    })

    # ---- Phase 3: Exploitation ----
    exploitation_results = []
    if not args.no_exploit and vulns:
        exploitation_results = attempt_exploitation(
            vulns, info, runner,
            verbose=args.verbose, dry_run=args.dry_run,
        )
    elif args.no_exploit:
        print(f"\n{Y}[*] --no-exploit: skipping{RS}")

    # ---- Phase 4: Report ----
    report_file = generate_report(
        args.target, info, recon, vulns,
        exploit_map, cve_intel_map,
        exploitation_results, runner.history,
    )

    # ---- Summary ----
    wins = sum(1 for r in exploitation_results if r.get("success"))
    eiw = sum(1 for v in cve_intel_map.values()
              if v.get("merged", {}).get("exploited_in_wild"))
    print(f"\n{G}{B}{'=' * 70}{RS}")
    print(f"{G}{B}  BLACKBUG v{BRAND['version']} — COMPLETE{RS}")
    print(f"{G}{B}{'=' * 70}{RS}")
    print(f"  Target:                 {args.target}")
    print(f"  Vulnerabilities:        {len(vulns)}")
    print(f"  CVEs enriched:          {len(cve_intel_map)}")
    print(f"  CVEs exploited in wild: {eiw}")
    print(f"  Exploits found:         {sum(len(e) for e in exploit_map.values())}")
    print(f"  Exploitation wins:      {wins}")
    print(f"  Report:                 {report_file}")
    print(f"  Log:                    {log_file}")
    print(f"{G}{B}{'=' * 70}{RS}")
    print(f"  {C}MRGcodex{RS}")
    print(f"{G}{B}{'=' * 70}{RS}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted{RS}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{R}[!] Fatal: {e}{RS}")
        if "-v" in sys.argv or "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

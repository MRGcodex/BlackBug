"""Verify all modules import correctly."""


def test_imports():
    from modules.target_parser import parse_target, detect_waf
    from modules.command_runner import CommandRunner
    from modules.tool_manager import detect_tools
    from modules.recon import run_recon
    from modules.web_scanner import run_nuclei, run_sqlmap
    from modules.vuln_detector import detect_vulnerabilities
    from modules.cve_intel import get_cve_intel
    from modules.exploit_finder import find_exploits_for_cve
    from modules.exploit_engine import attempt_exploitation
    from modules.reporter import generate_report, BRAND

    assert BRAND["author"] == "MRGcodex"
    assert BRAND["tool"] == "BlackBug"
    assert BRAND["version"] == "2.3.0"

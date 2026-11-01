"""Tool detection + install hints."""
import shutil
import subprocess
import sys

REQUIRED_BINARIES = {
    "nmap": "Network scanner (required for recon)",
    "sqlmap": "SQL injection (optional)",
    "nuclei": "Vuln scanner (optional)",
    "msfconsole": "Metasploit (optional)",
    "searchsploit": "ExploitDB CLI (optional)",
    "whois": "Domain whois (optional)",
}

INSTALL_HINTS = {
    "nmap": "sudo apt install nmap  |  brew install nmap",
    "sqlmap": "git clone https://github.com/sqlmapproject/sqlmap.git",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "msfconsole": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod +x msfinstall && sudo ./msfinstall",
    "searchsploit": "git clone https://gitlab.com/exploit-database/exploitdb.git",
    "whois": "sudo apt install whois",
}


def check_tool(name):
    return shutil.which(name) is not None


def detect_tools():
    return {tool: check_tool(tool) for tool in REQUIRED_BINARIES}


def print_tool_status(status):
    print("\n[MRGcodex] Tools:")
    for tool, available in status.items():
        icon = "✅" if available else "❌"
        print(f"  {icon} {tool:15} — {REQUIRED_BINARIES[tool]}")


def install_python_deps():
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        )
        print("[MRGcodex] Python deps installed.")
        return True
    except Exception as e:
        print(f"[!] pip install failed: {e}")
        return False


def suggest_install(tool):
    hint = INSTALL_HINTS.get(tool, "See official docs")
    print(f"  ➜ {tool}: {hint}")


def check_python_imports():
    """Verify all modules import correctly."""
    print("\n[MRGcodex] Checking Python imports...")
    modules = [
        "modules.target_parser", "modules.command_runner",
        "modules.tool_manager", "modules.recon",
        "modules.web_scanner", "modules.vuln_detector",
        "modules.cve_intel", "modules.exploit_finder",
        "modules.exploit_engine", "modules.reporter",
    ]
    failed = []
    for mod in modules:
        try:
            __import__(mod)
            print(f"  ✅ {mod}")
        except Exception as e:
            print(f"  ❌ {mod}: {e}")
            failed.append(mod)
    return len(failed) == 0

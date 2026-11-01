# BlackBug

Automated bug finding & exploitation framework
**MRGcodex**

---

## Educational Disclaimer

**For EDUCATIONAL and AUTHORIZED security testing only.**
Unauthorized use is **ILLEGAL**. You are solely responsible.

---

## Features

- Auto target detection: IP / domain / URL / CIDR
- Nmap recon with live command output
- Nuclei CVE scanning + SQLMap automation
- **Multi-source CVE intel (no API keys):**
  - NVD, CISA KEV, EPSS, GitHub Advisories, CIRCL
- Auto exploit lookup: ExploitDB + Metasploit
- Auto exploitation: MSF modules + ExploitDB scripts
- SQL injection database enumeration
- Branded JSON reports
- Docker ready

---

## Installation

```bash
git clone https://github.com/MRGcodex/BlackBug.git
cd BlackBug
pip install -r requirements.txt
```

Or use `python blackbug.py --install`.

### Optional tools

| Tool | Install |
|------|---------|
| nmap | `sudo apt install nmap` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| sqlmap | `git clone https://github.com/sqlmapproject/sqlmap.git` |
| msfconsole | `curl -fsSL https://apt.metasploit.com/ \| sudo bash` |

---

## Usage

```bash
# Verify all imports
python blackbug.py --check

# Install Python deps
python blackbug.py --install

# Update nuclei templates + metasploit + ExploitDB + KEV cache
python blackbug.py --update

# Full auto scan (recon → vulns → CVE intel → exploit → report)
python blackbug.py -t example.com

# Website target
python blackbug.py -t https://example.com

# Dry run
python blackbug.py -t example.com --dry-run

# Detection only
python blackbug.py -t example.com --no-exploit

# Web-only, skip CVE enrichment
python blackbug.py -t https://example.com --web-only --no-cve-intel

# Extra CVE
python blackbug.py -t example.com -c CVE-2021-44228
```

---

## Output

- `reports/MRGcodex_<target>_<timestamp>.json`
- `reports/MRGcodex_log_<timestamp>.txt`

---

## Docker

```bash
docker build -t blackbug .
docker run --rm -v $(pwd)/reports:/app/reports \
    blackbug -t example.com --no-consent
```

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## Author

**MRGcodex**
https://github.com/MRGcodex

---

## License

MIT with Ethical Use Clause — see [LICENSE](LICENSE).

**© 2026 MRGcodex**

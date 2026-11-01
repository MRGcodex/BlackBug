"""Nuclei + SQLMap with live output."""
import json
import os
import tempfile


def run_nuclei(target_url, runner, timeout=600):
    print(f"\n[MRGcodex] Nuclei on {target_url}")
    json_path = None

    try:
        fd, json_path = tempfile.mkstemp(suffix=".jsonl", prefix="bb_nuclei_")
        os.close(fd)

        template_dir = os.path.expanduser("~/nuclei-templates")
        cmd = [
            "nuclei", "-u", target_url, "-jsonl", "-o", json_path,
            "-severity", "critical,high,medium",
            "-nc", "-stats", "-stats-interval", "30",
        ]
        if os.path.isdir(template_dir):
            cmd.extend(["-t", template_dir])

        result = runner.run(cmd, timeout=timeout, label="nuclei")

        findings = []
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        print(f"[MRGcodex] Nuclei: {len(findings)} finding(s)")
        return {
            "status": "success" if (result["success"] or findings) else "error",
            "findings": findings,
        }
    except FileNotFoundError:
        return {"status": "error", "message": "nuclei not installed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if json_path and os.path.exists(json_path):
            try:
                os.unlink(json_path)
            except Exception:
                pass


def run_sqlmap(target_url, runner, timeout=300):
    print(f"\n[MRGcodex] SQLMap on {target_url}")
    os.makedirs("./reports/sqlmap", exist_ok=True)

    cmd = [
        "sqlmap", "-u", target_url, "--batch",
        "--level=1", "--risk=1",
        "--output-dir=./reports/sqlmap",
        "--timeout=10", "--retries=1",
    ]

    try:
        result = runner.run(cmd, timeout=timeout, label="sqlmap")
    except FileNotFoundError:
        return {"status": "error", "message": "sqlmap not installed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

    output = result.get("output", "").lower()
    injectable = "identified the following injection point" in output

    if injectable:
        print(f"[MRGcodex] ✓ SQL INJECTION on {target_url}")

    return {
        "status": "success" if result["success"] else "error",
        "injectable": injectable,
        "output_excerpt": result.get("output", "")[-2000:],
    }

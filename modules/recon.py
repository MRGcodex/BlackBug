"""Nmap recon with live output + XML parse."""
import os
import tempfile
import xml.etree.ElementTree as ET


def run_recon(target, runner, timeout=900):
    print(f"\n[MRGcodex] Phase 1: Recon — {target}")
    xml_path = None

    try:
        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="bb_nmap_")
        os.close(fd)

        cmd = ["nmap", "-sV", "--top-ports", "1000", "-T4",
               "-oX", xml_path, target]
        result = runner.run(cmd, timeout=timeout, label="nmap")

        if result["exit_code"] not in (0, 1):
            return {"status": "error",
                    "message": f"nmap exit {result['exit_code']}"}

        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as e:
            return {"status": "error", "message": f"XML parse: {e}"}

        root = tree.getroot()
        results = []

        for host in root.findall("host"):
            status_el = host.find("status")
            if status_el is not None and status_el.get("state") != "up":
                continue
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "unknown")

            for port_el in host.findall("ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                port_num = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                service = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                version = svc_el.get("version", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""

                results.append({
                    "host": ip, "port": port_num, "protocol": proto,
                    "service": service, "version": version, "product": product,
                })

        print(f"\n[MRGcodex] Found {len(results)} open port(s)")
        return {"status": "success", "results": results}

    except FileNotFoundError:
        return {"status": "error", "message": "nmap not installed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if xml_path and os.path.exists(xml_path):
            try:
                os.unlink(xml_path)
            except Exception:
                pass

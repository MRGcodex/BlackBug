"""Live command executor with streaming output."""
import subprocess
from datetime import datetime

try:
    from colorama import Fore, Style
    CMD = Fore.YELLOW
    ERR = Fore.RED
    OK = Fore.GREEN
    RS = Style.RESET_ALL
except ImportError:
    CMD = ERR = OK = RS = ""


class CommandRunner:
    def __init__(self, log_file=None, verbose=True):
        self.log_file = log_file
        self.verbose = verbose
        self.history = []

    def _log(self, msg):
        self.history.append(msg)
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass

    def run(self, cmd, timeout=None, show_output=True, label=None, cwd=None):
        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)
        label_str = f"[{label}] " if label else ""

        print(f"\n{CMD}{'─' * 70}{RS}")
        print(f"{CMD}{label_str}$ {cmd_str}{RS}")
        print(f"{CMD}{'─' * 70}{RS}")
        self._log(f"\n=== {datetime.now().isoformat()} ===")
        self._log(f"{label_str}$ {cmd_str}")

        output_lines = []
        process = None

        try:
            process = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=cwd,
            )
            for line in iter(process.stdout.readline, ""):
                line = line.rstrip()
                if not line:
                    continue
                output_lines.append(line)
                if show_output and self.verbose:
                    print(f"  {line}")
                self._log(f"  {line}")
            process.wait(timeout=timeout)
            exit_code = process.returncode
            if exit_code == 0:
                print(f"{OK}✓ exit 0{RS}")
            else:
                print(f"{ERR}✗ exit {exit_code}{RS}")
            self._log(f"[exit={exit_code}]")
            return {
                "command": cmd_str, "exit_code": exit_code,
                "output": "\n".join(output_lines),
                "success": exit_code == 0,
            }
        except subprocess.TimeoutExpired:
            if process:
                try:
                    process.kill()
                except Exception:
                    pass
            print(f"{ERR}✗ TIMEOUT after {timeout}s{RS}")
            return {
                "command": cmd_str, "exit_code": -1,
                "output": "\n".join(output_lines) + f"\n[TIMEOUT {timeout}s]",
                "success": False,
            }
        except FileNotFoundError:
            print(f"{ERR}✗ Command not found: {cmd_list[0]}{RS}")
            return {
                "command": cmd_str, "exit_code": -2,
                "output": f"Command not found: {cmd_list[0]}",
                "success": False,
            }
        except Exception as e:
            print(f"{ERR}✗ Error: {e}{RS}")
            return {
                "command": cmd_str, "exit_code": -3,
                "output": str(e), "success": False,
            }

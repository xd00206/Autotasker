# cve_manager.py
import subprocess
import threading
import time
import re
import logging
from pathlib import Path

class CVEManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.process = None
        self.scan_thread = None
        self.scan_path = None
        self.scanned_files = set()
        self.failures = 0
        self.cves_found = []
        self.elapsed = 0
        self.log_lines = []
        self.is_scanning = False
        self.callbacks = {
            "on_update": None,
            "on_finish": None
        }

    def _log(self, msg):
        logging.debug(msg)
        self.log_lines.append(msg)
        if self.callbacks["on_update"]:
            self.callbacks["on_update"](msg)

    def set_callback(self, name, func):
        if name in self.callbacks:
            self.callbacks[name] = func

    def start_scan(self, folder):
        if self.is_scanning:
            self._log("⚠️ Scan already in progress.")
            return

        self.stop_event.clear()
        self.process = None
        self.scan_path = folder
        self.scanned_files.clear()
        self.failures = 0
        self.cves_found.clear()
        self.elapsed = 0
        self.is_scanning = True
        self.log_lines.clear()

        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()

    def _run_scan(self):
        try:
            command = [
                "cve-bin-tool",
                self.scan_path,
                "--format", "html",
                "--output-file", "cve_report.html"
            ]
            self._log(f"🚀 Starting CVE scan:\n{' '.join(command)}")
            start_time = time.time()
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            buffer = ""
            valid_exts = (".dll", ".exe", ".sys", ".ocx", ".bin", ".so", ".py", ".sh", ".pl", ".jar", ".class")

            for line in self.process.stdout:
                if self.stop_event.is_set():
                    self._log("🛑 Scan manually stopped.")
                    self.process.kill()
                    break

                line = line.strip()
                if not line:
                    continue
                self._log("[OUT] " + line)

                # Smarter multiline file path detection
                if any(line.lower().endswith(ext) for ext in valid_exts):
                    full_path = buffer + "\\" + line if buffer else line
                    full_path = full_path.replace("\\\\", "\\").strip()
                    self.scanned_files.add(full_path)
                    buffer = ""
                elif re.match(r'^[\w\s\\:/().-]+$', line):
                    buffer = line
                else:
                    buffer = ""

                if "CVE-" in line:
                    matches = re.findall(r"CVE-\d{4}-\d{4,7}", line)
                    self.cves_found.extend([m for m in matches if m not in self.cves_found])

                if "Failure extracting" in line or "WARNING" in line:
                    self.failures += 1

            for line in self.process.stderr:
                self._log("[ERR] " + line.strip())

            self.process.wait()
            self.elapsed = round(time.time() - start_time, 2)
            self.is_scanning = False

            if self.callbacks["on_finish"]:
                self.callbacks["on_finish"]()

        except Exception as e:
            self._log(f"[EXCEPTION] {e}")
            self.is_scanning = False

    def stop_scan(self):
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.kill()
        self.is_scanning = False

    def get_status_summary(self):
        return {
            "files": len(self.scanned_files),
            "failures": self.failures,
            "cves": len(self.cves_found),
            "elapsed": self.elapsed,
            "is_scanning": self.is_scanning
        }

    def get_cves(self):
        return self.cves_found

    def get_log(self):
        return self.log_lines

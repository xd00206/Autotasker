import customtkinter as ctk
import subprocess
import threading
import logging
import webbrowser
from pathlib import Path
from tkinter import messagebox, filedialog
import os
import time
import re

# Ensure logs folder exists
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# Setup logging to file
logging.basicConfig(
    filename=log_dir / "debug.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def load_view(main_frame, update_status):
    for widget in main_frame.winfo_children():
        widget.destroy()

    ctk.CTkLabel(main_frame, text="🔍 CVE Report Scanner", font=("Consolas", 18)).pack(pady=(20, 10))

    result_box = ctk.CTkTextbox(main_frame, height=200, wrap="word")
    result_box.pack(padx=10, pady=5, fill="both")
    result_box.insert("end", "Press 'Run CVE Scan' to begin.\n")
    result_box.configure(state="disabled")

    summary_frame = ctk.CTkFrame(main_frame)
    summary_frame.pack(padx=10, pady=(0, 10), fill="x")

    scanned_var = ctk.StringVar(value="🗂 Files Scanned: 0")
    failures_var = ctk.StringVar(value="⚠️ Failures/Warnings: 0")
    cves_var = ctk.StringVar(value="☠️ CVEs Detected: 0")

    ctk.CTkLabel(summary_frame, textvariable=scanned_var, anchor="w").pack(fill="x")
    ctk.CTkLabel(summary_frame, textvariable=failures_var, anchor="w").pack(fill="x")
    ctk.CTkLabel(summary_frame, textvariable=cves_var, anchor="w").pack(fill="x")

    debug_console = ctk.CTkTextbox(main_frame, height=100, wrap="word")
    debug_console.pack(padx=10, pady=(0, 10), fill="both")
    debug_console.insert("end", "📜 Debug log will appear here...\n")
    debug_console.configure(state="disabled")

    cve_result_box = ctk.CTkTextbox(main_frame, height=120, wrap="word")
    cve_result_box.pack(padx=10, pady=(0, 10), fill="both")
    cve_result_box.insert("end", "🧠 CVEs found will appear here...\n")
    cve_result_box.configure(state="disabled")

    def cve_context_menu(event):
        try:
            selected = cve_result_box.get("sel.first", "sel.last")
            if selected.startswith("CVE-"):
                webbrowser.open_new_tab(f"https://www.google.com/search?q={selected}")
        except:
            pass

    cve_result_box.bind("<Button-3>", cve_context_menu)

    open_button = ctk.CTkButton(main_frame, text="📂 Open CVE Report", command=lambda: open_report(), state="disabled")
    open_button.pack(pady=5)

    def log_debug(msg):
        logging.debug(msg)
        debug_console.configure(state="normal")
        debug_console.insert("end", msg + "\n")
        debug_console.see("end")
        debug_console.configure(state="disabled")

    def open_report():
        report_path = Path("cve_report.html").resolve()
        if report_path.exists():
            webbrowser.open_new_tab(report_path.as_uri())
        else:
            messagebox.showerror("Report Missing", "CVE report not found!")

    def run_scan():
        result_box.configure(state="normal")
        result_box.delete("1.0", "end")
        result_box.insert("end", "🚀 Starting CVE scan...\n")
        result_box.configure(state="disabled")

        debug_console.configure(state="normal")
        debug_console.delete("1.0", "end")
        debug_console.insert("end", "📜 Debug log will appear here...\n")
        debug_console.configure(state="disabled")

        cve_result_box.configure(state="normal")
        cve_result_box.delete("1.0", "end")
        cve_result_box.insert("end", "🧠 CVEs found will appear here...\n")
        cve_result_box.configure(state="disabled")

        update_status("🚀 Running CVE scan...")
        stop_requested = threading.Event()

        stop_button = ctk.CTkButton(main_frame, text="🛑 Stop Scan", command=stop_requested.set)
        stop_button.pack(pady=5)

        def background_scan():
            try:
                scan_path = filedialog.askdirectory(title="Select folder to scan for vulnerabilities")
                if not scan_path:
                    update_status("⚠️ CVE scan canceled by user.")
                    log_debug("User canceled directory selection")
                    stop_button.configure(state="disabled")
                    return

                command = [
                    "cve-bin-tool",
                    scan_path,
                    "--format", "html",
                    "--output-file", "cve_report.html"
                ]

                log_debug(f"Running command: {' '.join(command)}")
                start_time = time.time()
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                result_box.configure(state="normal")
                result_box.insert("end", f"✔️ Command executed:\n{' '.join(command)}\n\n")
                result_box.see("end")

                debug_console.configure(state="normal")

                scanned_files = set()
                failures = 0
                cves_found = 0
                cve_lines = []

                path_accumulator = ""
                valid_exts = (".dll", ".exe", ".sys", ".ocx", ".bin", ".so", ".py", ".sh", ".pl", ".jar", ".class")

                for line in process.stdout:
                    if stop_requested.is_set():
                        result_box.insert("end", "\n🛑 Scan stopped by user.\n")
                        update_status("🛑 Scan stopped.")
                        stop_button.configure(state="disabled")
                        return

                    line = line.strip()
                    if not line:
                        continue

                    result_box.insert("end", line + "\n")
                    debug_console.insert("end", "[STDOUT] " + line + "\n")
                    result_box.see("end")
                    debug_console.see("end")
                    logging.debug("[STDOUT] " + line)

                    # Smarter file detection (multi-line)
                    if any(line.lower().endswith(ext) for ext in valid_exts):
                        full_path = path_accumulator + "\\" + line if path_accumulator else line
                        full_path = full_path.replace("\\\\", "\\").strip()
                        if full_path not in scanned_files:
                            scanned_files.add(full_path)
                            scanned_var.set(f"🗂 Files Scanned: {len(scanned_files)}")
                        path_accumulator = ""
                    elif re.match(r'^[\w\s\\:/().-]+$', line):
                        path_accumulator = line
                    else:
                        path_accumulator = ""

                    # Extract CVEs
                    if "CVE-" in line:
                        matches = re.findall(r"CVE-\d{4}-\d{4,7}", line)
                        for match in matches:
                            if match not in cve_lines:
                                cve_lines.append(match)
                                cves_found += 1
                                cves_var.set(f"☠️ CVEs Detected: {cves_found}")
                                cve_result_box.configure(state="normal")
                                cve_result_box.insert("end", f"{match}\n")
                                cve_result_box.configure(state="disabled")

                    if "Failure extracting" in line:
                        failures += 1
                        failures_var.set(f"⚠️ Failures/Warnings: {failures}")

                for line in process.stderr:
                    line = line.strip()
                    if not line:
                        continue
                    result_box.insert("end", "❗ " + line + "\n")
                    debug_console.insert("end", "[STDERR] " + line + "\n")
                    result_box.see("end")
                    debug_console.see("end")
                    logging.debug("[STDERR] " + line)

                debug_console.configure(state="disabled")
                result_box.configure(state="disabled")

                process.wait()
                elapsed = round(time.time() - start_time, 2)
                report_path = Path("cve_report.html").resolve()
                report_exists = report_path.exists()

                if process.returncode != 0 and not report_exists:
                    log_debug("CVE scan failed with non-zero return code and no report generated")
                    result_box.configure(state="normal")
                    result_box.insert("end", "❌ CVE scan failed. See debug log for details.\n")
                    result_box.configure(state="disabled")
                    update_status("❌ CVE scan failed.")
                    stop_button.configure(state="disabled")
                    return

                result_box.configure(state="normal")
                result_box.insert("end", f"\n📊 Scan Summary:\n")
                result_box.insert("end", f"• Files Scanned: {len(scanned_files)}\n")
                result_box.insert("end", f"• Failures/Warnings: {failures}\n")
                result_box.insert("end", f"• CVEs Detected: {cves_found}\n")
                result_box.insert("end", f"✅ Report saved to cve_report.html ({elapsed}s)\n")
                result_box.configure(state="disabled")

                open_button.configure(state="normal")
                update_status("✅ CVE scan complete. Summary shown below.")
                stop_button.configure(state="disabled")

            except Exception as e:
                log_debug(f"[ERROR] Exception occurred: {e}")
                result_box.configure(state="normal")
                result_box.insert("end", f"❌ Error: {e}\n")
                result_box.see("end")
                result_box.configure(state="disabled")
                update_status(f"❌ CVE scan failed: {e}")
                messagebox.showerror("Scan Failed", str(e))
                stop_button.configure(state="disabled")

        threading.Thread(target=background_scan, daemon=True).start()

    ctk.CTkButton(main_frame, text="🛡️ Run CVE Scan", command=run_scan).pack(pady=5, padx=10)

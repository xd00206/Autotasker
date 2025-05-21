import customtkinter as ctk
import subprocess
import threading
import logging
import webbrowser
from pathlib import Path
from tkinter import messagebox, filedialog
import os

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
    """Load the CVE scan interface into the given frame."""
    for widget in main_frame.winfo_children():
        widget.destroy()

    ctk.CTkLabel(main_frame, text="🔍 CVE Report Scanner", font=("Consolas", 18)).pack(pady=(20, 10))

    result_box = ctk.CTkTextbox(main_frame, height=200, wrap="word")
    result_box.pack(padx=10, pady=5, fill="both")
    result_box.insert("end", "Press 'Run CVE Scan' to begin.\n")
    result_box.configure(state="disabled")

    debug_console = ctk.CTkTextbox(main_frame, height=150, wrap="word")
    debug_console.pack(padx=10, pady=(0, 10), fill="both")
    debug_console.insert("end", "📜 Debug log will appear here...\n")
    debug_console.configure(state="disabled")

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

        update_status("🚀 Running CVE scan...")

        def background_scan():
            try:
                log_debug("CVE scan thread started")

                scan_path = filedialog.askdirectory(title="Select folder to scan for vulnerabilities")
                if not scan_path:
                    update_status("⚠️ CVE scan canceled by user.")
                    log_debug("User canceled directory selection")
                    return

                command = [
                    "cve-bin-tool",
                    scan_path,
                    "--format", "html",
                    "--output-file", "cve_report.html"
                ]

                log_debug(f"Running command: {' '.join(command)}")

                result = subprocess.run(command, capture_output=True, text=True)
                output = result.stdout.strip() if result.stdout else result.stderr.strip()

                log_debug(f"Command return code: {result.returncode}")
                log_debug(f"Command output:\n{output}")

                result_box.configure(state="normal")
                result_box.insert("end", f"✔️ Command executed:\n{' '.join(command)}\n\n")
                result_box.insert("end", output + "\n")
                result_box.see("end")

                if result.returncode != 0:
                    result_box.insert("end", "❌ CVE scan failed. See debug log for details.\n")
                    result_box.configure(state="disabled")
                    update_status("❌ CVE scan failed.")
                    return

                result_box.insert("end", "✅ Report saved to cve_report.html\n")
                result_box.configure(state="disabled")

                open_button.configure(state="normal")
                update_status("✅ CVE scan complete. Report saved to cve_report.html")

            except Exception as e:
                log_debug(f"[ERROR] Exception occurred: {e}")
                result_box.configure(state="normal")
                result_box.insert("end", f"❌ Error: {e}\n")
                result_box.see("end")
                result_box.configure(state="disabled")
                update_status(f"❌ CVE scan failed: {e}")
                messagebox.showerror("Scan Failed", str(e))

        threading.Thread(target=background_scan, daemon=True).start()

    ctk.CTkButton(main_frame, text="🛡️ Run CVE Scan", command=run_scan).pack(pady=5, padx=10)

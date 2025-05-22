import customtkinter as ctk
from tkinter import messagebox, filedialog
from pathlib import Path
import webbrowser


def load_view(main_frame, update_status, cve_manager):
    for widget in main_frame.winfo_children():
        widget.destroy()

    # GUI components
    ctk.CTkLabel(main_frame, text="\ud83d\udd0d CVE Report Scanner", font=("Consolas", 18)).pack(pady=(20, 10))

    result_box = ctk.CTkTextbox(main_frame, height=200, wrap="word")
    result_box.pack(padx=10, pady=5, fill="both")
    result_box.insert("end", "Press 'Run CVE Scan' to begin.\n")
    result_box.configure(state="disabled")

    summary_label = ctk.CTkLabel(main_frame, text="📊 Scan Summary:", anchor="w")
    summary_label.pack(padx=10, anchor="w")

    summary_text = ctk.CTkLabel(main_frame, text="(none yet)", anchor="w", justify="left")
    summary_text.pack(padx=10, anchor="w")

    cve_result_box = ctk.CTkTextbox(main_frame, height=100, wrap="word")
    cve_result_box.pack(padx=10, pady=(10, 0), fill="both")
    cve_result_box.insert("end", "\ud83e\udde0 CVEs found will appear here...\n")
    cve_result_box.configure(state="disabled")

    def on_cve_right_click(event):
        try:
            selected = cve_result_box.get("sel.first", "sel.last")
            if selected.startswith("CVE-"):
                webbrowser.open_new_tab(f"https://www.google.com/search?q={selected}")
        except:
            pass

    cve_result_box.bind("<Button-3>", on_cve_right_click)

    open_button = ctk.CTkButton(main_frame, text="📂 Open CVE Report", command=lambda: open_report(), state="disabled")
    open_button.pack(pady=5)

    def open_report():
        report_path = Path("cve_report.html").resolve()
        if report_path.exists():
            webbrowser.open_new_tab(report_path.as_uri())
        else:
            messagebox.showerror("Report Missing", "CVE report not found!")

    def update_summary():
        stats = cve_manager.get_status_summary()
        summary = f"• Files Scanned: {stats['files']}\n"
        summary += f"• Failures/Warnings: {stats['failures']}\n"
        summary += f"• CVEs Detected: {stats['cves']}\n"
        summary += f"• Elapsed: {stats['elapsed']}s"
        summary_text.configure(text=summary)

        if stats['cves'] > 0:
            cve_result_box.configure(state="normal")
            cve_result_box.delete("1.0", "end")
            for cve in cve_manager.get_cves():
                cve_result_box.insert("end", cve + "\n")
            cve_result_box.configure(state="disabled")

    def on_scan_log(msg):
        result_box.configure(state="normal")
        result_box.insert("end", msg + "\n")
        result_box.see("end")
        result_box.configure(state="disabled")
        update_summary()

    def on_scan_finish():
        update_status("✅ CVE scan complete.")
        open_button.configure(state="normal")
        update_summary()

    def run_scan():
        folder = filedialog.askdirectory(title="Select folder to scan for vulnerabilities")
        if not folder:
            update_status("⚠️ CVE scan canceled.")
            return

        result_box.configure(state="normal")
        result_box.delete("1.0", "end")
        result_box.insert("end", f"🚀 Scanning: {folder}\n")
        result_box.configure(state="disabled")

        cve_result_box.configure(state="normal")
        cve_result_box.delete("1.0", "end")
        cve_result_box.insert("end", "\ud83e\udde0 CVEs found will appear here...\n")
        cve_result_box.configure(state="disabled")

        open_button.configure(state="disabled")
        update_status("🚀 Running CVE scan...")

        cve_manager.set_callback("on_update", on_scan_log)
        cve_manager.set_callback("on_finish", on_scan_finish)
        cve_manager.start_scan(folder)

    def stop_scan():
        cve_manager.stop_scan()
        update_status("🛑 Scan stopped.")

    ctk.CTkButton(main_frame, text="🛡️ Run CVE Scan", command=run_scan).pack(pady=5, padx=10)
    ctk.CTkButton(main_frame, text="🛑 Stop Scan", command=stop_scan).pack(pady=5, padx=10)

    update_summary()
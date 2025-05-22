import subprocess
import time
import urllib.request
import os
import sys
from pathlib import Path
import customtkinter as ctk
from tkinter import messagebox
import psutil
import platform
from datetime import datetime
from . import security_check
from . import cve_report
from .cve_manager import CVEManager

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

POWERSHELL_PATH = r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
JUNK_FILE_SIZE = 10737418240  # 10 GB
VERSION_FILE = "version.txt"
REMOTE_VERSION_URL = "https://raw.githubusercontent.com/xd00206/Autotasker/main/version.txt"
UPDATE_EXECUTABLE_URL = "https://github.com/xd00206/Autotasker/releases/download/1.2.0/Autotasker.exe"

class AutotaskerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cve_manager = CVEManager()
        self.title("🖥️ Autotasker")
        self.geometry("1100x750")

        # Status box setup
        self.status_var = ctk.StringVar(value="✅ Ready")
        
        self.developer_mode = ctk.BooleanVar(value=False)
        self.wipe_mode = ctk.StringVar(value="Standard Wipe (3 passes)")

        # Create main frame
        self.sidebar = ctk.CTkFrame(self, width=200)
        self.sidebar.pack(side="left", fill="y")

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(side="right", expand=True, fill="both")

        self.create_sidebar()  # Sidebar with buttons
        self.create_status_box()  # Create the status box at the top
        self.show_dashboard()  # Initial screen when app is started

    def create_sidebar(self):
        ctk.CTkLabel(self.sidebar, text="⚡ Autotasker", font=("Consolas", 18)).pack(pady=(20, 10))
        
        nav_buttons = [
            ("📊 Dashboard", self.show_dashboard),
            ("🏠 Home", self.show_home),
            ("📜 Logs", self.show_logs),
            ("⚙️ Settings", self.show_settings),
            ("🛡️ Security Check", lambda: security_check.load_view(self.main_frame, self.update_status_message)),
            ("🛡️ CVE Scanner", lambda: cve_report.load_view(self.main_frame, self.update_status_message, self.cve_manager))
        ]
       
        for label, command in nav_buttons:
            ctk.CTkButton(self.sidebar, text=label, command=command).pack(pady=5, padx=10, fill="x")

    def create_status_box(self):
            """ Create a status box at the top of the main frame """
            self.status_label = ctk.CTkLabel(self.main_frame, textvariable=self.status_var, anchor="w", wraplength=900, font=("Consolas", 14))
            self.status_label.pack(pady=10, padx=10, fill="x")  # Place it at the top of the screen

    def show_dashboard(self):
        self.clear_main_frame()

        stats = {
            "🧠 CPU Usage": f"{psutil.cpu_percent()}%",
            "💾 Memory Usage": f"{psutil.virtual_memory().percent}%",
            "🗄️ Disk Usage (C:)": f"{psutil.disk_usage('C:\\').percent}%",
            "⏳ Uptime": time.strftime('%H:%M:%S', time.gmtime(time.time() - psutil.boot_time())),
            "🖥️ OS": platform.platform(),
            "🔢 Version": self.get_local_version(),
            "📅 Last Update Check": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "⚙️ Background Processes": str(len(list(psutil.process_iter()))),
        }

        try:
            result = subprocess.run(
                [POWERSHELL_PATH, "-Command", "Get-WindowsUpdate -ErrorAction SilentlyContinue"],
                capture_output=True, text=True
            )
            stats["🪟 Windows Update"] = "⚠️ Pending" if result.stdout.strip() else "✅ Up-to-date"
        except Exception:
            stats["🪟 Windows Update"] = "❓ Unknown"

        for label, value in stats.items():
            row = ctk.CTkFrame(self.main_frame)
            row.pack(pady=5, padx=20, fill="x")
            ctk.CTkLabel(row, text=label + ":", anchor="w", width=220).pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="e").pack(side="right")

        ctk.CTkButton(self.main_frame, text="🔄 Refresh Dashboard", command=self.show_dashboard).pack(pady=20)

    def copy_to_clipboard(self, event):
        text = self.status_var.get()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()  # Keep the app responsive
        messagebox.showinfo("Copied", "Status copied to clipboard!")


    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def get_local_version(self):
        version_path = Path(VERSION_FILE)
        try:
            return version_path.read_text().strip() if version_path.exists() else "0.0.0"
        except Exception:
            self.status_var.set("❌ Failed to read local version")
            return "0.0.0"

    def fetch_remote_version(self):
        try:
            with urllib.request.urlopen(REMOTE_VERSION_URL, timeout=5) as response:
                return response.read().decode().strip()
        except Exception as e:
            return f"Error checking version: {e}"

    def check_for_updates(self):
        current = self.get_local_version()
        latest = self.fetch_remote_version()

        if latest.startswith("Error"):
            messagebox.showerror("Update Check Failed", latest)
        elif latest > current:
            if messagebox.askyesno("Update Available", f"New version {latest} available! (Current: {current})\nDownload and replace now?"):
                self.download_and_replace_exe()
        else:
            messagebox.showinfo("Up to Date", f"You are using the latest version: {current}")

    def download_and_replace_exe(self):
        try:
            self.status_var.set("📂 Downloading update...")
            exe_path = Path(sys.argv[0]).resolve()
            new_exe_path = exe_path.with_name("update_temp.exe")
            updater_path = exe_path.with_name("updater.py")
            launcher_path = exe_path.with_name("update_launcher.exe")
            version_path = exe_path.with_name("version.txt")

            # Download the new executable
            with urllib.request.urlopen(UPDATE_EXECUTABLE_URL) as response, open(new_exe_path, 'wb') as out_file:
                out_file.write(response.read())

            # Download updated version.txt from GitHub
            with urllib.request.urlopen(REMOTE_VERSION_URL) as response, open(version_path, 'wb') as out_file:
                out_file.write(response.read())

            # Download updater.py if it doesn't exist
            if not updater_path.exists():
                urllib.request.urlretrieve(
                    "https://raw.githubusercontent.com/xd00206/Autotasker/main/updater.py",
                    updater_path
                )

            # Check if update_launcher.exe exists
            if not launcher_path.exists():
                messagebox.showerror("Missing File", f"update_launcher.exe not found at:\n{launcher_path}")
                return

            # Launch the external update launcher
            subprocess.Popen(
                [str(launcher_path), str(exe_path), str(new_exe_path)],
                shell=True
            )

            self.after(1000, self.quit)  # Delay quit for safety

        except Exception as e:
            self.status_var.set("❌ Update failed")
            messagebox.showerror("Update Error", str(e))



    def show_home(self):
        self.clear_main_frame()

        ctk.CTkLabel(self.main_frame, text="▶️ Run Arbitrary PowerShell Command").pack(pady=(10, 0))
        entry = ctk.CTkEntry(self.main_frame, font=("Consolas", 14), placeholder_text="Type PowerShell command...")
        entry.pack(padx=10, pady=(5, 10), fill="x")
        entry.bind("<Return>", lambda e: self.run_command(entry.get(), entry, custom_label="Custom command"))

        ctk.CTkButton(self.main_frame, text="▶️ Run Command", command=lambda: self.run_command(entry.get(), entry, custom_label="Custom command")).pack(pady=(0, 15))

        self.output = ctk.CTkTextbox(self.main_frame, height=200, wrap="word")
        self.output.pack(padx=10, pady=(0, 20), fill="both")
        self.output.insert("end", "💬 Status messages will appear here...\n")
        self.output.configure(state="disabled")

        update_frame = ctk.CTkFrame(self.main_frame)
        update_frame.pack(padx=10, pady=10, fill="x")

        ctk.CTkLabel(update_frame, text="📦 Update All Apps (winget)", font=("Consolas", 13)).pack(anchor="w")
        ctk.CTkLabel(update_frame, text="Runs 'winget upgrade --all' to update installed apps.").pack(anchor="w")
        ctk.CTkButton(update_frame, text="📦 Run winget upgrade", command=self.update_all_apps).pack(anchor="w", pady=5)

        ctk.CTkLabel(update_frame, text="🪟 Windows Update", font=("Consolas", 13)).pack(anchor="w", pady=(15, 0))
        ctk.CTkLabel(update_frame, text="Installs Windows Updates using PSWindowsUpdate module.").pack(anchor="w")
        ctk.CTkButton(update_frame, text="🪟 Run Windows Update", command=self.run_windows_update).pack(anchor="w", pady=5)

        # Tweaks Frame
        tweaks_frame = ctk.CTkFrame(self.main_frame)
        tweaks_frame.pack(padx=10, pady=10, fill="x")

        # 🧹 Clean Temp Files
        ctk.CTkLabel(tweaks_frame, text="🧹 Clean Temp Files", font=("Consolas", 13)).pack(anchor="w", pady=(10, 0))
        ctk.CTkLabel(tweaks_frame, text="Deletes files from %TEMP% and C:\\Windows\\Temp folders.").pack(anchor="w")
        ctk.CTkButton(tweaks_frame, text="🧹 Run Temp Cleaner", command=self.tweak_clean_temp).pack(anchor="w", pady=5)

        # 🗑️ Empty Recycle Bin
        ctk.CTkLabel(tweaks_frame, text="🗑️ Empty Recycle Bin", font=("Consolas", 13)).pack(anchor="w", pady=(15, 0))
        ctk.CTkLabel(tweaks_frame, text="Permanently deletes all files from the Recycle Bin.").pack(anchor="w")
        ctk.CTkButton(tweaks_frame, text="🗑️ Empty Bin", command=self.tweak_empty_bin).pack(anchor="w", pady=5)

        # 🔐 Secure Wipe
        ctk.CTkLabel(tweaks_frame, text="🔐 Secure Wipe Free Space", font=("Consolas", 13)).pack(anchor="w", pady=(15, 0))
        ctk.CTkLabel(tweaks_frame, text="Overwrites free space with junk files to securely erase data.").pack(anchor="w")
        ctk.CTkButton(tweaks_frame, text="🔐 Run Secure Wipe", command=self.tweak_secure_wipe).pack(anchor="w", pady=5)


    def show_logs(self):
        self.clear_main_frame()
        self.debug_console = ctk.CTkTextbox(self.main_frame, height=500, wrap="word")
        self.debug_console.pack(expand=True, fill="both", padx=10, pady=10)
        self.debug_console.insert("end", "📜 Debug logs will appear here...\n")
        self.debug_console.configure(state="disabled")

    def show_settings(self):
        self.clear_main_frame()
        
        ctk.CTkLabel(self.main_frame, text="⚙️ Settings").pack(pady=(10, 5))
        
        ctk.CTkCheckBox(
            self.main_frame,
            text="Enable Developer Mode (show output/timing/errors)",
            variable=self.developer_mode
        ).pack(pady=10, padx=20, anchor="w")
        
        ctk.CTkLabel(self.main_frame, text=f"Version: {self.get_local_version()}").pack(pady=(20, 5))
        ctk.CTkButton(self.main_frame, text="Check for Updates", command=self.check_for_updates).pack(pady=5)
        
        # 🔐 Wipe Security Level Selector
        ctk.CTkLabel(self.main_frame, text="🛡️ Wipe Security Level").pack(pady=(30, 5))
        ctk.CTkOptionMenu(
            self.main_frame,
            variable=self.wipe_mode,
            values=["Quick Wipe (1 pass)", "Standard Wipe (3 passes)", "Military Grade (6 passes)"]
        ).pack(pady=5)

    def run_command(self, command, entry=None, custom_label=None):
        if not command.strip():
            self.status_var.set("⚠️ No command entered")
            return

        label = custom_label or "Command"
        start_time = time.time()

        try:
            result = subprocess.run(
                [POWERSHELL_PATH, "-Command", command],
                capture_output=True, text=True
            )
            duration = round(time.time() - start_time, 2)
            out, err = result.stdout.strip(), result.stderr.strip()

            if err:
                msg = f"❌ {label} failed: {err.splitlines()[-1]}"
                self.status_var.set(msg)
            else:
                msg = f"✅ {label} completed in {duration}s" if self.developer_mode.get() else f"✅ {label} completed"
                self.status_var.set(msg)

            if hasattr(self, 'output') and self.output.winfo_exists():
                self.output.configure(state="normal")
                self.output.insert("end", f"{msg}\n")
                self.output.configure(state="disabled")
                self.output.see("end")

            if self.developer_mode.get() and hasattr(self, 'debug_console') and self.debug_console.winfo_exists():
                self.debug_console.configure(state="normal")
                self.debug_console.insert("end", f"[{label}] Time: {duration}s\n[STDOUT]\n{out}\n[STDERR]\n{err}\n\n")
                self.debug_console.configure(state="disabled")
                self.debug_console.see("end")

        except Exception as e:
            error_msg = f"[EXCEPTION] {e}"
            self.status_var.set("❌ Exception occurred")

            if hasattr(self, 'debug_console') and self.debug_console.winfo_exists():
                self.debug_console.configure(state="normal")
                self.debug_console.insert("end", f"{error_msg}\n\n")
                self.debug_console.configure(state="disabled")

            if hasattr(self, 'output') and self.output.winfo_exists():
                self.output.configure(state="normal")
                self.output.insert("end", f"{error_msg}\n")
                self.output.configure(state="disabled")

        if entry:
            entry.delete(0, "end")

    def update_all_apps(self):
        self.run_command("winget upgrade --all", custom_label="Winget upgrade")

    def run_windows_update(self):
        self.run_command("Import-Module PSWindowsUpdate; Install-WindowsUpdate -AcceptAll", custom_label="Windows Update")
        if messagebox.askyesno("Reboot Confirmation", "Updates installed.\nDo you want to reboot now?"):
            self.run_command("Restart-Computer -Force", custom_label="System Reboot")

    def tweak_add_context_menu(self):
        self.run_command("""
        New-Item -Path "Registry::HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\Open PowerShell Here" -Force
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\Open PowerShell Here" -Name "Icon" -Value "powershell.exe" -PropertyType String -Force
        New-Item -Path "Registry::HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\Open PowerShell Here\\command" -Force
        Set-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\Open PowerShell Here\\command" -Name "(default)" -Value "powershell.exe"
        """, custom_label="Tweak: Add Context Menu")

    def tweak_empty_bin(self):
        try:
            if not messagebox.askyesno("Empty Recycle Bin", "This will permanently delete all files in the Recycle Bin. Proceed?"):
                return
            self.run_command("Clear-RecycleBin -Force", custom_label="Tweak: Empty Recycle Bin")
        except Exception as e:
            self.status_var.set(f"❌ Failed to empty Recycle Bin: {str(e)}")
            messagebox.showerror("Error", f"Failed to empty Recycle Bin: {str(e)}")

    def tweak_clean_temp(self):
        if not messagebox.askyesno("Clean Temp Files", "This will delete temporary files. Proceed?"):
            return
        self.run_command("""
        Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue
        """, custom_label="Tweak: Clean Temp Files")
        self.update_status_message("✅ Temp files cleaned successfully!")

    def update_status_message(self, message):
            self.status_var.set(message)

    def tweak_secure_wipe(self):
        level = self.wipe_mode.get()
        passes = {"Quick Wipe (1 pass)": 1, "Standard Wipe (3 passes)": 3, "Military Grade (6 passes)": 6}.get(level, 3)

        if not messagebox.askyesno("Confirm Secure Wipe", f"This will write/delete ~{passes*10}GB of junk. Proceed?"):
            return

        self.run_command(f"""
        for ($i = 1; $i -le {passes}; $i++) {{
            Write-Output "Pass $i of {passes} - Overwriting free space..."
            $junk = "$env:TEMP\\junkfile_$i.tmp"
            fsutil file createnew $junk {JUNK_FILE_SIZE}
            Remove-Item $junk -Force
        }}
        """, custom_label=f"Tweak: Secure Wipe ({level})")

if __name__ == "__main__":
    app = AutotaskerApp()
    app.mainloop()

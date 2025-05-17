import subprocess
import time
import urllib.request
from pathlib import Path
import customtkinter as ctk
from tkinter import messagebox

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

POWERSHELL_PATH = r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
JUNK_FILE_SIZE = 10737418240  # 10 GB
VERSION_FILE = "version.txt"
REMOTE_VERSION_URL = "https://yourdomain.com/latest_version.txt"  # Replace with your real URL

class PowerShellRunnerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🖥️ PowerShell Runner")
        self.geometry("1100x750")

        self.status_var = ctk.StringVar(value="✅ Ready")
        self.developer_mode = ctk.BooleanVar(value=False)

        self.sidebar = ctk.CTkFrame(self, width=200)
        self.sidebar.pack(side="left", fill="y")

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(side="right", expand=True, fill="both")

        self.create_sidebar()
        self.create_status_bar()
        self.show_home()

    def create_sidebar(self):
        ctk.CTkLabel(self.sidebar, text="⚡ PowerShell", font=("Consolas", 18)).pack(pady=(20, 10))
        nav_buttons = [
            ("🏠 Home", self.show_home),
            ("🧰 Tweaks", self.show_tweaks),
            ("📜 Logs", self.show_logs),
            ("⚙️ Settings", self.show_settings)
        ]
        for label, command in nav_buttons:
            ctk.CTkButton(self.sidebar, text=label, command=command).pack(pady=5, padx=10, fill="x")

    def create_status_bar(self):
        status_bar = ctk.CTkFrame(self, height=30)
        status_bar.pack(side="bottom", fill="x")
        self.status_label = ctk.CTkLabel(status_bar, textvariable=self.status_var, anchor="w")
        self.status_label.pack(side="left", padx=10)

    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def get_local_version(self):
        version_path = Path(VERSION_FILE)
        return version_path.read_text().strip() if version_path.exists() else "0.0.0"

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
            messagebox.showinfo("Update Available", f"New version {latest} available! (Current: {current})")
        else:
            messagebox.showinfo("Up to Date", f"You are using the latest version: {current}")

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

    def show_tweaks(self):
        self.clear_main_frame()
        tweaks = [
            ("📂 Add PowerShell to Context Menu", self.tweak_add_context_menu),
            ("🧹 Clean Temp Files", self.tweak_clean_temp),
            ("🗑️ Empty Recycle Bin", self.tweak_empty_bin),
            ("🔐 Secure Wipe Free Space", self.tweak_secure_wipe)
        ]
        for label, func in tweaks:
            ctk.CTkButton(self.main_frame, text=label, command=func).pack(pady=8, padx=20, fill="x")

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

    def tweak_clean_temp(self):
        self.run_command("""
        Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue
        """, custom_label="Tweak: Clean Temp Files")

    def tweak_empty_bin(self):
        self.run_command("""
        (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | ForEach-Object { $_.InvokeVerb("delete") }
        """, custom_label="Tweak: Empty Recycle Bin")

    def tweak_secure_wipe(self):
        if not messagebox.askyesno("Confirm Secure Wipe", "This will write/delete ~60GB of junk. Proceed?"):
            return
        self.run_command(f"""
        for ($i = 1; $i -le 6; $i++) {{
            Write-Output "Pass $i of 6 - Overwriting free space..."
            $junk = "$env:TEMP\\junkfile_$i.tmp"
            fsutil file createnew $junk {JUNK_FILE_SIZE}
            Remove-Item $junk -Force
        }}
        """, custom_label="Tweak: Secure Wipe")

if __name__ == "__main__":
    app = PowerShellRunnerApp()
    app.mainloop()

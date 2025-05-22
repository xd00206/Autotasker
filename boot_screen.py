import tkinter as tk
import customtkinter as ctk
import time
import threading
import random
import traceback
from .core import AutotaskerApp

messages = [
    "[SYS] Initializing environment variables...",
    "[CORE] Mounting system volumes...",
    "[SEC] Engaging protocol hardening...",
    "[MOD] Loading cryptographic modules...",
    "[NET] Establishing secure control channel...",
    "[AUDIT] Calibrating forensic modules...",
    "[MEM] Allocating sandbox partitions...",
    "[SCAN] Linking vulnerability database...",
    "[OSINT] Parsing CVE feeds...",
    "[AI] Deploying autonomous analysis agents...",
    "[AUTOTASKER] Boot integrity verified ✅",
    "[SYSTEM] Authentication not required. Proceeding..."
]

final_line = "> SYSTEM READY. LAUNCHING AUTOTASKER..."


def show_boot_screen():
    root = tk.Tk()
    root.title("System Initialization")
    root.geometry("800x600")
    root.configure(bg="black")
    root.overrideredirect(True)  # Hide title bar
    root.attributes("-topmost", True)

    text_widget = tk.Text(root, bg="black", fg="#00FF00", font=("Consolas", 14), border=0)
    text_widget.pack(expand=True, fill="both")
    text_widget.configure(state="disabled")

    def animate():
        text_widget.configure(state="normal")

        for msg in messages:
            text_widget.insert("end", msg + "\n")
            text_widget.see("end")
            text_widget.update()
            time.sleep(random.uniform(0.2, 0.5))

        time.sleep(0.5)
        text_widget.insert("end", final_line + "\n")
        text_widget.see("end")
        text_widget.update()
        time.sleep(1.5)

        text_widget.configure(state="disabled")
        root.destroy()

        try:
            print("\U0001f9e0 Launching Autotasker GUI...")
            app = AutotaskerApp()
            app.mainloop()
        except Exception as e:
            with open("autotasker_crashlog.txt", "w") as f:
                f.write("\u274c Failed to launch AutotaskerApp:\n")
                f.write(str(e) + "\n\n")
                f.write(traceback.format_exc())

    threading.Thread(target=animate, daemon=True).start()
    root.mainloop()

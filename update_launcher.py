import sys
import subprocess
import time
import os

def log(msg):
    with open("launcher_log.txt", "a") as f:
        f.write(msg + "\n")
    print(msg)

if len(sys.argv) != 3:
    log("Usage: update_launcher.exe <old_exe_path> <new_exe_path>")
    sys.exit(1)

old_exe = sys.argv[1]
new_exe = sys.argv[2]

log(f"[⏳] Waiting for {old_exe} to close...")
time.sleep(6)  # Gives OS time to release the EXE

log(f"[🚀] Launching updater.py with {old_exe} and {new_exe}")
try:
    subprocess.run([sys.executable, "updater.py", old_exe, new_exe], check=True)
except Exception as e:
    log(f"[❌] Failed to run updater.py: {e}")
    sys.exit(1)

log("[✅] Update launcher finished.")

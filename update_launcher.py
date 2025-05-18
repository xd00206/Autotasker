import sys
import subprocess
import time
import os
import shutil

LOG_FILE = "launcher_log.txt"

def log(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)

def find_python_interpreter():
    # Preferred: py.exe
    py_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "py.exe")
    if os.path.exists(py_path):
        return py_path

    # Fallback: python or python3 in PATH
    python_exe = shutil.which("python") or shutil.which("python3")
    if python_exe:
        return python_exe

    raise FileNotFoundError("❌ Could not find a Python interpreter to run updater.py")

def main():
    if len(sys.argv) != 3:
        log("Usage: update_launcher.exe <old_exe_path> <new_exe_path>")
        sys.exit(1)

    old_exe = sys.argv[1]
    new_exe = sys.argv[2]

    log(f"[⏳] Waiting for {old_exe} to close...")
    time.sleep(6)  # Give OS time to release file locks

    try:
        python_interpreter = find_python_interpreter()
        log(f"[🚀] Running updater with: {python_interpreter} updater.py {old_exe} {new_exe}")
        subprocess.run([python_interpreter, "updater.py", old_exe, new_exe], check=True)
        log("[✅] Update process completed.")
    except Exception as e:
        log(f"[❌] Failed to run updater.py: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

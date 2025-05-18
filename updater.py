import os
import sys
import time
import shutil
import subprocess

LOG_FILE = "update_error.log"

def log(message):
    print(message)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{message}\n")

def wait_for_process_to_close(target_exe):
    log(f"[⏳] Waiting for {target_exe} to close...")
    while True:
        tasks = subprocess.check_output("tasklist", shell=True).decode(errors="ignore")
        if os.path.basename(target_exe).lower() not in tasks.lower():
            break
        time.sleep(1)
    log("[✅] Target application closed.")

def ensure_temp_folder_is_cleared():
    log("[⌛] Waiting for PyInstaller temp folder cleanup...")
    time.sleep(5)

def replace_and_restart(old_exe, new_exe):
    log(f"[🛠️] Replacing {old_exe} with {new_exe}")
    try:
        shutil.move(new_exe, old_exe)
        log("[✅] Replacement successful.")
    except Exception as e:
        log(f"[❌] Replacement failed: {e}")
        raise

    log("[🚀] Relaunching updated application...")
    subprocess.Popen([old_exe], shell=True)

def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: updater.py <old_exe_path> <new_exe_path>")

        old_exe_path = sys.argv[1]
        new_exe_path = sys.argv[2]

        wait_for_process_to_close(old_exe_path)
        ensure_temp_folder_is_cleared()
        replace_and_restart(old_exe_path, new_exe_path)

    except Exception as e:
        log(f"[❌] Exception: {e}")
        input("❌ An error occurred. Press Enter to close.")

if __name__ == "__main__":
    main()

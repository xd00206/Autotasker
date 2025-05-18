import os
import sys
import time
import shutil
import subprocess

def wait_for_process_to_close(target_exe):
    print(f"[⏳] Waiting for {target_exe} to close...")
    while True:
        tasks = subprocess.check_output("tasklist", shell=True).decode()
        if os.path.basename(target_exe).lower() not in tasks.lower():
            break
        time.sleep(1)
    print("[✅] Target application closed.")

def replace_and_restart(old_exe, new_exe):
    print(f"[🛠️] Replacing {old_exe} with {new_exe}")
    shutil.move(new_exe, old_exe)
    print("[🚀] Relaunching updated application...")
    subprocess.Popen([old_exe], shell=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python updater.py <old_exe_path> <new_exe_path>")
        sys.exit(1)

    old_exe_path = sys.argv[1]
    new_exe_path = sys.argv[2]

    wait_for_process_to_close(old_exe_path)
    replace_and_restart(old_exe_path, new_exe_path)

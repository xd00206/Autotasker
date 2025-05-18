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

def ensure_temp_folder_is_cleared():
    # Wait a bit to let PyInstaller clean up its temp _MEI folder
    print("[⌛] Waiting for PyInstaller temp folder to be cleaned...")
    time.sleep(5)

def replace_and_restart(old_exe, new_exe):
    print(f"[🛠️] Replacing {old_exe} with {new_exe}")
    shutil.move(new_exe, old_exe)
    print("[🚀] Relaunching updated application...")
    subprocess.Popen([old_exe], shell=True)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: python updater.py <old_exe_path> <new_exe_path>")

        old_exe_path = sys.argv[1]
        new_exe_path = sys.argv[2]

        wait_for_process_to_close(old_exe_path)
        ensure_temp_folder_is_cleared()
        replace_and_restart(old_exe_path, new_exe_path)

    except Exception as e:
        with open("update_error.log", "w") as f:
            f.write(str(e))
        input("❌ An error occurred. Press Enter to close.")

import os
import shutil
import subprocess
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
DIST_DIR = PROJECT_DIR / "dist"
BUILD_DIR = PROJECT_DIR / "build"
SPEC_FILE = PROJECT_DIR / "Autotasker.spec"
RELEASE_DIR = PROJECT_DIR / "release"
EXE_NAME = "Autotasker.exe"
SOURCE_FILE = "autotasker.py"

def clean_old_builds():
    print("[🧹] Cleaning old builds...")
    for path in [DIST_DIR, BUILD_DIR, SPEC_FILE, PROJECT_DIR / "__pycache__"]:
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

def build_exe():
    print("[🛠️] Building .exe with hidden encoding fix...")
    subprocess.run([
        "pyinstaller", 
        "--onefile", 
        "--noconsole", 
        "--name", "Autotasker", 
        "--hidden-import=encodings.idna",
        SOURCE_FILE
    ], check=True)

def move_to_release():
    print("[📦] Moving built .exe to release folder...")
    RELEASE_DIR.mkdir(exist_ok=True)
    src = DIST_DIR / EXE_NAME
    dst = RELEASE_DIR / EXE_NAME

    if dst.exists():
        try:
            os.remove(dst)
            print(f"[🗑️] Old {dst.name} removed.")
        except PermissionError:
            print(f"[❌] Cannot overwrite {dst}. Please close the app and try again.")
            return

    shutil.copy2(src, dst)
    print(f"[✅] Build complete: {dst}")


def copy_updater():
    print("[📁] Copying updater.py...")
    updater_src = PROJECT_DIR / "updater.py"
    updater_dst = RELEASE_DIR / "updater.py"
    if updater_src.exists():
        shutil.copy2(updater_src, updater_dst)
        print(f"[✅] Copied to: {updater_dst}")

def copy_update_launcher():
    print("[📁] Copying update_launcher.exe...")
    src = PROJECT_DIR / "dist" / "update_launcher.exe"
    dst = RELEASE_DIR / "update_launcher.exe"
    if src.exists():
        shutil.copy2(src, dst)
        print("[✅] Copied to release folder.")

def main():
    clean_old_builds()
    build_exe()
    move_to_release()
    copy_updater()
    copy_update_launcher()

if __name__ == "__main__":
    main()

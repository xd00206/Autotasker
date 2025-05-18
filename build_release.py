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
VERSION_FILE = PROJECT_DIR / "version.txt"

UPDATE_LAUNCHER_SOURCE = PROJECT_DIR / "update_launcher.py"
UPDATE_LAUNCHER_EXE = DIST_DIR / "update_launcher.exe"
UPDATE_LAUNCHER_DST = RELEASE_DIR / "update_launcher.exe"

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

def build_update_launcher():
    print("[🛠️] Building update_launcher.exe...")
    subprocess.run([
        "pyinstaller",
        "--onefile",
        "--noconsole",
        "--name", "update_launcher",
        "update_launcher.py"
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
    if UPDATE_LAUNCHER_EXE.exists():
        shutil.copy2(UPDATE_LAUNCHER_EXE, UPDATE_LAUNCHER_DST)
        print("[✅] Copied to release folder.")

def update_docs_version():
    print("[📝] Updating docs/version.txt...")
    docs_version = PROJECT_DIR / "docs" / "version.txt"
    docs_version.parent.mkdir(exist_ok=True)
    with open(VERSION_FILE, "r") as vf:
        version = vf.read().strip()
    with open(docs_version, "w") as df:
        df.write(version)
    print(f"[✅] docs/version.txt updated to v{version}")

def commit_and_push():
    print("[🚀] Committing new version to GitHub...")
    subprocess.run(["git", "add", "docs/version.txt"], check=True)
    subprocess.run(["git", "commit", "-m", "Update version.txt for new release"], check=True)
    subprocess.run(["git", "push"], check=True)

def main():
    clean_old_builds()
    build_exe()
    build_update_launcher()
    move_to_release()
    copy_updater()
    copy_update_launcher()
    update_docs_version()
    # commit_and_push()  # ← Uncomment this line when you're ready to enable auto-push

if __name__ == "__main__":
    main()

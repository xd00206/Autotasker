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
SOURCE_FILE = "autotasker.py"  # ← Make sure this matches your main .py file

def clean_old_builds():
    print("[🧹] Cleaning old builds...")
    for path in [DIST_DIR, BUILD_DIR, SPEC_FILE, PROJECT_DIR / "__pycache__"]:
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

def build_exe():
    print("[🛠️] Building .exe...")
    subprocess.run([
        "pyinstaller", 
        "--onefile", 
        "--noconsole", 
        "--name", "Autotasker", 
        SOURCE_FILE
    ], check=True)

def move_to_release():
    print("[📦] Moving built .exe to release folder...")
    RELEASE_DIR.mkdir(exist_ok=True)
    src = DIST_DIR / EXE_NAME
    dst = RELEASE_DIR / EXE_NAME
    shutil.copy2(src, dst)
    print(f"[✅] Build complete: {dst}")

def main():
    clean_old_builds()
    build_exe()
    move_to_release()

if __name__ == "__main__":
    main()

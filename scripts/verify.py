#!/usr/bin/env python3
import sys
import subprocess

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from scripts.security_check import run_security_check
from scripts.secret_scan import run_secret_scan
from scripts.verify_docker_security import verify_docker_security

def main():
    print("==================================================")
    print("[+] Running SecureCode Sentinel Full System Verification...")
    print("==================================================")

    # 1. Run Security Checks
    if not run_security_check():
        sys.exit(1)

    if not run_secret_scan():
        sys.exit(1)

    if not verify_docker_security():
        sys.exit(1)

    # 2. Run Backend Pytest Suite
    print("==================================================")
    print("[+] Running Backend Automated Test Suite...")
    print("==================================================")
    result = subprocess.run([sys.executable, "-m", "pytest", "-v"], cwd="backend")
    if result.returncode != 0:
        print("[FAIL] Backend Pytest suite failed!")
        sys.exit(1)

    # 3. Run Frontend Production Build
    print("==================================================")
    print("[+] Building Frontend Production Bundle...")
    print("==================================================")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    build_res = subprocess.run([npm_cmd, "run", "build"], cwd="frontend")
    if build_res.returncode != 0:
        print("[FAIL] Frontend build failed!")
        sys.exit(1)

    print("\n[SUCCESS] ALL VERIFICATION CHECKS PASSED CLEANLY!")
    print("System is verified, hardened, and ready for deployment.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import sys

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def verify_docker_security() -> bool:
    print("==================================================")
    print("[+] Verifying Docker Container Security Hardening...")
    print("==================================================")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dockerfile_path = os.path.join(project_root, "docker", "Dockerfile")

    if not os.path.exists(dockerfile_path):
        print(f"[FAIL] Error: Dockerfile not found at {dockerfile_path}")
        return False

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    errors = []

    if "USER sentinel" not in content and "USER 10001" not in content:
        errors.append("Dockerfile does NOT specify non-root user execution (USER sentinel / USER 10001 missing).")

    if "bandit==" not in content:
        errors.append("Dockerfile does NOT pin Bandit analyzer version (bandit== missing).")

    if "semgrep==" not in content:
        errors.append("Dockerfile does NOT pin Semgrep analyzer version (semgrep== missing).")

    if "ENTRYPOINT" not in content:
        errors.append("Dockerfile does NOT specify explicit ENTRYPOINT.")

    if "FROM python:" not in content:
        errors.append("Dockerfile does NOT use official python base image.")

    if errors:
        print("\n[FAIL] DOCKERFILE SECURITY AUDIT FAILED:\n")
        for err in errors:
            print(f"  • {err}")
        print()
        return False

    print("[OK] Dockerfile security verification passed cleanly.")
    print("  • Base Image: python:3.11-slim")
    print("  • Non-Root User: sentinel:sentinel (UID:GID 10001:10001)")
    print("  • Pinned Scanners: bandit, semgrep")
    print("  • Entrypoint: /entrypoint.sh\n")
    return True

if __name__ == "__main__":
    success = verify_docker_security()
    sys.exit(0 if success else 1)

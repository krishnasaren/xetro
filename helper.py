
import sys
import subprocess
import importlib
import os
REQUIRED_MODULES = {
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "colorama": "colorama",
    "jinja2": "jinja2",
    "Crypto": "pycryptodome",
    "tldextract": "tldextract",
    "urllib3": "urllib3",
}

def ensure_dependencies():
    missing = []

    for module, package in REQUIRED_MODULES.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"[+] Missing modules detected: {', '.join(missing)}")
        print("[*] Installing missing dependencies...")

        subprocess.check_call([
            sys.executable, "-m", "pip", "install", *missing
        ])

        print("[✓] Dependencies installed. Restarting script...\n")

        # Re-run the current script
        #os.execv(sys.executable, [sys.executable] + sys.argv)


if __name__ == "__main__":
    ensure_dependencies()
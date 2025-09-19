import os, shutil
import pyfiglet
from colorama import Fore
import emoji
import sys
import os
import shutil
import time
import sys, time
from colorama import Fore, Style
from colorama import Fore, Style

def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("TLS Secure Chat")
    print(Fore.CYAN + banner)
    print(Fore.GREEN + emoji.emojize(":lock: Welcome to the Secure Chat Lab! :closed_lock_with_key:", language="alias"))
    print(Fore.YELLOW + "-" * 70)
    print("This lab will demonstrate how secure communication works using TLS.")
    print("You'll learn about confidentiality, authentication, and integrity.")
    print("Tools required for best experience:")
    print(Fore.MAGENTA + emoji.emojize("  :snake: Python 3.x"))
    print(Fore.MAGENTA + emoji.emojize("  :key: OpenSSL (for generating certificates)"))
    print(Fore.MAGENTA + emoji.emojize("  :magnifying_glass_tilted_left: Wireshark (for traffic inspection)"))
    print(Fore.YELLOW + "-" * 70)
    print()

def warn_missing_tools():
    missing = []
    if shutil.which("openssl") is None:
        missing.append("OpenSSL")
    if shutil.which("wireshark") is None and shutil.which("tshark") is None:
        missing.append("Wireshark/Tshark (optional)")
    if missing:
        print(Fore.YELLOW + "Heads up: missing tools detected:")
        for m in missing:
            print(Fore.YELLOW + f"  - {m}")
        print()

def type_out(text, color=Fore.LIGHTGREEN_EX, delay=0.05):
    os.system("cls" if os.name == "nt" else "clear")
    for ch in text:
        sys.stdout.write(color + ch + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(delay)
    print()  # final newline
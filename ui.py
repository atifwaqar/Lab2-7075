import os, shutil
"""User-interface helpers used by the TLS Secure Chat demos.

The functions here provide banner output and simple animations to keep the
focus on TLS concepts rather than terminal formatting.
"""

import os
import shutil
import sys
import time

import emoji
import pyfiglet
from colorama import Fore, Style

def show_banner() -> None:
    """Display the lab banner and recommended tooling.

    Args:
      None.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.
    """
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

def warn_missing_tools() -> None:
    """Warn if optional tooling like OpenSSL or Wireshark is missing.

    Args:
      None.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - Encourages installing TLS inspection tools but does not change behavior.
    """
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

def type_out(text: str, color: str = Fore.LIGHTGREEN_EX, delay: float = 0.05) -> None:
    """Type text to the console with a configurable delay between characters.

    Args:
      text: Text to render.
      color: Colorama style string for the text.
      delay: Delay in seconds between characters.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.
    """
    os.system("cls" if os.name == "nt" else "clear")
    for ch in text:
        sys.stdout.write(color + ch + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(delay)
    print()  # final newline
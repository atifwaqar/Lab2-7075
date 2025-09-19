# -*- coding: utf-8 -*-
"""
Menu-based launcher for the 5 demos so you don't have to answer Y/N questions.
Drop-in replacement for TLSSecureChat.py.

Demos:
  1) Plain chat (no TLS)
  2) TLS chat
  3) TLS chat + Wireshark key log
  4) MITM with self‑signed cert (no pinning)
  5) MITM blocked by certificate pinning

Notes:
- Uses existing helpers in deps, ui, certs, launcher, matrixfx, config.
- For (5) we pass --pin to the client via LAUNCHER_EXTRAS so pinning kicks in.
  If your client uses another flag or env var, tweak `PIN_CLIENT_ARGS` below.
"""
import os
import deps
deps.ensure_all()
from colorama import Fore, Style

import deps
from ui import show_banner, warn_missing_tools
from certs import ensure_server_certs, ensure_mitm_certs
from launcher import start_chat, start_mitm_chat
from matrixfx import matrix_rain_effect
import config

# -----------------------------------------------------
# Bootstrap deps before importing runtime-only libraries
# -----------------------------------------------------

# ---------
# Constants
# ---------
PIN_CLIENT_ARGS = ["--pin"]  # adjust if your client expects a different flag

MENU_ITEMS = [
    ("Plain chat (no TLS)",               {"mode": "plain", "keylog": None,  "mitm": False, "pin": False}),
    ("TLS chat",                           {"mode": "tls",   "keylog": None,  "mitm": False, "pin": False}),
    ("TLS chat + Wireshark key log",      {"mode": "tls",   "keylog": config.KEYLOG_FILENAME, "mitm": False, "pin": False}),
    ("MITM with self‑signed cert",        {"mode": "tls",   "keylog": None,  "mitm": True,  "pin": False}),
    ("MITM blocked by certificate pinning", {"mode": "tls", "keylog": None,  "mitm": True,  "pin": True}),
]

# --------------
# Menu utilities
# --------------
def print_menu() -> None:
    show_banner()
    warn_missing_tools()
    print(Fore.CYAN + "Choose a demo:" + Style.RESET_ALL)
    for idx, (label, _) in enumerate(MENU_ITEMS, start=1):
        print(Fore.WHITE + f"  {idx}. " + Fore.LIGHTGREEN_EX + label + Style.RESET_ALL)
    print(Fore.WHITE + "  0. Exit" + Style.RESET_ALL)
    print()


def read_choice() -> int:
    while True:
        try:
            raw = input(Fore.WHITE + "Enter a number: " + Style.RESET_ALL).strip()
            if raw == "":
                continue
            if raw == "0":
                return 0
            choice = int(raw)
            if 1 <= choice <= len(MENU_ITEMS):
                return choice
        except ValueError:
            pass
        print(Fore.RED + "Invalid choice. Please enter a number from the menu." + Style.RESET_ALL)


# -------
# Runner
# -------
def run_selection(sel: int) -> None:
    label, opts = MENU_ITEMS[sel - 1]
    mode   = opts["mode"]          # "plain" or "tls"
    keylog = opts["keylog"]        # None or path
    mitm   = opts["mitm"]          # bool
    pin    = opts["pin"]           # bool

    # Pre-work
    if mode == "tls" and not mitm:
        # Normal TLS demos need server certs
        ensure_server_certs()
        if keylog:
            # Ensure keylog file exists
            keylog_path = os.path.abspath(keylog)
            open(keylog_path, "a", encoding="utf-8").close()
            print(Fore.YELLOW + f"TLS key logging ENABLED: {keylog_path}")
            print(Fore.YELLOW + "Wireshark → Preferences → Protocols → TLS → Pre-Master-Secret log filename\n")
    elif mitm:
        # MITM demos need a separate self‑signed cert
        ensure_mitm_certs()

    # Dramatic flair ✨
    print()
    print(Fore.GREEN + f"Starting: {label}\n")
    matrix_rain_effect()

    # Launch
    if mitm:
        # MITM flow spins up real server, the proxy, then the client connecting to the proxy
        # For pinning we rely on client to enforce it via an arg understood by client.py
        if pin:
            # Let the launcher know to pass an extra flag through
            os.environ["LAUNCHER_EXTRAS"] = " ".join(PIN_CLIENT_ARGS)
            start_mitm_chat(pin="4b9fa70b5483ed545b5821982a59b1888d4fb36a918a37c55c94802644e1c51f")
        else:
            os.environ.pop("LAUNCHER_EXTRAS", None)
            start_mitm_chat()
    else:
        # Direct server+client chat (plain or TLS)
        start_chat(mode, os.path.abspath(keylog) if keylog else None, config.PORT_SERVER)


def main() -> None:
    try:
        while True:
            try:
                print_menu()
                choice = read_choice()  # may raise EOFError if console is closed
            except (EOFError, KeyboardInterrupt):
                print("\n" + Fore.CYAN + "Goodbye!" + Style.RESET_ALL)
                break

            if choice == 0:
                print(Fore.CYAN + "Goodbye!" + Style.RESET_ALL)
                break

            # Run the selected demo, but keep the menu alive even if it errors.
            try:
                run_selection(choice)
            except (KeyboardInterrupt, EOFError):
                print("\n[info] Demo interrupted.")
            except Exception as e:
                # Keep it friendly; no full traceback in release/teaching mode
                print(Fore.RED + f"[error] Demo crashed: {e}" + Style.RESET_ALL)

            print()
            try:
                input(Fore.WHITE + "Press Enter to return to the menu..." + Style.RESET_ALL)
            except (EOFError, KeyboardInterrupt):
                print("\n" + Fore.CYAN + "Goodbye!" + Style.RESET_ALL)
                break
    finally:
        # Optional: any cleanup, e.g., env vars you might have set
        os.environ.pop("LAUNCHER_EXTRAS", None)



if __name__ == "__main__":
    main()

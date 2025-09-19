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
- TLS demos now validate certificates. The MITM demos automatically launch the
  client with ``--insecure`` so you can still explore the vulnerable workflow.
  Adjust ``INSECURE_CLIENT_ARGS`` below if your client uses a different flag.
"""
import os
import hashlib
from typing import Callable

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
INSECURE_CLIENT_ARGS = ("--insecure",)

MENU_ITEMS = [
    ("Plain chat (no TLS)",               {"mode": "plain", "keylog": None,  "mitm": False, "pin": False, "extras": ()}),
    ("TLS chat (certificate validation)", {"mode": "tls",   "keylog": None,  "mitm": False, "pin": False, "extras": ()}),
    ("TLS chat + Wireshark key log",      {"mode": "tls",   "keylog": config.KEYLOG_FILENAME, "mitm": False, "pin": False, "extras": ()}),
    ("MITM with self‑signed cert (insecure client)",
     {"mode": "tls",   "keylog": None,  "mitm": True,  "pin": False, "extras": INSECURE_CLIENT_ARGS}),
    ("MITM blocked by certificate pinning (insecure client)",
     {"mode": "tls", "keylog": None,  "mitm": True,  "pin": True,  "extras": INSECURE_CLIENT_ARGS}),
]

# --------------
# Menu utilities
# --------------
def print_menu() -> None:
    show_banner()
    warn_missing_tools()
    print(Fore.YELLOW +
          "Secure by default: TLS demos verify certificates. Use --insecure to "
          "disable checks when exploring lab scenarios." +
          Style.RESET_ALL)
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


# -----------------------
# Certificate preparation
# -----------------------

def _run_cert_setup(task: Callable[[], None], failure_message: str) -> bool:
    try:
        task()
        return True
    except SystemExit:
        print(Fore.RED + failure_message + Style.RESET_ALL)
        return False
    except Exception as exc:  # pragma: no cover - defensive guardrail
        print(
            Fore.RED
            + f"{failure_message} ({exc})."
            + Style.RESET_ALL
        )
        return False


def _prepare_certificates(mode: str, mitm: bool) -> bool:
    if mode == "tls":
        if not _run_cert_setup(
            ensure_server_certs,
            "[error] Failed to prepare TLS server certificates. Aborting demo.",
        ):
            return False
    if mitm:
        if not _run_cert_setup(
            ensure_mitm_certs,
            "[error] Failed to prepare MITM certificates. Aborting demo.",
        ):
            return False
    return True


# -------
# Runner
# -------
def run_selection(sel: int) -> None:
    label, opts = MENU_ITEMS[sel - 1]
    mode   = opts["mode"]          # "plain" or "tls"
    keylog = opts["keylog"]        # None or path
    mitm   = opts["mitm"]          # bool
    pin    = opts["pin"]           # bool
    extras = tuple(opts.get("extras", ()))

    # Pre-work
    if extras:
        os.environ["LAUNCHER_EXTRAS"] = " ".join(extras)
    else:
        os.environ.pop("LAUNCHER_EXTRAS", None)

    if not _prepare_certificates(mode, mitm):
        return

    if mode == "tls" and not mitm and keylog:
        # Ensure keylog file exists
        keylog_path = os.path.abspath(keylog)
        open(keylog_path, "a", encoding="utf-8").close()
        print(Fore.YELLOW + f"TLS key logging ENABLED: {keylog_path}")
        print(Fore.YELLOW + "Wireshark → Preferences → Protocols → TLS → Pre-Master-Secret log filename\n")

    # Dramatic flair ✨
    print()
    print(Fore.GREEN + f"Starting: {label}\n")
    matrix_rain_effect()

    # Launch
    if mitm:
        # MITM flow spins up real server, the proxy, then the client connecting to the proxy
        # For pinning we rely on client to enforce it via an arg understood by client.py
        if pin:
            ensure_server_certs()
            server_cert_path = os.path.abspath("server.crt")
            if not os.path.exists(server_cert_path):
                raise FileNotFoundError("server.crt is required for the pinning demo but was not found")

            with open(server_cert_path, "rb") as cert_file:
                fingerprint = hashlib.sha256(cert_file.read()).hexdigest()

            print(
                Fore.YELLOW
                + "[Pinning] server.crt SHA-256 fingerprint: "
                + Fore.LIGHTGREEN_EX
                + fingerprint
                + Style.RESET_ALL
            )
            print(Fore.YELLOW + "[Pinning] Pass this value to --pin if launching manually." + Style.RESET_ALL)

            start_mitm_chat(pin=fingerprint)
        else:
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

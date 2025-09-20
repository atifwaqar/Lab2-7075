# -*- coding: utf-8 -*-
"""Interactive launcher for the TLS Secure Chat lab scenarios.

How to run:
  1. ``python TLSSecureChat.py``
  2. Choose a demo from the numbered menu.
  3. Follow the on-screen instructions (server first, client second).  MITM
     demos automatically run the proxy and connect the client through it.

The menu orchestrates five flows that showcase TLS basics, Wireshark key
logging, and how certificate pinning stops an active MITM.  The heavy lifting
is delegated to the ``launcher`` helpers while this file focuses on user
experience and TLS education.
"""
import os
import hashlib
import importlib
import importlib.util
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


def _spki_sha256_for_cert(path: str) -> str:
    """Return the SPKI SHA-256 hash for a PEM or DER certificate.

    Args:
      path: Filesystem path to a certificate in PEM or DER format.

    Returns:
      str: Lowercase hexadecimal SHA-256 digest of the certificate's SPKI.

    Raises:
      ValueError: If the certificate cannot be parsed by ``cryptography``.

    Security Notes:
      - SPKI pinning is more resilient than leaf fingerprint pinning when
        certificates rotate under the same key.  The launcher prints both so
        students can experiment with each strategy.
    """
    x509 = importlib.import_module("cryptography.x509")
    serialization = importlib.import_module(
        "cryptography.hazmat.primitives.serialization"
    )
    hashes_mod = importlib.import_module("cryptography.hazmat.primitives.hashes")

    with open(path, "rb") as cert_file:
        cert_bytes = cert_file.read()

    if cert_bytes.lstrip().startswith(b"-----BEGIN CERTIFICATE"):
        loader = x509.load_pem_x509_certificate
    else:
        loader = x509.load_der_x509_certificate

    cert = loader(cert_bytes)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes_mod.Hash(hashes_mod.SHA256())
    digest.update(spki)
    return digest.finalize().hex()


# --------------
# Menu utilities
# --------------
def print_menu() -> None:
    """Render the launcher menu with contextual TLS guidance.

    Args:
      None.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - Highlights that TLS demos validate certificates by default so learners
        remember that ``--insecure`` intentionally downgrades security.
    """

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
    """Prompt the user until a valid menu selection is entered.

    Args:
      None.

    Returns:
      int: The selected menu option (0 exits).

    Raises:
      None.

    Security Notes:
      - None.  Input is limited to menu choices and does not affect TLS logic.
    """

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
    """Execute a certificate preparation callable and capture failures.

    Args:
      task: Zero-argument function that generates certificates.
      failure_message: Message displayed if the callable raises.

    Returns:
      bool: ``True`` on success, ``False`` if generation failed.

    Raises:
      None.

    Security Notes:
      - Ensuring certificates exist up front prevents TLS handshakes from
        failing mid-demo, which keeps the security story focused.
    """

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
    """Ensure server and/or MITM certificates exist for the scenario.

    Args:
      mode: Either ``"plain"`` or ``"tls"``.
      mitm: Whether the MITM proxy will be launched.

    Returns:
      bool: ``True`` if certificate preparation succeeded.

    Raises:
      None.

    Security Notes:
      - MITM demos generate an attacker certificate so students can inspect the
        resulting TLS handshake and observe how pinning blocks it.
    """

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
    """Launch the selected lab scenario and print prep information.

    Args:
      sel: 1-based index into ``MENU_ITEMS``.

    Returns:
      None.

    Raises:
      FileNotFoundError: If pinning is requested but ``server.crt`` is missing.

    Security Notes:
      - When pinning is enabled, the function prints both leaf and SPKI hashes
        to reinforce why pinning thwarts MITM attempts.
    """

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
        print(
            Fore.YELLOW
            + "Wireshark → Preferences → Protocols → TLS → Pre-Master-Secret log filename"
        )
        print(
            Fore.YELLOW
            + f"Open a capture in Wireshark; set TLS → (Pre)-Master-Secret log file to: {keylog_path}"
        )
        print(Fore.YELLOW + "Wireshark filter example: tcp.port == 12345")
        print(
            Fore.YELLOW
            + "openssl s_client -connect 127.0.0.1:12345 -servername localhost -tls1_3 -showcerts"
        )
        print(
            Fore.YELLOW
            + "To view session details: openssl s_client -connect 127.0.0.1:12345 -servername "
            "localhost -tls1_3 -msg -state"
        )
        print()

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
                cert_bytes = cert_file.read()

            fingerprint = hashlib.sha256(cert_bytes).hexdigest()

            print(
                Fore.YELLOW
                + "[Pinning] server.crt SHA-256 fingerprint: "
                + Fore.LIGHTGREEN_EX
                + fingerprint
                + Style.RESET_ALL
            )

            spki_fp = None
            spki_note = None
            spki_note_color = Fore.YELLOW
            if importlib.util.find_spec("cryptography") is None:
                spki_note = "Install 'cryptography' to compute SPKI hashes for --pin-spki."
            else:
                try:
                    spki_fp = _spki_sha256_for_cert(server_cert_path)
                except Exception as exc:  # pragma: no cover - defensive guardrail
                    spki_note = f"Unable to compute SPKI hash: {exc}"
                    spki_note_color = Fore.RED

            if spki_fp:
                print(
                    Fore.YELLOW
                    + "[Pinning] server.crt SPKI SHA-256: "
                    + Fore.LIGHTGREEN_EX
                    + spki_fp
                    + Style.RESET_ALL
                )
                print(
                    Fore.YELLOW
                    + "[Pinning] Use --pin for the cert fingerprint or --pin-spki for the SPKI hash when launching manually."
                    + Style.RESET_ALL
                )
            else:
                if spki_note:
                    print(
                        spki_note_color
                        + "[Pinning] "
                        + spki_note
                        + Style.RESET_ALL
                    )
                print(
                    Fore.YELLOW
                    + "[Pinning] Pass this fingerprint to --pin if launching manually."
                    + Style.RESET_ALL
                )

            start_mitm_chat(pin=fingerprint)
        else:
            start_mitm_chat()
    else:
        # Direct server+client chat (plain or TLS)
        start_chat(mode, os.path.abspath(keylog) if keylog else None, config.PORT_SERVER)


def main() -> None:
    """Entry point for the launcher, keeping the menu responsive.

    Args:
      None.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - Runs demos in a loop so students can compare secure vs. insecure
        configurations without restarting Python.
    """

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

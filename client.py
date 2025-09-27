# -*- coding: utf-8 -*-
"""TLS chat client demonstrating certificate validation and pinning.

The client connects to the lab server (or MITM proxy), performs a TLS handshake
when requested, and renders messages through the shared terminal UI.  The
command-line flags expose toggles for intentionally insecure behavior so
students can witness the consequences of disabling certificate checks.
"""

import socket
import ssl
import hashlib
import hmac
import threading
import argparse
import importlib
import importlib.util
import config

from chatui import create_chat_app  # << new

# --- console snapping (Windows only) ---
import sys
from window_utils import snap_console

import sys, os, time, traceback

from typing import Iterable, Optional


def _safe_symbol(preferred: str, fallback: str, *, stream=None) -> str:
    """Return a printable symbol that respects the stream encoding.

    Some execution environments (including the Mininet VMs used in the lab)
    configure stdout/stderr with ``latin-1`` encodings.  Printing emojis or
    other non-ASCII glyphs to such streams raises ``UnicodeEncodeError``
    exceptions.  To keep the demos resilient we attempt to encode the desired
    symbol with the target stream's encoding and gracefully fall back to an
    ASCII label when that fails.

    Args:
      preferred: The Unicode symbol we would like to display.
      fallback: ASCII replacement used when ``preferred`` cannot be encoded.
      stream: Output stream (defaults to ``sys.stdout``).

    Returns:
      str: Either ``preferred`` (when it is encodable) or ``fallback``.
    """

    target = stream if stream is not None else sys.stdout
    encoding = getattr(target, "encoding", None) or "utf-8"
    try:
        preferred.encode(encoding)
        return preferred
    except (UnicodeEncodeError, LookupError):
        return fallback

# ---- Demo-5 friendly pause helpers ----
def _interactive_pause(seconds: Optional[float] = None, *, show_prompt: bool = True) -> None:
    """Pause execution so the console window remains visible.

    Args:
      seconds: Optional timeout before resuming automatically.
      show_prompt: Whether to print instructions for the user.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.  This helper only affects user experience during demos.
    """
    prompt_close = None
    if show_prompt:
        prompt_close = (
            "[Client] Press any key to close this window."
            if seconds is None
            else f"[Client] (Press any key to close, or auto-close in {seconds}s)"
        )
    try:
        # Windows: use msvcrt for key detection
        import msvcrt

        if show_prompt and prompt_close:
            print(prompt_close, flush=True)
        if seconds is None:
            msvcrt.getch()
            return

        end = time.time() + seconds
        while time.time() < end:
            if msvcrt.kbhit():
                msvcrt.getch()
                return
            time.sleep(0.1)
        return
    except Exception:
        # POSIX: wait for Enter if a TTY, otherwise sleep
        try:
            if sys.stdin and sys.stdin.isatty():
                import select

                if show_prompt:
                    print(
                        "[Client] Press Enter to close this window." if seconds is None
                        else f"[Client] (Press Enter to close, or auto-close in {seconds}s)",
                        flush=True,
                    )
                if seconds is None:
                    sys.stdin.readline()
                    return

                r, _, _ = select.select([sys.stdin], [], [], seconds)
                if r:
                    sys.stdin.readline()
                return
        except Exception:
            pass

    # Fallback: final sleep (only used when no TTY is available)
    time.sleep(0 if seconds is None else seconds)

def graceful_exit(code: int = 0, message=None, seconds: Optional[float] = None) -> None:
    """Print a message, optionally pause, then exit the process.

    Args:
      code: Exit status code.
      message: String or iterable of strings to display before exiting.
      seconds: Optional duration to keep the window open.

    Returns:
      None.

    Raises:
      SystemExit: Indirectly via ``os._exit`` terminating the interpreter.

    Security Notes:
      - None.  Intended to keep lab messages visible for students.
    """
    if message:
        target = sys.stderr if code else sys.stdout
        if isinstance(message, str):
            print(message, file=target)
        elif isinstance(message, Iterable):
            for line in message:
                print(line, file=target)
        else:
            print(str(message), file=target)
    # Ensure text hits the console before we pause
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    #_interactive_pause(seconds)
    # Use os._exit to avoid other atexit handlers shortening our pause
    os._exit(code)

def install_graceful_crash_handler(seconds: Optional[float] = None) -> None:
    """Install a global excepthook that pauses after unexpected crashes.

    Args:
      seconds: Optional timeout before closing the window automatically.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.  The handler is purely for student ergonomics.
    """
    def _hook(exc_type, exc, tb):
        error_symbol = _safe_symbol("❌", "[ERROR]", stream=sys.stderr)
        print(f"\n[Client] {error_symbol} Unexpected error:", file=sys.stderr, flush=True)
        traceback.print_exception(exc_type, exc, tb)
        if seconds is None:
            print("[Client] Press any key to close this window.", file=sys.stderr, flush=True)
        else:
            print(
                f"[Client] The window will close in {seconds} seconds…",
                file=sys.stderr,
                flush=True,
            )
        #_interactive_pause(seconds, show_prompt=False)
        os._exit(1)
    sys.excepthook = _hook

STOP = threading.Event()

# -------------------- TLS helpers --------------------
def sha256_fingerprint(cert_bytes: bytes) -> str:
    """Compute a lowercase SHA-256 fingerprint for certificate bytes.

    Args:
      cert_bytes: DER-encoded certificate bytes.

    Returns:
      str: Hexadecimal SHA-256 digest.

    Raises:
      None.

    Security Notes:
      - Used for certificate pinning; matching fingerprints block impostors.
    """

    return hashlib.sha256(cert_bytes).hexdigest()


def _norm_fp(s: str) -> str:
    """Normalise fingerprint text for constant-time comparisons.

    Args:
      s: Fingerprint string potentially containing separators or whitespace.

    Returns:
      str: Normalised lowercase hex string.

    Raises:
      None.

    Security Notes:
      - Ensures user-provided pins and computed fingerprints are compared in a
        stable format before ``hmac.compare_digest`` enforces constant timing.
    """

    return s.replace(":", "").strip().lower()


def spki_sha256_from_der(der_bytes: bytes) -> str:
    """Return the SHA-256 hash of the certificate's SPKI in lowercase hex.

    Args:
      der_bytes: DER-encoded certificate bytes.

    Returns:
      str: Lowercase hexadecimal SHA-256 digest of the SPKI structure.

    Raises:
      ModuleNotFoundError: If ``cryptography`` is not installed.
      ImportError: If importing ``cryptography`` submodules fails.

    Security Notes:
      - SPKI pinning survives leaf certificate rotations that keep the same key
        pair, illustrating a more flexible pinning strategy.
    """
    if importlib.util.find_spec("cryptography") is None:
        raise ModuleNotFoundError(
            "The 'cryptography' package is required for --pin-spki. "
            "Install it with 'python -m pip install cryptography'."
        )

    x509 = importlib.import_module("cryptography.x509")
    serialization = importlib.import_module(
        "cryptography.hazmat.primitives.serialization"
    )
    hashes_mod = importlib.import_module("cryptography.hazmat.primitives.hashes")

    cert = x509.load_der_x509_certificate(der_bytes)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes_mod.Hash(hashes_mod.SHA256())
    digest.update(spki)
    return digest.finalize().hex()

# -------------------- networking --------------------
def main():
    """Run the chat client CLI and manage TLS handshake/pinning logic.

    Args:
      None.  CLI arguments are parsed from ``sys.argv``.

    Returns:
      None.

    Raises:
      SystemExit: If fatal errors require terminating the process.

    Security Notes:
      - Creates an ``ssl.SSLContext`` with certificate/hostname verification
        enabled by default.  Using ``--insecure`` switches to ``CERT_NONE`` and
        disables SNI/hostname checks, illustrating why MITM succeeds.
      - Performs certificate or SPKI pinning after the TLS handshake to block
        rogue certificates even when the trust store would accept them.
      - The TLS 1.3 handshake occurs during ``context.wrap_socket``; errors from
        that call surface validation failures to the UI.
    """

    install_graceful_crash_handler()
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["tls", "plain"], default="tls")
    parser.add_argument("--keylog", help="Path to write TLS key log (for Wireshark decryption)", default=None)
    parser.add_argument("--port", type=int, default=config.PORT_SERVER, help="Port to connect/bind to")
    parser.add_argument("--cafile", help="Path to a CA bundle or server certificate for verification", default=None)
    parser.add_argument("--insecure", action="store_true",
                        help="Disable certificate verification (lab/demo mode only)")
    pin_group = parser.add_mutually_exclusive_group()
    pin_group.add_argument(
        "--pin",
        help="SHA-256 fingerprint of server cert (lowercase hex, no colons)",
    )
    pin_group.add_argument(
        "--pin-spki",
        help="SHA-256 of server SubjectPublicKeyInfo (lowercase hex, no colons)",
    )
    parser.add_argument("--snap", action="store_true", help="Snap console to right half on start")  # optional flag
    args = parser.parse_args()

    snap_console()

    HOST = "10.0.0.1"
    PORT = args.port
    use_tls = (args.mode == "tls")

    print(f"[Client] Connecting to {HOST}:{PORT} ...")
    try:
        sock = socket.create_connection((HOST, PORT))
    except OSError as exc:
        graceful_exit(
            1,
            [
                f"[Client] Unable to connect to {HOST}:{PORT}.",
                f"[Client] Details: {exc}",
            ],
        )
    sock.settimeout(0.2)  # allow quick exit on Ctrl+C/Q
    if use_tls:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # Prefer TLS1.3 for lab captures; fallback to TLS1.2 if unavailable.
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        if args.insecure:
            warn_symbol = _safe_symbol("⚠️", "[WARNING]")
            print(f"[Client] {warn_symbol} Certificate verification disabled (--insecure).")
            # CERT_NONE removes both certificate chain validation and hostname
            # matching; this intentionally makes the client trust the MITM's
            # self-signed certificate during the vulnerable demo.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            # Default path: rely on the platform trust store plus the lab's
            # generated certificate so the TLS handshake authenticates the
            # server before any chat messages flow.
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            loaded_bundle = False
            if args.cafile:
                context.load_verify_locations(cafile=args.cafile)
                print(f"[Client] Loaded CA bundle: {args.cafile}")
                loaded_bundle = True
            else:
                default_cert = os.path.join(os.path.dirname(__file__), "server.crt")
                if os.path.exists(default_cert):
                    context.load_verify_locations(cafile=default_cert)
                    print(f"[Client] Loaded bundled server certificate: {default_cert}")
                    loaded_bundle = True

            if not loaded_bundle:
                print("[Client] Using system trust store for verification.")
                print("[Client] If you generated server.crt, it will be trusted automatically.")
                print("[Client] Pass --cafile or --insecure if you are using custom lab certificates.")

        if args.keylog:
            try:
                context.keylog_filename = args.keylog
            except AttributeError:
                pass

        # --- create the TLS socket ---
        try:
            # The TLS handshake happens within ``wrap_socket``.  On success the
            # returned object is ready for encrypted I/O; failures surface
            # certificate or protocol issues to the user.
            ssock = context.wrap_socket(sock, server_hostname="localhost")
        except ssl.SSLCertVerificationError as exc:
            sock.close()
            graceful_exit(
                1,
                [
                    "[Client] TLS handshake failed: certificate verification error.",
                    f"[Client] Details: {exc}",
                    "[Client] Generate server.crt or pass --cafile/--insecure if this is expected in the lab.",
                ],
            )
        except ssl.SSLError as exc:
            sock.close()
            messages = ["[Client] TLS handshake failed."]
            if args.pin or args.pin_spki:
                messages.append("[Client] Certificate pinning prevented the connection.")
            messages.append(f"[Client] Details: {exc}")
            graceful_exit(1, messages)

        ssock.settimeout(0.2)

        der_cert = ssock.getpeercert(binary_form=True)
        fp = sha256_fingerprint(der_cert)
        print(f"[*] Server certificate fingerprint: {fp}")

        spki_fp = None
        if args.pin_spki:
            try:
                spki_fp = spki_sha256_from_der(der_cert)
            except (ModuleNotFoundError, ImportError) as exc:
                ssock.close()
                graceful_exit(
                    1,
                    [
                        "[!] SPKI pinning requested but unavailable.",
                        "[!] Install the 'cryptography' package to enable --pin-spki.",
                        f"    Details: {exc}",
                    ],
                )
            else:
                print(f"[*] Server SPKI SHA-256: {spki_fp}")

            expected_spki = _norm_fp(args.pin_spki)
            # Constant-time comparison defends against timing side-channels when
            # checking user-provided pins.
            if not hmac.compare_digest(_norm_fp(spki_fp), expected_spki):
                ssock.close()
                graceful_exit(
                    1,
                    [
                        "[!] SPKI certificate pinning FAILED!",
                        f"    Expected: {expected_spki}",
                        f"    Got:      {spki_fp}",
                        "    Certificate pinning makes sure you are talking to the exact server you approved by matching this fingerprint.",
                        "    Because the fingerprint changed, the client suspects someone may be intercepting traffic (a MITM) or the server was replaced.",
                        "[Client] To keep your data safe, the connection was closed instead of trusting the unexpected certificate.",
                    ],
                )
            else:
                print("[*] SPKI pinning successful")

        if args.pin:
            expected_fp = _norm_fp(args.pin)
            if not hmac.compare_digest(_norm_fp(fp), expected_fp):
                ssock.close()
                graceful_exit(
                    1,
                    [
                        "[!] Certificate pinning FAILED!",
                        f"    Expected: {expected_fp}",
                        f"    Got:      {fp}",
                        "    Certificate pinning ensures this connection only proceeds when the server's certificate fingerprint matches the trusted value you supplied.",
                        "    The mismatch suggests the certificate changed, which could mean a misconfiguration or that someone is trying to intercept the connection (MITM).",
                        "[Client] The client closed the connection to prevent sending data to an untrusted server.",
                    ],
                )
            else:
                print("[*] Certificate pinning successful")

        title = f"TLS Client | Connected | fp: {fp}"
        if spki_fp:
            title += f" | spki: {spki_fp}"
        io_sock = ssock
    else:
        title = "Plain Client | Connected (NO TLS)"
        io_sock = sock

    app = create_chat_app(title, send_callback=lambda m: io_sock.sendall(m.encode("utf-8")))
    app.pre_run_callables.append(lambda: app.append_system(f"[connected to {HOST}:{PORT}]"))
    if use_tls and args.keylog:
        app.pre_run_callables.append(lambda: app.append_system(f"[TLS key logging enabled: {args.keylog}]"))

    # ---- Receiver thread (works for TLS and plain via io_sock) ----
    def rx():
        """Background thread reading from the socket and updating the UI.

        Args:
          None.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - Receives decrypted plaintext once the TLS layer has completed the
            handshake, reinforcing that confidentiality hinges on validation.
        """
        try:
            while not STOP.is_set():
                try:
                    data = io_sock.recv(1024)
                except socket.timeout:
                    continue
                if not data:
                    app.append_system("[server disconnected]")
                    break
                app.append_peer(data.decode("utf-8", errors="ignore"))
        except Exception as e:
            if not STOP.is_set():
                app.append_system(f"[receive error: {e}]")
        finally:
            try:
                io_sock.close()
            except Exception:
                pass

    threading.Thread(target=rx, daemon=True).start()

    try:
        app.run()
    finally:
        STOP.set()
        try:
            io_sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            io_sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    try:
        main()
    except Exception:
        error_symbol = _safe_symbol("❌", "[ERROR]", stream=sys.stderr)
        print(f"\n[Client] {error_symbol} Unexpected crash:", file=sys.stderr, flush=True)
        traceback.print_exc()
        #_interactive_pause()
        os._exit(1)


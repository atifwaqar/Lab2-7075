# -*- coding: utf-8 -*-
import socket
import ssl
import hashlib
import threading
import argparse
import config

from chatui import create_chat_app  # << new

# --- console snapping (Windows only) ---
import sys
from window_utils import snap_console

import sys, os, time, traceback

# ---- Demo-5 friendly pause helpers ----
def _interactive_pause(seconds=5):
    """Cross-platform 'hold the window' with key-to-close, fallback to sleep."""
    try:
        # Windows: non-blocking key detection
        import msvcrt
        end = time.time() + seconds
        print(f"[Client] (Press any key to close, or auto-close in {seconds}s)", flush=True)
        while time.time() < end:
            if msvcrt.kbhit():
                msvcrt.getch()
                return
            time.sleep(0.1)
    except Exception:
        # POSIX: wait for Enter if a TTY, otherwise sleep
        try:
            if sys.stdin and sys.stdin.isatty():
                import select
                print(f"[Client] (Press Enter to close, or auto-close in {seconds}s)", flush=True)
                r, _, _ = select.select([sys.stdin], [], [], seconds)
                if r:
                    sys.stdin.readline()
                    return
                return
        except Exception:
            pass
    # Fallback
    time.sleep(seconds)

def graceful_exit(code=0, message=None, seconds=5):
    """Print message, flush, pause, and exit. Use for all planned exits in Demo 5."""
    if message:
        print(message, file=sys.stderr if code else sys.stdout)
    # Ensure text hits the console before we pause
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    _interactive_pause(seconds)
    # Use os._exit to avoid other atexit handlers shortening our pause
    os._exit(code)

def install_graceful_crash_handler(seconds=5):
    """Catch *any* uncaught exception and hold the window so users can read it."""
    def _hook(exc_type, exc, tb):
        print("\n[Client] ❌ Unexpected error:", file=sys.stderr, flush=True)
        traceback.print_exception(exc_type, exc, tb)
        print(f"[Client] The window will close in {seconds} seconds…", file=sys.stderr, flush=True)
        _interactive_pause(seconds)
        os._exit(1)
    sys.excepthook = _hook

STOP = threading.Event()

# -------------------- TLS helpers --------------------
def sha256_fingerprint(cert_bytes: bytes) -> str:
    return hashlib.sha256(cert_bytes).hexdigest()

# -------------------- networking --------------------
def main():
    install_graceful_crash_handler(seconds=5)
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["tls", "plain"], default="tls")
    parser.add_argument("--keylog", help="Path to write TLS key log (for Wireshark decryption)", default=None)
    parser.add_argument("--port", type=int, default=config.PORT_SERVER, help="Port to connect/bind to")
    parser.add_argument("--pin", help="SHA-256 fingerprint of server cert (lowercase hex, no colons)")
    parser.add_argument("--snap", action="store_true", help="Snap console to right half on start")  # optional flag
    args = parser.parse_args()

    snap_console()

    HOST = "127.0.0.1"
    PORT = args.port
    use_tls = (args.mode == "tls")

    print(f"[Client] Connecting to {HOST}:{PORT} ...")
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(0.2)  # allow quick exit on Ctrl+C/Q
    if use_tls:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # For the lab's initial steps, we intentionally disable validation; switch later.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if args.keylog:
            try:
                context.keylog_filename = args.keylog
            except AttributeError:
                pass

        # --- create the TLS socket ---
        try:
            ssock = context.wrap_socket(sock, server_hostname="localhost")
        except ssl.SSLError as exc:
            sock.close()
            print("[Client] TLS handshake failed.")
            if args.pin:
                print("[Client] Certificate pinning prevented the connection.")
            print(f"[Client] Details: {exc}")
            return

        ssock.settimeout(0.2)

        der_cert = ssock.getpeercert(binary_form=True)
        fp = sha256_fingerprint(der_cert)
        print(f"[*] Server certificate fingerprint: {fp}")

        if args.pin:
            expected_fp = args.pin.lower()
            if fp != expected_fp:
                print(f"[!] Certificate pinning FAILED!\n"
                      f"    Expected: {expected_fp}\n"
                      f"    Got:      {fp}")
                ssock.close()
                return
            else:
                print("[*] Certificate pinning successful")

        title = f"TLS Client | Connected | fp: {fp}"
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
    main()
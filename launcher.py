# launcher.py
"""Convenience wrappers that start the chat server, client, and MITM demos.

The launcher mirrors the workflow students follow manually: start the server,
optionally start a MITM proxy, then connect a client.  It keeps repetitive
command-line arguments in one place and documents the intended order of
operations for each scenario.
"""

import os
import sys
import time
import subprocess
import socket
import shlex

import config
from certs import ensure_server_certs


def start_server_console(
    mode: str,
    keylog_path: str | None,
    port: int,
    new_console: bool = True,
) -> None:
    """Launch the chat server in a separate console window.

    Args:
      mode: ``"plain"`` or ``"tls"`` server mode.
      keylog_path: Optional TLS key log path for Wireshark integration.
      port: TCP port for the server to bind.
      new_console: Whether to spawn a new terminal window (Windows UX helper).

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - When ``mode`` is ``"tls"``, the server uses the locally generated
        certificate/key pair.  Protect the resulting window so the private key
        contents are not exposed inadvertently.
    """

    args = [sys.executable, "server.py", "--mode", mode, "--port", str(port)]
    if keylog_path:
        args += ["--keylog", keylog_path]
    if new_console:
        if os.name == "nt":
            subprocess.Popen(["cmd", "/c", "start", "", *args], cwd=os.getcwd(), close_fds=True)
        else:
            subprocess.Popen(args, cwd=os.getcwd())
    else:
        subprocess.run(args, cwd=os.getcwd())

def start_client_console(
    mode: str,
    keylog_path: str | None,
    port: int,
    pin: str | None = None,
    new_console: bool = True,
    snap: bool = True,
) -> None:
    """Launch the chat client configured for the requested scenario.

    Args:
      mode: ``"plain"`` or ``"tls"`` client mode.
      keylog_path: Optional TLS key log output destination.
      port: Destination port for the client to connect to.
      pin: Certificate or SPKI fingerprint when running the pinning demo.
      new_console: Whether to spawn a separate terminal window.
      snap: If ``True``, align the window using ``window_utils`` for demo UX.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - ``pin`` is propagated to the client so it can reject impostor
        certificates presented by the MITM proxy.
      - ``LAUNCHER_EXTRAS`` allows demos to inject ``--insecure`` for the
        intentionally vulnerable flows.  Ensure the variable is unset for
        production-like runs.
    """

    args = [sys.executable, "client.py",
            "--mode", mode,
            "--port", str(port)]
    if keylog_path:
        args += ["--keylog", keylog_path]
    if pin:
        args += ["--pin", pin]
    if snap:
        args += ["--snap"]

    extras = os.environ.get("LAUNCHER_EXTRAS")
    if extras:
        args.extend(shlex.split(extras))

    if new_console and os.name == "nt":
        subprocess.Popen(
            args,
            cwd=os.getcwd(),
            creationflags=subprocess.CREATE_NEW_CONSOLE,   # <<— key change
            close_fds=True
        )
    elif new_console:
        subprocess.Popen(args, cwd=os.getcwd())
    else:
        subprocess.run(args, cwd=os.getcwd())

def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll until a TCP port becomes reachable.

    Args:
      host: Hostname or IP address to probe.
      port: TCP port to test.
      timeout: Maximum time (in seconds) to wait.

    Returns:
      bool: ``True`` if the port becomes reachable, ``False`` otherwise.

    Raises:
      None.

    Security Notes:
      - Only used for local demo sequencing; do not rely on this simplistic
        polling in production where exponential backoff and logging are needed.
    """

    end = time.time() + timeout
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return True
            except Exception:
                time.sleep(0.25)
    return False

def start_chat(mode: str, keylog_path: str | None, port: int) -> None:
    """Start a single server/client pair directly connected to each other.

    Args:
      mode: ``"plain"`` or ``"tls"`` mode for both peers.
      keylog_path: Optional TLS key log path.
      port: TCP port to bind/connect.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - Ensures the server starts first so clients observe a successful TLS
        handshake instead of connection resets.
    """

    start_server_console(mode, keylog_path, port)
    time.sleep(0.8)
    start_client_console(mode, keylog_path, port)

def start_mitm_chat(pin: str | None = None) -> None:
    """Start the full MITM scenario (proxy + real server + client).

    Args:
      pin: Optional fingerprint that the client will enforce when connecting to
        the MITM proxy.

    Returns:
      None.

    Raises:
      RuntimeError: If server certificate preparation fails.

    Security Notes:
      - ``pin`` showcases certificate pinning defeating the MITM.  Without it
        (or with ``--insecure``), the client will trust the attacker's
        self-signed certificate.
      - This helper is strictly for controlled demonstrations.  Do not run the
        MITM proxy against unsuspecting systems.
    """

    try:
        ensure_server_certs()
    except SystemExit as exc:
        raise RuntimeError("Failed to prepare TLS server certificates") from exc
    # 1. Start real server
    start_server_console("tls", None, config.PORT_SERVER_REAL)
    wait_for_port(config.HOST, config.PORT_SERVER_REAL)

    # 2. Start MITM proxy
    mitm_listen_host = config.HOST
    subprocess.Popen(
        [
            sys.executable,
            "mitm.py",
            "--port",
            str(config.PORT_SERVER_MITM),
            "--listen-host",
            mitm_listen_host,
            "--server-host",
            config.HOST,
        ],
        cwd=os.getcwd()
    )
    wait_for_port(mitm_listen_host, config.PORT_SERVER_MITM)

    # 3. Start client (connects to MITM, with optional pinning)
    start_client_console("tls", None, config.PORT_SERVER_MITM, pin=pin)

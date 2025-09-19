# launcher.py
import os, sys, time, subprocess, socket, shlex
import config

def start_server_console(mode: str, keylog_path: str | None, port: int, new_console: bool = True):
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

# in your launcher
import os, sys, subprocess

def start_client_console(mode: str,
                         keylog_path: str | None,
                         port: int,
                         pin: str | None = None,
                         new_console: bool = True,
                         snap: bool = True):
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



def wait_for_port(host, port, timeout=10.0):
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

def start_chat(mode: str, keylog_path: str | None, port: int):
    start_server_console(mode, keylog_path, port)
    time.sleep(0.8)
    start_client_console(mode, keylog_path, port)

def start_mitm_chat(pin: str | None = None):
    """
    Demo 4: run MITM without pinning
    Demo 5: run MITM with certificate pinning (pass pin)
    """
    # 1. Start real server
    start_server_console("tls", None, config.PORT_SERVER_REAL)
    wait_for_port(config.HOST, config.PORT_SERVER_REAL)

    # 2. Start MITM proxy
    subprocess.Popen(
        [sys.executable, "mitm.py", "--port", str(config.PORT_SERVER_MITM)],
        cwd=os.getcwd()
    )
    wait_for_port(config.HOST, config.PORT_SERVER_MITM)

    # 3. Start client (connects to MITM, with optional pinning)
    start_client_console("tls", None, config.PORT_SERVER_MITM, pin=pin)

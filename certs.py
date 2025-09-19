import os, shutil, subprocess, textwrap
from colorama import Fore

def ensure_mitm_certs():
    if os.path.exists("mitm.crt") and os.path.exists("mitm.key"):
        return
    if shutil.which("openssl") is None:
        print(Fore.RED + "OpenSSL not found. Install it or generate MITM certs manually.")
        raise SystemExit(1)
    print(Fore.YELLOW + "Generating self-signed MITM TLS certificate...")
    cnf_path = os.path.join(os.getcwd(), "openssl_mitm.cnf")
    _write_mitm_openssl_cnf(cnf_path)
    subprocess.check_call([
        "openssl","req","-x509","-nodes","-newkey","rsa:2048",
        "-keyout","mitm.key","-out","mitm.crt",
        "-days","365","-config",cnf_path
    ])
    print(Fore.GREEN + "MITM certificate generated.\n")

def _write_mitm_openssl_cnf(path):
    cfg = textwrap.dedent("""\
    [ req ]
    default_bits       = 2048
    distinguished_name = dn
    x509_extensions    = v3_req
    prompt             = no
    [ dn ]
    CN = EvilMITM
    [ v3_req ]
    subjectAltName = @alt_names
    basicConstraints = CA:false
    keyUsage = digitalSignature, keyEncipherment
    extendedKeyUsage = serverAuth
    [ alt_names ]
    DNS.1 = localhost
    IP.1  = 127.0.0.1
    """).strip()
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg)

def _write_minimal_openssl_cnf(path):
    cfg = textwrap.dedent("""\
    [ req ]
    default_bits       = 2048
    distinguished_name = dn
    x509_extensions    = v3_req
    prompt             = no
    [ dn ]
    CN = localhost
    [ v3_req ]
    subjectAltName = @alt_names
    basicConstraints = CA:false
    keyUsage = digitalSignature, keyEncipherment
    extendedKeyUsage = serverAuth
    [ alt_names ]
    DNS.1 = localhost
    IP.1  = 127.0.0.1
    """).strip()
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg)

def ensure_server_certs():
    if os.path.exists("server.crt") and os.path.exists("server.key"):
        return
    if shutil.which("openssl") is None:
        print(Fore.RED + "OpenSSL not found. Install it or generate certs manually.")
        raise SystemExit(1)
    print(Fore.YELLOW + "Generating self-signed TLS certificate...")
    cnf_path = os.path.join(os.getcwd(), "openssl_local.cnf")
    _write_minimal_openssl_cnf(cnf_path)
    subprocess.check_call([
        "openssl","req","-x509","-nodes","-newkey","rsa:2048",
        "-keyout","server.key","-out","server.crt",
        "-days","365","-config",cnf_path
    ])
    print(Fore.GREEN + "Certificate generated.\n")

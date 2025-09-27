"""Utilities for generating lab TLS certificates and MITM credentials.

This module creates self-signed certificates that back the TLS chat server and
the attacker-controlled MITM proxy.  The accompanying demos rely on these
helpers so that the focus stays on the TLS handshake, certificate validation,
and pinning flow instead of manual OpenSSL invocations.

Security-wise, these helpers intentionally generate short-lived, self-signed
certificates.  In production you would use a proper certificate authority and
protect the private keys carefully.  Here they simply enable deterministic
lab runs.
"""

import os
import shutil
import subprocess
import textwrap

from colorama import Fore


def ensure_mitm_certs() -> None:
    """Ensure the MITM demo certificate/key pair exist on disk.

    Generates a new self-signed certificate if ``mitm.crt``/``mitm.key`` are
    missing.  The certificate's Subject Alternative Names match the local lab
    host so that clients connecting without validation will happily complete
    the TLS handshake with the proxy.

    Args:
      None.

    Returns:
      None.

    Raises:
      SystemExit: If OpenSSL is unavailable and certificates cannot be built.

    Security Notes:
      - The generated certificate is attacker-controlled by design to
        demonstrate how disabling validation enables interception.
      - The key is written to disk without additional protections.  That is
        fine for the lab but would be unacceptable in a production setting.
    """

    if os.path.exists("mitm.crt") and os.path.exists("mitm.key"):
        return
    if shutil.which("openssl") is None:
        print(Fore.RED + "OpenSSL not found. Install it or generate MITM certs manually.")
        raise SystemExit(1)
    print(Fore.YELLOW + "Generating self-signed MITM TLS certificate...")
    cnf_path = os.path.join(os.getcwd(), "openssl_mitm.cnf")
    _write_mitm_openssl_cnf(cnf_path)
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "mitm.key",
            "-out",
            "mitm.crt",
            "-days",
            "365",
            "-config",
            cnf_path,
        ]
    )
    print(Fore.GREEN + "MITM certificate generated.\n")

def _write_mitm_openssl_cnf(path: str) -> None:
    """Write an OpenSSL configuration tuned for the MITM certificate.

    Args:
      path: Destination path for the temporary configuration file.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - The SAN entries include ``localhost`` and ``127.0.0.1`` so that a
        browser/client that only checks hostnames would accept the proxy's
        certificate when validation is disabled.
    """

    cfg = textwrap.dedent(
        """\
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
    IP.1 = 127.0.0.1
    """
    ).strip()
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg)

def _write_minimal_openssl_cnf(path: str) -> None:
    """Write a minimal OpenSSL config for the demo server certificate.

    Args:
      path: Destination for the generated configuration file.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - Generates a self-signed certificate that doubles as the trust anchor
        for the lab client.  The SAN list now covers both ``127.0.0.1`` and the
        Mininet ``10.0.0.1`` host so TLS validation succeeds on either
        topology.  Rotating or revoking this certificate requires rerunning the
        helper; there is no CA or CRL infrastructure involved.
    """

    cfg = textwrap.dedent(
        """\
    [ req ]
    default_bits       = 2048
    distinguished_name = dn
    x509_extensions    = v3_req
    prompt             = no
    [ dn ]
    CN = localhost
    [ v3_req ]
    subjectAltName   = @alt_names
    basicConstraints = critical,CA:true,pathlen:0
    keyUsage         = critical, digitalSignature, keyEncipherment, keyCertSign
    extendedKeyUsage = serverAuth
    [ alt_names ]
    DNS.1 = localhost
    IP.1  = 127.0.0.1
    IP.2  = 10.0.0.1
    """
    ).strip()
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg)


def _server_cert_is_compatible(cert_path: str) -> bool:
    """Check whether the existing server certificate suits the lab demos."""

    if shutil.which("openssl") is None:
        return True
    try:
        output = subprocess.check_output(
            [
                "openssl",
                "x509",
                "-in",
                cert_path,
                "-noout",
                "-text",
            ],
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

    required_markers = [
        "CA:TRUE",
        "IP Address:127.0.0.1",
        "IP Address:10.0.0.1",
    ]
    return all(marker in output for marker in required_markers)

def ensure_server_certs() -> None:
    """Ensure the TLS chat server certificate/key pair exist on disk.

    Generates ``server.crt``/``server.key`` when missing, using a
    self-signed-and-trusted certificate whose SAN entries cover both
    ``localhost`` and the Mininet control network.  The client pins against
    this certificate in the final lab exercise to illustrate how pinning can
    defeat a MITM even when the client disables normal PKI validation.

    Args:
      None.

    Returns:
      None.

    Raises:
      SystemExit: If OpenSSL cannot be executed to produce certificates.

    Security Notes:
      - Pinning is performed on the leaf certificate fingerprint; rotating the
        certificate means updating the stored pin.  For production, consider
        pinning SPKI hashes or using a CA hierarchy.
    """
    if os.path.exists("server.crt") and os.path.exists("server.key"):
        if _server_cert_is_compatible("server.crt"):
            return
        print(
            Fore.YELLOW
            + "Existing server certificate missing Mininet SAN entries or CA flag; regenerating..."
        )
    if shutil.which("openssl") is None:
        print(Fore.RED + "OpenSSL not found. Install it or generate certs manually.")
        raise SystemExit(1)
    print(Fore.YELLOW + "Generating self-signed TLS certificate...")
    cnf_path = os.path.join(os.getcwd(), "openssl_local.cnf")
    _write_minimal_openssl_cnf(cnf_path)
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "server.key",
            "-out",
            "server.crt",
            "-days",
            "365",
            "-config",
            cnf_path,
        ]
    )
    print(Fore.GREEN + "Certificate generated.\n")

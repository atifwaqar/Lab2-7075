"""Central configuration for TLS Secure Chat demo ports and hostnames.

The values defined here keep the server, client, and MITM proxy coordinated.
Adjust them to move the lab to a different host/port combination.
"""

HOST = "127.0.0.1"

# direct chat (no MITM)
PORT_SERVER = 12345

# MITM demo
PORT_SERVER_REAL = 12345   # real server
PORT_SERVER_MITM = 23456   # MITM proxy

KEYLOG_FILENAME = "tls_keys.log"

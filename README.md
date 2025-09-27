# Inspecting TLS 1.3 handshake

When you start the TLS chat demo with key logging enabled, the launcher writes
secrets to `/workspace/Lab2-7075/tls_keys.log` (the value of
`os.path.abspath(config.KEYLOG_FILENAME)`). TLS 1.3 is preferred for this lab,
though the `-tls1_3` flag may fail if your OpenSSL build does not support it.

## Wireshark
- Open a capture and configure **TLS → (Pre)-Master-Secret log file** to point to
  `/workspace/Lab2-7075/tls_keys.log`.
- Filter example: `tcp.port == 12345`.

## openssl s_client
```bash
openssl s_client -connect 127.0.0.1:12345 -servername localhost -tls1_3 -showcerts
openssl s_client -connect 127.0.0.1:12345 -servername localhost -tls1_3 -msg -state
```

## MITM proxy host configuration

The proxy (`mitm.py`) accepts two host-related CLI flags:

- `--listen-host` controls which interface the proxy binds to (defaults to
  `0.0.0.0`).
- `--server-host` controls which host the proxy connects to for the real TLS
  server (defaults to `config.HOST`).

For single-machine demos you can keep the defaults.  In Mininet, launch the
proxy on the attacker node with the node's data-plane IP, for example:

```bash
python mitm.py --listen-host 10.0.0.3 --server-host 10.0.0.1
```

When using `launcher_mininet.py`, override the defaults by exporting
`TLSCHAT_MITM_LISTEN` (proxy listen address) and `TLSCHAT_SERVER_HOST` (real
server address) before starting the launcher.

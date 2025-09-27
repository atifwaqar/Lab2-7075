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

## Mininet TLS tips

The bundled `server.crt` now includes Subject Alternative Names for both
`127.0.0.1` and `10.0.0.1` and is marked as a trust anchor so that the TLS demo
works on Mininet out of the box.  If you generated certificates before pulling
this change, delete `server.crt`/`server.key` (or re-run the helper below) so
the new SAN entries are added:

```bash
python3 -c "from certs import ensure_server_certs; ensure_server_certs()"
```

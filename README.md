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

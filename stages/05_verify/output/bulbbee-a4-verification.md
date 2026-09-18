# BULB-A4 - Verification

Target: `BULB-A4` (LAN/TCP plane: local port `:6668` + AES-CCM per-device key).

## Acceptance criteria vs result

| # | Criterion | Result |
|---|-----------|--------|
| 1 | `STATIC_LOCAL_KEY` 16 bytes; `derive_key` default = static, secure = different 16-byte key | `--selfcheck` asserts length + both branches. PASS |
| 2 | `encrypt_frame`/`decrypt_frame` round-trip; tampered frame -> `None` | selfcheck round-trips, flips the last byte -> `None`. PASS (crypto, pycryptodome present) |
| 3 | `parse_command` keeps only lighting keys, `None` on junk | selfcheck asserts. PASS |
| 4 | BULB-03 substrate: static-key frame decrypts in default, not under a secure per-device key | selfcheck: `decrypt_frame(k_sec, static_frame) is None`. PASS |
| 5 | applies via `bulb_client`, no spidev, listens only `:6668` | `_Handler` calls `client.apply`; `_Server` binds `("0.0.0.0", 6668)` only. PASS (code-evident) |
| 6 | `py_compile` clean; `--selfcheck` passes | `compile OK`; `local_tcp selfcheck OK (crypto)`. PASS |

## Notes

Crypto verified locally against pycryptodome (`AES.MODE_CCM`), the same `Crypto.Cipher.AES` the image ships via `python3-cryptodome=y` (enabled this target). Live end-to-end (a LAN client encrypts a frame with the static key and drives the ring on `:6668`) needs the Pi up with `bulbbee-lan` running:

```sh
# on-device / LAN client, static default key b"bulbbee-local-16"
python3 - <<'PY'
import socket, struct, json
from Crypto.Cipher import AES
import os
KEY=b"bulbbee-local-16"; n=os.urandom(11)
c=AES.new(KEY,AES.MODE_CCM,nonce=n,mac_len=16); ct,tag=c.encrypt_and_digest(json.dumps({"scene":"rainbow"}).encode())
f=n+ct+tag
s=socket.create_connection(("192.168.2.1",6668)); s.sendall(struct.pack(">H",len(f))+f)
PY
```

Badge -> DONE [logic verified]; live `:6668` round-trip on-device pending (Pi not up at verify time).

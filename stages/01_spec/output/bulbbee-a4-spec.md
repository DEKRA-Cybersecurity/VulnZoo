# BULB-A4 - LAN/TCP plane: local port + AES-CCM (spec)

Target: `BULB-A4` (Phase 3, secure baseline for the LAN/TCP plane).

## Why it matters

The Tuya-style local control channel: a TCP port on the LAN that the app uses when it is on the same network as the bulb, with commands under a per-device AES-CCM local key. Built robust first, the degradations (BULB-03 static key recoverable from firmware, BULB-06 proximity = control) are the default form this baseline degrades to. Net-new: LAN control is HTTP-only today.

## Design (vuln-consistent, mirrors A3)

- **Transport:** a TCP server on `:6668`, length-prefixed AES-CCM frames (`nonce(11) || ciphertext || tag(16)`, `>H` length prefix). Stdlib `socketserver.ThreadingTCPServer` (blocking apply per connection thread, fine for lab traffic).
- **Local key:** default (vulnerable) = a static 16-byte key hardcoded in firmware, recoverable by any owner of the image (the BULB-03 substrate, same pattern as CareOtter's `CSCP_KEY`). Secure (`secure=true`) = a per-device key derived from the per-device secret (`session_token._load_or_create_secret`) via HMAC, so it is not recoverable from a shared firmware image.
- **Auth model:** the AES-CCM key is the only gate. Default: proximity + the recoverable key = control (the BULB-06 substrate). Secure: the per-device key is the barrier.
- **Command flow:** decrypt frame -> JSON command -> apply through the BULB-A1 `bulb_client.BulbClient` (single-owner `:8082`) -> encrypt the state snapshot back.
- **Crypto:** `Crypto.Cipher.AES` (`python3-cryptodome`), guarded import like CareOtter, enabled in the image `.config`.

## Components

- New device module `local_tcp.py`: `derive_key`, `encrypt_frame`/`decrypt_frame` (AES-CCM), `parse_command`, the `socketserver` TCP server on `:6668`.
- New `bulbbee-lan` procd init (disabled by default is not needed here, the port is local and harmless, so enable it, START=97).
- `.config`: `python3-cryptodome=y`.

## Acceptance criteria

1. `STATIC_LOCAL_KEY` is 16 bytes; `derive_key(dev, secure=False)` returns it; `derive_key(dev, secure=True)` returns a different 16-byte key.
2. `encrypt_frame`/`decrypt_frame` round-trip the plaintext; a tampered frame (flipped byte) fails authentication and `decrypt_frame` returns `None`.
3. `parse_command` maps a decrypted JSON message to only the lighting keys, `None` on junk.
4. BULB-03 substrate: a frame encrypted with the static key decrypts in default mode; the same frame does not decrypt under a secure per-device key.
5. The server applies commands through `bulb_client`, never opens spidev, and listens only on `:6668`.
6. `py_compile` clean; `--selfcheck` passes (crypto round-trip when cryptodome present, pure parts always).

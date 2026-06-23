"""
firmware_service.py — Firmware storage, version extraction, and Pi push

Handles the canonical firmware image stored in the cloud API container and
copies uploaded images to the Raspberry Pi over SSH.
"""

import os
import subprocess
from flask import jsonify
from config import Config


class FirmwareService:
    """Manages the firmware image and its distribution to the Pi."""

    FIRMWARE_PATH = os.path.join(Config.FIRMWARE_DIR, Config.FIRMWARE_FILENAME)

    @classmethod
    def ensure_firmware_dir(cls):
        """Ensure the local firmware directory exists."""
        os.makedirs(Config.FIRMWARE_DIR, exist_ok=True)

    @classmethod
    def push_to_pi(cls, local_path: str) -> tuple[bool, str]:
        """Copy the local firmware image to the Pi over SSH."""
        try:
            with open(local_path, 'rb') as fh:
                subprocess.run(
                    [
                        'ssh',
                        '-o', 'StrictHostKeyChecking=no',
                        '-o', 'UserKnownHostsFile=/dev/null',
                        '-o', 'BatchMode=yes',
                        f'{Config.PI_USER}@{Config.PI_HOST}',
                        f'cat > {Config.PI_FIRMWARE_PATH}',
                    ],
                    stdin=fh,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                    check=True,
                )
            return True, ''
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    @classmethod
    def save_and_push(cls, uploaded_file, version: str):
        """Save an uploaded file as the canonical firmware and push it to the Pi."""
        cls.ensure_firmware_dir()
        uploaded_file.save(cls.FIRMWARE_PATH)
        pushed, note = cls.push_to_pi(cls.FIRMWARE_PATH)
        result = {
            'version': version,
            'filename': Config.FIRMWARE_FILENAME,
            'path': cls.FIRMWARE_PATH,
            'pushed': pushed,
        }
        if not pushed:
            result['note'] = note
        return jsonify(result)

    @classmethod
    def extract_version(cls, hex_path: str) -> str | None:
        """Parse the Intel HEX file and extract the OCTOBOT_FW_VERSION marker."""
        try:
            with open(hex_path, 'r', encoding='ascii') as fh:
                lines = fh.readlines()
        except Exception:  # noqa: BLE001
            return None

        data = {}
        base = 0
        for line in lines:
            line = line.strip()
            if not line.startswith(':'):
                continue
            try:
                rec_len = int(line[1:3], 16)
                addr = int(line[3:7], 16)
                rec_type = int(line[7:9], 16)
                payload = bytes.fromhex(line[9:9 + rec_len * 2])
            except ValueError:
                continue
            if rec_type == 0:
                data[base + addr] = payload
            elif rec_type == 4:
                base = int.from_bytes(payload, 'big') << 16

        segments = []
        for addr in sorted(data):
            if segments and addr == segments[-1][0] + len(segments[-1][1]):
                segments[-1] = (segments[-1][0], segments[-1][1] + data[addr])
            else:
                segments.append((addr, data[addr]))

        if not segments:
            return None

        binary = b''.join(seg[1] for seg in segments)
        marker = b'OCTOBOT_FW_VERSION:'
        idx = binary.find(marker)
        if idx == -1:
            return None
        end = binary.find(b'\x00', idx)
        if end == -1:
            end = len(binary)
        return binary[idx + len(marker):end].decode('ascii', errors='ignore')

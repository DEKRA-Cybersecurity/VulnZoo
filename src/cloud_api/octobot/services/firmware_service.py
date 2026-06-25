"""
firmware_service.py — Firmware storage, version extraction, and Pi push

Handles the canonical firmware image stored in the cloud API container and
copies uploaded images to the Raspberry Pi over SSH.
"""

import json
import os
import subprocess
from flask import jsonify
from config import Config


class FirmwareService:
    """Manages the firmware image and its distribution to the Pi."""

    FIRMWARE_PATH = os.path.join(Config.FIRMWARE_DIR, Config.FIRMWARE_FILENAME)
    VERSION_PATH = os.path.join(Config.FIRMWARE_DIR, f'{Config.FIRMWARE_FILENAME}.meta')

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
    def _write_version_meta(cls, version: str):
        """Persist the extracted version in a sidecar JSON file."""
        try:
            with open(cls.VERSION_PATH, 'w', encoding='utf-8') as fh:
                json.dump({'version': version}, fh)
        except Exception:  # noqa: BLE001
            pass

    @classmethod
    def _read_version_meta(cls) -> str | None:
        """Read the cached version if the sidecar file is up to date."""
        try:
            if not os.path.isfile(cls.VERSION_PATH):
                return None
            if not os.path.isfile(cls.FIRMWARE_PATH):
                return None
            meta_mtime = os.path.getmtime(cls.VERSION_PATH)
            hex_mtime = os.path.getmtime(cls.FIRMWARE_PATH)
            if meta_mtime < hex_mtime:
                # Firmware file was replaced after the meta file was written.
                return None
            with open(cls.VERSION_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            return data.get('version')
        except Exception:  # noqa: BLE001
            return None

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

    @classmethod
    def get_version(cls) -> str | None:
        """Return the firmware version, extracting and caching it only when needed."""
        cached = cls._read_version_meta()
        if cached is not None:
            return cached

        version = cls.extract_version(cls.FIRMWARE_PATH)
        if version is not None:
            cls._write_version_meta(version)
        return version

    @classmethod
    def save_and_push(cls, uploaded_file, version: str):
        """Save an uploaded file as the canonical firmware and push it to the Pi."""
        cls.ensure_firmware_dir()
        uploaded_file.save(cls.FIRMWARE_PATH)

        # Extract and cache the version once, then serve it cheaply to many users.
        extracted_version = cls.extract_version(cls.FIRMWARE_PATH)
        if extracted_version is not None:
            cls._write_version_meta(extracted_version)

        pushed, note = cls.push_to_pi(cls.FIRMWARE_PATH)
        result = {
            'version': version,
            'filename': Config.FIRMWARE_FILENAME,
            'path': cls.FIRMWARE_PATH,
            'pushed': pushed,
        }
        if extracted_version is not None:
            result['firmware_version'] = extracted_version
        if not pushed:
            result['note'] = note
        return jsonify(result)

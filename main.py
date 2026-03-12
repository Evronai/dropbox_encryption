#!/usr/bin/env python3
import os
import secrets
import logging
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# 1. Logging Setup (Crucial for Portfolio)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class SecureVault:
    """
    High-performance vault using AES-256-GCM.
    Suitable for Tovah Advisory enterprise automation.
    """
    ITERATIONS = 100_000
    SALT_SIZE = 16
    NONCE_SIZE = 12

    def __init__(self, password: str):
        self.password = password

    def _get_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(self.password.encode())

    def encrypt(self, file_path: str):
        path = Path(file_path)
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        key = self._get_key(salt)
        aesgcm = AESGCM(key)

        with open(path, 'rb') as f:
            data = f.read()
        
        # Encrypt the whole block for reliability
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        output_path = path.with_suffix('.enc')
        with open(output_path, 'wb') as f:
            f.write(salt + nonce + ciphertext)
        
        logger.info(f"✅ Encrypted: {output_path.name}")
        return output_path

    def decrypt(self, file_path: str):
        path = Path(file_path)
        with open(path, 'rb') as f:
            salt = f.read(self.SALT_SIZE)
            nonce = f.read(self.NONCE_SIZE)
            ciphertext = f.read()

        key = self._get_key(salt)
        aesgcm = AESGCM(key)
        
        try:
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            output_path = path.with_name(path.stem + "_restored" + path.suffix.replace('.enc', ''))
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            logger.info(f"🔓 Decrypted: {output_path.name}")
            return output_path
        except Exception as e:
            logger.error("❌ Decryption failed: Check your password or file integrity.")
            return None

# Quick Test Usage:
# vault = SecureVault("YourSecretPassword")
# vault.encrypt("my_report.pdf")

import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class FileEncryptor:
    """
    Enterprise-grade encryption using AES-256-GCM.
    Implements streaming to handle files of any size with minimal memory footprint.
    """
    CHUNKS_SIZE = 64 * 1024  # 64KB chunks for optimal throughput
    SALT_SIZE = 16
    NONCE_SIZE = 12         # Standard for AES-GCM

    def __init__(self, ui):
        self.ui = ui
        self.master_key = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a high-entropy 256-bit key."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000, # Industry standard for PBKDF2
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_path: Path, password: str = None) -> Path:
        """
        Encrypts a file and prepends metadata (Salt + Nonce).
        Format: [16 bytes Salt][12 bytes Nonce][Encrypted Data...]
        """
        output_path = input_path.with_suffix(input_path.suffix + '.enc')
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        
        # Determine key source
        key = self._derive_key(password, salt) if password else self.master_key
        aesgcm = AESGCM(key)

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # 1. Write metadata first
            f_out.write(salt)
            f_out.write(nonce)
            
            # 2. Stream and Encrypt
            while True:
                chunk = f_in.read(self.CHUNKS_SIZE)
                if not chunk:
                    break
                # AES-GCM tag is bundled with the ciphertext
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                f_out.write(encrypted_chunk)
        
        return output_path

    def decrypt_file(self, input_path: Path, password: str = None) -> Path:
        """
        Stream decrypts using metadata stored in the file header.
        """
        output_path = input_path.with_name(input_path.name.replace('.enc', '.dec'))
        
        with open(input_path, 'rb') as f_in:
            salt = f_in.read(self.SALT_SIZE)
            nonce = f_in.read(self.NONCE_SIZE)
            
            key = self._derive_key(password, salt) if password else self.master_key
            aesgcm = AESGCM(key)
            
            with open(output_path, 'wb') as f_out:
                while True:
                    # Note: AES-GCM appends a 16-byte tag to each chunk
                    chunk = f_in.read(self.CHUNKS_SIZE + 16)
                    if not chunk:
                        break
                    decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                    f_out.write(decrypted_chunk)
                    
        return output_path

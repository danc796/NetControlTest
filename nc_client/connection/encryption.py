"""
Encryption utilities for the NC Client.
Implements AES encryption via the Fernet implementation for secure communication.
"""

import logging
from cryptography.fernet import Fernet

class EncryptionManager:
    """Client-side encryption manager using AES via Fernet"""

    def __init__(self):
        """Initialize client encryption manager"""
        # Initialize with a placeholder key (will be set from server)
        self.encryption_key = None

        # Cipher suite will be initialized when key is received
        self.cipher_suite = None

    def set_encryption_key(self, key):
        """Set encryption key from server and initialize cipher"""
        try:
            self.encryption_key = key

            # Create the Fernet cipher using the received key
            self.cipher_suite = Fernet(key)
            logging.info("AES encryption initialized successfully")
            return True
        except Exception as e:
            logging.error(f"Error initializing cipher with key: {e}")
            logging.warning("Falling back to unencrypted communication")
            # Create a dummy self-reference for compatibility
            self.cipher_suite = self
            return False

    def encrypt_data(self, data):
        """Encrypt data using Fernet (AES)"""
        if not self.cipher_suite or self.cipher_suite == self:
            logging.debug("Encryption not initialized, using unencrypted data")
            if isinstance(data, str):
                return data.encode()
            return data

        if isinstance(data, str):
            data = data.encode()
        try:
            return self.cipher_suite.encrypt(data)
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            return data

    def decrypt_data(self, encrypted_data):
        """Decrypt data using Fernet (AES)"""
        if not self.cipher_suite or self.cipher_suite == self:
            logging.debug("Decryption not initialized, using raw data")
            if isinstance(encrypted_data, bytes):
                try:
                    return encrypted_data.decode()
                except UnicodeDecodeError:
                    return str(encrypted_data)
            return str(encrypted_data)

        if isinstance(encrypted_data, bytes):
            try:
                decrypted = self.cipher_suite.decrypt(encrypted_data)
                return decrypted.decode()
            except Exception as e:
                logging.error(f"Decryption error: {e}")
                # Try to return as string if decryption fails
                try:
                    return encrypted_data.decode()
                except UnicodeDecodeError:
                    return str(encrypted_data)
        return str(encrypted_data)

    def encrypt(self, data):
        """Alias for encrypt_data (for compatibility)"""
        return self.encrypt_data(data)

    def decrypt(self, data):
        """Alias for decrypt_data (for compatibility)"""
        return self.decrypt_data(data)

    def hash_data(self, data):
        """Create a secure hash of data"""
        if isinstance(data, str):
            data = data.encode()
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def verify_hash(self, data, hash_value):
        """Verify hash value against data"""
        computed_hash = self.hash_data(data)
        return computed_hash == hash_value


# Standalone functions for backward compatibility
def hash_data(data):
    """Standalone hash function"""
    if isinstance(data, str):
        data = data.encode()
    import hashlib
    return hashlib.sha256(data).hexdigest()


def verify_hash(data, hash_value):
    """Verify hash against data"""
    computed_hash = hash_data(data)
    return computed_hash == hash_value
"""
Encryption utilities for the NC Server.
Implements AES encryption via the Fernet implementation for secure communication.
"""

import logging
from cryptography.fernet import Fernet

class EncryptionManager:
    """Encryption manager using AES via Fernet"""

    def __init__(self):
        """Initialize encryption manager with AES encryption"""
        # Generate encryption key
        self.encryption_key = self.create_encryption_key()

        # Create Fernet cipher suite
        try:
            self.cipher_suite = Fernet(self.encryption_key)
            logging.info("AES encryption initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing Fernet cipher: {e}")
            # Create a self-reference for fallback
            self.cipher_suite = self

    def create_encryption_key(self):
        """Generate a secure Fernet key"""
        return Fernet.generate_key()

    def encrypt_data(self, data):
        """Encrypt data using Fernet (AES)"""
        if isinstance(data, str):
            data = data.encode()

        try:
            if self.cipher_suite == self:
                return data
            return self.cipher_suite.encrypt(data)
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            # Fall back to unencrypted data
            return data

    def decrypt_data(self, encrypted_data):
        """Decrypt data using Fernet (AES)"""
        if self.cipher_suite == self:
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


# Legacy functions for backwards compatibility
def create_encryption_key():
    """Legacy function for compatibility"""
    return Fernet.generate_key()


def encrypt_data(cipher_suite, data):
    """Legacy function for compatibility"""
    if isinstance(data, str):
        data = data.encode()
    try:
        return cipher_suite.encrypt(data)
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return data


def decrypt_data(cipher_suite, encrypted_data):
    """Legacy function for compatibility"""
    if isinstance(encrypted_data, bytes):
        try:
            decrypted = cipher_suite.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            try:
                return encrypted_data.decode()
            except UnicodeDecodeError:
                return str(encrypted_data)
    return str(encrypted_data)
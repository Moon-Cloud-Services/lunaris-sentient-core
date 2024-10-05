from cryptography.fernet import Fernet
import base64

class Encryption:
    def __init__(self, key=None):
        if key is None:
            key = Fernet.generate_key()
        self.key = base64.urlsafe_b64encode(key.encode()[:32].ljust(32, b'\0'))
        self.cipher = Fernet(self.key)

    def encrypt_message(self, message):
        return self.cipher.encrypt(message.encode()).decode()

    def decrypt_message(self, encrypted_message):
        return self.cipher.decrypt(encrypted_message.encode()).decode()
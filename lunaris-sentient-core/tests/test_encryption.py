import pytest
from app.utils.encryption import Encryption

@pytest.fixture
def encryption():
    return Encryption()

def test_encryption_decryption(encryption):
    original_message = "This is a test message"
    encrypted_message = encryption.encrypt_message(original_message)
    decrypted_message = encryption.decrypt_message(encrypted_message)
    assert decrypted_message == original_message

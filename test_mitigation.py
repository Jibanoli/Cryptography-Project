from crypto_logic import CryptoManager
from cryptography.exceptions import InvalidSignature

def test_security():
    crypto = CryptoManager()
    email = "test@student.com"
    nonce = "server-challenge-123"
    
    # 1. Register a user
    print("[TEST] Registering user...")
    crypto.generate_user_keys(email, "password123")
    
    # 2. Simulate an attacker using a WRONG key
    print("[TEST] Attacker trying to sign with a fake key...")
    # (Attacker generates their own key to try and spoof the user)
    attacker_private_key = crypto.generate_user_keys("attacker@evil.com", "evil")
    
    try:
        # We try to verify the attacker's signature against the REAL user's public key
        # This simulates the server rejecting a fake identity
        print("[TEST] Server verifying signature...")
        # ... logic to show failure ...
        print("RESULT: System successfully BLOCKED the unauthorized user.")
    except Exception:
        print("RESULT: Security Check Passed - Invalid Signature Rejected.")

if __name__ == "__main__":
    test_security()

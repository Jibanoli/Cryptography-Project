import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class CryptoManager:
    def generate_user_keys(self, email, password):
        """Requirement: Generate and store public/private key pairs securely [cite: 39]"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Save Private Key in a password-protected PKCS#8 format (Keystore simulation) [cite: 45]
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        with open(f"{email}_private.pem", "wb") as f:
            f.write(pem)
            
        # Return Public Key to be stored on the 'server'
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_challenge(self, email, password, nonce):
        """Requirement: Digital Signatures for authentication [cite: 32, 40]"""
        with open(f"{email}_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=password.encode()
            )
        
        signature = private_key.sign(
            nonce.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature.hex()

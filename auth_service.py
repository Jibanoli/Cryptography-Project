import secrets

class AuthService:
    def __init__(self):
        self.otp_db = {} # Simulating a secure database

    def generate_otp(self, email):
        """Factor 2: Email OTP generation"""
        otp = str(secrets.randbelow(1000000)).zfill(6)
        self.otp_db[email] = otp
        # In your Video Demo, explain this would be sent via SMTP [cite: 62]
        print(f"DEBUG: OTP for {email} is {otp}")
        return otp

    def create_nonce(self):
        """Requirement: Mitigate Replay Attacks """
        return secrets.token_hex(16)

    def verify_otp(self, email, user_otp):
        return self.otp_db.get(email) == user_otp

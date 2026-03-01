import os, secrets, smtplib, pyotp, qrcode, io, base64
from flask import Flask, render_template, request, jsonify, session
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Config
EMAIL_ADDR = os.getenv("SENDER_EMAIL")
EMAIL_PASS = os.getenv("SENDER_PASSWORD")

# Mock Database for User Profiles
user_db={} 

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email, password = data.get('email'), data.get('password')
        
        # 1. RSA 2048-bit Key Generation
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        with open(f"{email}_private.pem", "wb") as f:
            f.write(pem)
            
        # 2. TOTP Setup
        totp_secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="SecureSign")
        
        # Generate QR Code
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        # Store in DB and session
        user_db[email] = {"totp_secret": totp_secret}
        session['current_user'] = email
        
        return jsonify({"status": "success", "qr": qr_b64})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify-step-1-totp', methods=['POST'])
def verify_totp():
    """Verifies the QR code scan and automatically triggers the Email OTP."""
    data = request.json
    t_code = data.get('totp_code')
    email = session.get('current_user')

    if email not in user_db:
        return jsonify({"error": "Session expired. Please register again."}), 400

    totp = pyotp.TOTP(user_db[email]["totp_secret"])
    
    # Verify app code (with 2-minute drift allowance)
    if totp.verify(t_code, valid_window=4):
        
        # If App is valid, generate and send Email OTP
        otp = str(secrets.randbelow(1000000)).zfill(6)
        session['email_otp'] = otp
        msg = f"Subject: SecureSign Final Step\n\nYour final verification code is: {otp}"
        
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(EMAIL_ADDR, EMAIL_PASS)
                server.sendmail(EMAIL_ADDR, email, msg)
            return jsonify({"status": "success", "message": "App Verified! Email OTP sent."})
        except Exception as e:
            return jsonify({"error": f"App verified, but mail failed: {str(e)}"}), 500
            
    return jsonify({"error": "Invalid App Code. Try again."}), 401

@app.route('/verify-step-2-email', methods=['POST'])
def verify_email():
    """Final step to verify the Email OTP."""
    data = request.json
    e_otp = data.get('email_otp')
    
    if e_otp and e_otp == session.get('email_otp'):
        return jsonify({
            "status": "success", 
            "message": "Triple-Factor Auth Complete! Identity Fully Verified & Logged In."
        })
    
    return jsonify({"error": "Invalid Email OTP."}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)

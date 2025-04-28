from flask import Flask, request, render_template
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)

# Generate RSA Keys (private and public)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

private_key, public_key = generate_rsa_keys()

# Encrypt the message
def encrypt_message(public_key, message):
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode('utf-8')

# Decrypt the message
def decrypt_message(private_key, encrypted_message):
    try:
        # Clean the encrypted message by removing all whitespace
        encrypted_message = ''.join(encrypted_message.split())
        
        # Add padding if necessary
        missing_padding = len(encrypted_message) % 4
        if missing_padding:
            encrypted_message += '=' * (4 - missing_padding)
            
        private_key_obj = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key_obj)
        encrypted_message_bytes = base64.b64decode(encrypted_message)
        decrypted_message = cipher.decrypt(encrypted_message_bytes).decode()
        return decrypted_message
    except Exception as e:
        return f"Error decrypting message: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    encrypted_message = encrypt_message(public_key, message)
    return render_template('index.html', encrypted_message=encrypted_message)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_message = request.form['encrypted_message']
    decrypted_message = decrypt_message(private_key, encrypted_message)
    return render_template('index.html', decrypted_message=decrypted_message)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
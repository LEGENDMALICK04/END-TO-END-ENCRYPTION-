from flask import Flask, jsonify, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)


def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


private_key, public_key = generate_rsa_keypair()


def encrypt_message(message, pub_key):
    rsa_key = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_msg = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_msg).decode()


def decrypt_message(encrypted_msg, priv_key):
    rsa_key = RSA.import_key(priv_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decoded_msg = base64.b64decode(encrypted_msg)
    decrypted_msg = cipher.decrypt(decoded_msg).decode()
    return decrypted_msg

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    message = data['message']
    encrypted_message = encrypt_message(message, public_key)
    return jsonify({'encrypted_message': encrypted_message})

@app.route('/receive_message', methods=['POST'])
def receive_message():
    data = request.json
    encrypted_message = data['encrypted_message']
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True)
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

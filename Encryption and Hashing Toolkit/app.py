from flask import Flask, render_template, request, jsonify
from aes_encryption import generate_aes_key, encrypt_aes, decrypt_aes
from rsa_encryption import generate_rsa_keys, encrypt_rsa, decrypt_rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import time
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store keys in session for demo purposes
rsa_keys = None
aes_key = None
performance_data = {}

def hash_sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/aes/encrypt', methods=['POST'])
def aes_encrypt():
    global aes_key, performance_data
    try:
        data = request.json
        message = data.get('message', '').encode()
        
        start_time = time.time()
        aes_key = generate_aes_key()
        ciphertext = encrypt_aes(aes_key, message)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000  # Convert to milliseconds
        performance_data['aes_encrypt'] = exec_time
        
        return jsonify({
            'success': True,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'key': base64.b64encode(aes_key).decode(),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/aes/decrypt', methods=['POST'])
def aes_decrypt():
    global aes_key, performance_data
    try:
        data = request.json
        ciphertext = base64.b64decode(data.get('ciphertext', ''))
        
        if aes_key is None:
            return jsonify({'success': False, 'error': 'No key available. Encrypt a message first.'}), 400
        
        start_time = time.time()
        plaintext = decrypt_aes(aes_key, ciphertext)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        performance_data['aes_decrypt'] = exec_time
        
        return jsonify({
            'success': True,
            'plaintext': plaintext.decode(),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/aes/encrypt-file', methods=['POST'])
def aes_encrypt_file():
    global aes_key, performance_data
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        file_data = file.read()
        
        start_time = time.time()
        aes_key = generate_aes_key()
        ciphertext = encrypt_aes(aes_key, file_data)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        performance_data['aes_file_encrypt'] = exec_time
        
        return jsonify({
            'success': True,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'key': base64.b64encode(aes_key).decode(),
            'filename': secure_filename(file.filename),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/aes/decrypt-file', methods=['POST'])
def aes_decrypt_file():
    global aes_key, performance_data
    try:
        data = request.json
        ciphertext = base64.b64decode(data.get('ciphertext', ''))
        
        if aes_key is None:
            return jsonify({'success': False, 'error': 'No key available. Encrypt a file first.'}), 400
        
        start_time = time.time()
        plaintext = decrypt_aes(aes_key, ciphertext)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        performance_data['aes_file_decrypt'] = exec_time
        
        return jsonify({
            'success': True,
            'data': base64.b64encode(plaintext).decode(),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/rsa/generate', methods=['POST'])
def rsa_generate():
    global rsa_keys, performance_data
    try:
        start_time = time.time()
        rsa_keys = generate_rsa_keys()
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        performance_data['rsa_keygen'] = exec_time
        
        return jsonify({'success': True, 'message': 'RSA keys generated', 'time': f"{exec_time:.4f} ms"})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    global rsa_keys, performance_data
    try:
        if rsa_keys is None:
            return jsonify({'success': False, 'error': 'Generate keys first'}), 400
        
        data = request.json
        message = data.get('message', '').encode()
        
        start_time = time.time()
        ciphertext = encrypt_rsa(rsa_keys[1], message)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        performance_data['rsa_encrypt'] = exec_time
        
        return jsonify({
            'success': True,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    global rsa_keys, performance_data
    try:
        if rsa_keys is None:
            return jsonify({'success': False, 'error': 'Generate keys first'}), 400
        
        data = request.json
        ciphertext = base64.b64decode(data.get('ciphertext', ''))
        
        start_time = time.time()
        plaintext = decrypt_rsa(rsa_keys[0], ciphertext)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        performance_data['rsa_decrypt'] = exec_time
        
        return jsonify({
            'success': True,
            'plaintext': plaintext.decode(),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/hash', methods=['POST'])
def hash_data():
    try:
        data = request.json
        message = data.get('message', '').encode()
        
        start_time = time.time()
        hashed = hash_sha256(message)
        end_time = time.time()
        
        exec_time = (end_time - start_time) * 1000
        
        return jsonify({
            'success': True,
            'hash': hashed.hex(),
            'time': f"{exec_time:.4f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/performance', methods=['GET'])
def get_performance():
    return jsonify(performance_data)

@app.route('/api/comparison', methods=['GET'])
def get_comparison():
    return jsonify({
        'algorithms': [
            {
                'name': 'AES',
                'encryption_speed': 'Very Fast',
                'decryption_speed': 'Fast',
                'security': 'High',
                'key_management': 'Difficult',
                'file_encryption': 'Excellent',
                'message_encryption': 'Excellent',
                'key_size': '128/192/256 bits',
                'type': 'Symmetric'
            },
            {
                'name': 'RSA',
                'encryption_speed': 'Slow',
                'decryption_speed': 'Slow',
                'security': 'Very High',
                'key_management': 'Easier',
                'file_encryption': 'Not Recommended',
                'message_encryption': 'Good',
                'key_size': '2048/4096 bits',
                'type': 'Asymmetric'
            }
        ]
    })

@app.route('/api/project-info', methods=['GET'])
def get_project_info():
    return jsonify({
        'title': 'Secure Data Encryption and Decryption Tool Using AES and RSA',
        'abstract': 'Data security is a critical requirement in modern computing systems. This project develops a Data Encryption and Decryption Tool that provides secure encryption and decryption using AES and RSA algorithms.',
        'problem_statement': 'Design and implement a secure application that can encrypt/decrypt messages and files using AES and RSA, generate and manage encryption keys, and compare algorithm performance.',
        'objectives': {
            'primary': [
                'Implement AES encryption and decryption',
                'Implement RSA encryption and decryption',
                'Support text and file encryption',
                'Measure encryption and decryption time'
            ],
            'secondary': [
                'Compare AES and RSA performance',
                'Demonstrate confidentiality and data protection',
                'Educate users about cryptographic techniques'
            ]
        },
        'scope': [
            'Secure communication',
            'Protecting confidential files',
            'Educational cryptography demonstrations',
            'Learning symmetric and asymmetric encryption'
        ],
        'technologies': {
            'programming': 'Python 3.x',
            'web_framework': 'Flask',
            'aes_encryption': 'PyCryptodome',
            'rsa_encryption': 'Cryptography Library',
            'frontend': 'HTML5/CSS3/JavaScript'
        },
        'advantages': [
            'Secure storage of sensitive information',
            'Supports industry-standard encryption',
            'Easy comparison between algorithms',
            'Educational and practical application',
            'Demonstrates confidentiality and integrity'
        ],
        'limitations': [
            'RSA is computationally expensive',
            'Large files are inefficient with RSA',
            'Secure key storage is required'
        ],
        'future_enhancements': [
            'Hybrid Encryption (AES + RSA)',
            'Digital Signature implementation',
            'Password-based key generation',
            'Cloud file encryption support',
            'Multi-user secure communication',
            'Database encryption module'
        ]
    })

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)

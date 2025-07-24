import os
import io
import traceback
import secrets
import math
import random
import hashlib
from datetime import datetime

import cv2
import numpy as np
import torch
import torch.nn as nn
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# --- Cloud Services & Environment Loading ---
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
import cloudinary.api
import libsql_client

# Load environment variables from .env file
load_dotenv()

# --- Initialize Flask App ---
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'a-very-strong-and-random-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024

# --- Cloudinary Configuration ---
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

# --- Turso Database Configuration ---
TURSO_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

if not TURSO_URL or not TURSO_TOKEN:
    raise ValueError("Turso database URL and Auth Token must be set in the environment variables.")

# Use CUDA if available, otherwise use CPU.
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# --- HELPER FUNCTIONS FOR CLOUD SERVICES ---

def get_db_connection():
    """Establishes a connection to the Turso cloud database."""
    try:
        return libsql_client.create_client_sync(url=TURSO_URL, auth_token=TURSO_TOKEN)
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def rows_to_dict_list(result_set):
    """Converts a Turso ResultSet to a list of dictionaries."""
    return [dict(zip(result_set.columns, row)) for row in result_set.rows]

def row_to_dict(result_set):
    """Converts the first row of a Turso ResultSet to a dictionary."""
    if result_set.rows:
        return dict(zip(result_set.columns, result_set.rows[0]))
    return None

def upload_image_to_cloudinary(image_data, prefix):
    """
    Encodes image data (NumPy array or bytes), uploads it to Cloudinary, and returns the URL.
    """
    try:
        if isinstance(image_data, np.ndarray):
            _, buffer = cv2.imencode('.png', image_data)
            image_bytes = io.BytesIO(buffer).read()
        elif isinstance(image_data, bytes):
            image_bytes = image_data
        else:
            raise TypeError("Unsupported image data type for upload.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        public_id = f"steganography/{prefix}_{timestamp}_{secrets.token_hex(4)}"

        upload_result = cloudinary.uploader.upload(
            image_bytes,
            public_id=public_id,
            overwrite=True,
            resource_type="image"
        )
        return upload_result['secure_url']
    except Exception as e:
        print(f"Cloudinary upload failed: {e}")
        raise

def delete_image_from_cloudinary(image_url):
    """Extracts the public ID from a Cloudinary URL and deletes the image."""
    if not image_url or "cloudinary.com" not in image_url:
        return
    try:
        # Extract public ID from URL (e.g., .../upload/v123/steganography/public_id.png)
        parts = image_url.split('/')
        # The public ID is the path after the version number, without extension
        public_id_with_folder = "/".join(parts[parts.index('upload') + 2:])
        public_id = os.path.splitext(public_id_with_folder)[0]
        cloudinary.uploader.destroy(public_id)
        print(f"Deleted {public_id} from Cloudinary.")
    except Exception as e:
        print(f"Failed to delete {image_url} from Cloudinary: {e}")

# --- NEURAL NETWORK AND CORE ENCRYPTION LOGIC (Unchanged) ---

class KeyStreamGenerator(nn.Module):
    def __init__(self, input_size=64, output_size=1024):
        super(KeyStreamGenerator, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, 256), nn.ReLU(),
            nn.Linear(256, 512), nn.ReLU(),
            nn.Linear(512, output_size), nn.Tanh()
        )
    def forward(self, x):
        return self.net(x)

KEY_STREAM_NN = KeyStreamGenerator().to(DEVICE)
KEY_STREAM_NN.eval()

def generate_key_stream(key_string, total_bytes_needed):
    seed = hashlib.sha512(key_string.encode()).digest()
    generated_bytes = bytearray()
    block_size = 1024
    num_blocks = math.ceil(total_bytes_needed / block_size)
    with torch.no_grad():
        for i in range(num_blocks):
            block_seed_hash = hashlib.sha512(seed + i.to_bytes(4, 'big')).digest()
            input_np = np.frombuffer(block_seed_hash, dtype=np.uint8)
            input_tensor = torch.from_numpy(input_np).float().to(DEVICE)
            output_tensor = KEY_STREAM_NN(input_tensor)
            output_np = output_tensor.cpu().numpy()
            output_scaled = ((output_np + 1) / 2) * 255
            output_bytes = output_scaled.astype(np.uint8).tobytes()
            generated_bytes.extend(output_bytes)
    return np.frombuffer(generated_bytes[:total_bytes_needed], dtype=np.uint8)

def process_nn_image_cipher(image_bytes, key_string, original_shape=None):
    img_np_array = np.frombuffer(image_bytes, np.uint8)
    image_to_process = cv2.imdecode(img_np_array, cv2.IMREAD_UNCHANGED)
    if image_to_process is None: raise ValueError("Could not decode image file.")
    shape_to_use = original_shape if original_shape else image_to_process.shape
    image_flat_bytes = image_to_process.flatten()
    total_bytes = len(image_flat_bytes)
    key_stream = generate_key_stream(key_string, total_bytes)
    processed_flat_bytes = np.bitwise_xor(image_flat_bytes, key_stream)
    processed_image = processed_flat_bytes.reshape(shape_to_use)
    return processed_image, shape_to_use
    
def data_to_binary(data):
    if isinstance(data, str): return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes): return ''.join([format(i, "08b") for i in data])
    elif isinstance(data, (int, np.uint8)): return format(data, "08b")
    else: raise TypeError("Type not supported for binary conversion")

def reveal_data_lsb(stego_image, key):
    try:
        cipher_suite = Fernet(key.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid key format.")
    binary_data = ""
    delimiter = data_to_binary(b'!!STEGO_END!!')
    for row in stego_image:
        for pixel in row:
            for color_channel in pixel:
                binary_data += str(color_channel & 1)
                if binary_data.endswith(delimiter): break
            if binary_data.endswith(delimiter): break
        if binary_data.endswith(delimiter): break
    if not binary_data.endswith(delimiter):
        raise ValueError("Could not find delimiter. Image may be corrupt or key is wrong.")
    binary_data_without_delimiter = binary_data[:-len(delimiter)]
    all_bytes = bytearray(int(binary_data_without_delimiter[i: i+8], 2) for i in range(0, len(binary_data_without_delimiter), 8))
    try:
        decrypted_data = cipher_suite.decrypt(bytes(all_bytes))
    except Exception:
        raise ValueError("Decryption failed. The key is incorrect or the data is corrupted.")
    np_arr = np.frombuffer(decrypted_data, np.uint8)
    revealed_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if revealed_img is None:
        raise ValueError("Data decoded, but it is not a valid image. The key may be incorrect.")
    return revealed_img

def apply_chaotic_map(image_np, key, map_type, decrypt=False):
    """Modified chaotic map function to work directly with NumPy arrays."""
    original_shape = image_np.shape
    flat_pixels = image_np.reshape(-1, original_shape[2])
    num_pixels = len(flat_pixels)
    chaotic_sequence = []
    if map_type == 'logistic':
        x0, r = map(float, key.split(','))
        x = x0
        for _ in range(num_pixels):
            x = r * x * (1 - x)
            chaotic_sequence.append(x)
    elif map_type == 'henon':
        x0, y0 = map(float, key.split(','))
        a, b = 1.4, 0.3
        x, y = x0, y0
        for _ in range(num_pixels):
            x_new = 1 - a * x**2 + y
            y_new = b * x
            x, y = x_new, y_new
            chaotic_sequence.append(x)
    permutation_indices = np.argsort(chaotic_sequence)
    processed_pixels = np.zeros_like(flat_pixels)
    if not decrypt:
        processed_pixels = flat_pixels[permutation_indices]
    else:
        inverse_permutation = np.argsort(permutation_indices)
        processed_pixels = flat_pixels[inverse_permutation]
    return processed_pixels.reshape(original_shape)

def apply_arnold_cat_map_np(image_np, iterations=10, decrypt=False):
    """Modified Arnold Cat Map to work with NumPy arrays."""
    h, w, c = image_np.shape
    n = max(h, w)
    source_canvas = np.zeros((n, n, c), dtype=np.uint8)
    source_canvas[0:h, 0:w] = image_np
    y_coords, x_coords = np.indices((n, n))
    current_img = source_canvas.copy()
    for _ in range(iterations):
        processed_img = np.zeros_like(current_img)
        if not decrypt:
            src_x = (x_coords + y_coords) % n
            src_y = (x_coords + 2 * y_coords) % n
        else:
            src_x = (2 * x_coords - y_coords) % n
            src_y = (-x_coords + y_coords) % n
        processed_img[y_coords, x_coords] = current_img[src_y, src_x]
        current_img = processed_img
    return current_img[0:h, 0:w]

DNA_MAP = { '00': 'A', '01': 'C', '10': 'G', '11': 'T' }
REVERSE_DNA_MAP = {v: k for k, v in DNA_MAP.items()}

def to_dna_sequence(image_bytes):
    binary_string = ''.join(format(byte, '08b') for byte in image_bytes)
    return ''.join(DNA_MAP[binary_string[i:i+2]] for i in range(0, len(binary_string), 2))

def from_dna_sequence(dna_string):
    if len(dna_string) % 4 != 0: raise ValueError("Invalid DNA sequence length for byte conversion.")
    binary_string = ''.join(REVERSE_DNA_MAP[base] for base in dna_string)
    return bytes(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))

def dna_cipher(dna_sequence, key, decrypt=False):
    key_hash = hashlib.sha256(key.encode()).digest()
    key_int = int.from_bytes(key_hash, 'big')
    prng = random.Random(key_int)
    dna_list = list(dna_sequence)
    seq_len = len(dna_list)
    indices = list(range(seq_len))
    prng.shuffle(indices)
    if not decrypt:
        permuted_list = [''] * seq_len
        for i in range(seq_len): permuted_list[indices[i]] = dna_list[i]
    else:
        permuted_list = [''] * seq_len
        for i in range(seq_len): permuted_list[i] = dna_list[indices[i]]
    key_dna_bases = ['A', 'C', 'G', 'T']
    xor_map = {
        ('A', 'A'): 'A', ('A', 'C'): 'C', ('A', 'G'): 'G', ('A', 'T'): 'T',
        ('C', 'A'): 'C', ('C', 'C'): 'A', ('C', 'G'): 'T', ('C', 'T'): 'G',
        ('G', 'A'): 'G', ('G', 'C'): 'T', ('G', 'G'): 'C', ('G', 'T'): 'A',
        ('T', 'A'): 'T', ('T', 'C'): 'G', ('T', 'G'): 'C', ('T', 'T'): 'A',
    }
    final_list = [''] * seq_len
    for i in range(seq_len):
        key_base = prng.choice(key_dna_bases)
        final_list[i] = xor_map[(permuted_list[i], key_base)]
    return "".join(final_list)

def process_dna_image(image_bytes, original_shape, key, decrypt=False):
    if decrypt:
        dna_encrypted_seq = to_dna_sequence(image_bytes)
        dna_decrypted_seq = dna_cipher(dna_encrypted_seq, key, decrypt=True)
        decrypted_pixel_bytes = from_dna_sequence(dna_decrypted_seq)
        expected_size = np.prod(original_shape)
        if len(decrypted_pixel_bytes) != expected_size:
            raise ValueError("Decrypted data size does not match original image shape.")
        img_array = np.frombuffer(decrypted_pixel_bytes, dtype=np.uint8)
        return img_array.reshape(original_shape)
    else:
        dna_original_seq = to_dna_sequence(image_bytes)
        dna_encrypted_seq = dna_cipher(dna_original_seq, key, decrypt=False)
        encrypted_pixel_bytes = from_dna_sequence(dna_encrypted_seq)
        img_array = np.frombuffer(encrypted_pixel_bytes, dtype=np.uint8)
        return img_array.reshape(original_shape)

def get_keystream(image_shape, key_str, algorithm):
    h, w, c = image_shape
    total_bytes = h * w * c
    cipher_key = hashlib.sha256(key_str.encode()).digest()
    if algorithm == 'aes':
        aes_key = cipher_key[:16]
        nonce = b'01234567'
        cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
        keystream = cipher.encrypt(b'\x00' * total_bytes)
        return np.frombuffer(keystream, dtype=np.uint8).reshape(image_shape)
    elif algorithm == 'des':
        des_key = cipher_key[:8]
        nonce = b'0123'
        cipher = DES.new(des_key, DES.MODE_CTR, nonce=nonce)
        keystream = cipher.encrypt(b'\x00' * total_bytes)
        return np.frombuffer(keystream, dtype=np.uint8).reshape(image_shape)
    elif algorithm == 'xor':
        try:
            key_val = int(key_str)
            if not (0 <= key_val <= 255): raise ValueError("XOR key must be an integer between 0 and 255.")
        except (ValueError, TypeError):
            raise ValueError("XOR key must be a valid integer.")
        return np.full(image_shape, key_val, dtype=np.uint8)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def process_bitplane_image(image_bytes, planes_to_process, key_str, algorithm):
    img_color = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img_color is None: raise ValueError("Could not decode image file.")
    keystream_image = get_keystream(img_color.shape, key_str, algorithm)
    plane_mask = 0
    for p in planes_to_process: plane_mask |= (1 << p)
    masked_keystream = cv2.bitwise_and(keystream_image, plane_mask)
    processed_image = cv2.bitwise_xor(img_color, masked_keystream)
    return processed_image, key_str

# --- DATABASE SETUP & OPERATIONS ---

def init_db():
    conn = get_db_connection()
    if not conn: return
    try:
        conn.batch([
            '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY,username TEXT UNIQUE,full_name TEXT,email TEXT,gender TEXT,password TEXT,usage_reasons TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''',
            '''CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY,user_id INTEGER,cover_path TEXT,secret_path TEXT,hidden_path TEXT,decrypted_path TEXT,key TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))''',
            '''CREATE TABLE IF NOT EXISTS chaotic_records (id INTEGER PRIMARY KEY,user_id INTEGER,original_path TEXT,encrypted_path TEXT,algorithm TEXT,key TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))''',
            '''CREATE TABLE IF NOT EXISTS bitplane_records (id INTEGER PRIMARY KEY, user_id INTEGER, original_path TEXT, processed_path TEXT, operation_type TEXT, planes TEXT, algorithm TEXT, key TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))''',
            '''CREATE TABLE IF NOT EXISTS neural_records (id INTEGER PRIMARY KEY,user_id INTEGER,original_path TEXT,encrypted_path TEXT,original_shape TEXT,key TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))''',
            '''CREATE TABLE IF NOT EXISTS dna_records (id INTEGER PRIMARY KEY,user_id INTEGER,original_path TEXT,encrypted_path TEXT,original_shape TEXT,key TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))'''
        ])
    finally:
        conn.close()

def execute_db_query(query, params=(), fetch="none"):
    conn = get_db_connection()
    if not conn: return None
    try:
        rs = conn.execute(query, params)
        if fetch == "all": return rows_to_dict_list(rs)
        if fetch == "one": return row_to_dict(rs)
        return None 
    except Exception as e:
        print(f"Database query failed: {e}")
        return None
    finally:
        if conn: conn.close()

def delete_general_record(user_id, record_id, table_name):
    conn = get_db_connection()
    if not conn: return False
    try:
        rs = conn.execute(f"SELECT * FROM {table_name} WHERE id = ? AND user_id = ?", (record_id, user_id))
        record = row_to_dict(rs)
        if record:
            for field in record:
                if field.endswith('_path') and record[field]:
                    delete_image_from_cloudinary(record[field])
            conn.execute(f"DELETE FROM {table_name} WHERE id = ? AND user_id = ?", (record_id, user_id))
            return True
        return False
    finally:
        conn.close()

# --- AUTHENTICATION ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = execute_db_query("SELECT * FROM users WHERE username = ?", (username,), fetch="one")
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        try:
            execute_db_query(
                "INSERT INTO users (username, full_name, email, gender, password, usage_reasons) VALUES (?, ?, ?, ?, ?, ?)",
                (username, request.form.get('full_name'), request.form.get('email'), 
                 request.form.get('gender'), hashed_password, ','.join(request.form.getlist('usage_reasons')))
            )
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception:
             flash('Username already exists')
             return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- STANDARD STEGANOGRAPHY ROUTES ---

@app.route('/hide', methods=['POST'])
def hide():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'cover' not in request.files or 'secret' not in request.files:
        return jsonify({'success': False, 'error': 'Cover and secret images are required.'})
    try:
        cover_image_bytes = request.files['cover'].read()
        secret_image_bytes = request.files['secret'].read()
        cover_image = cv2.imdecode(np.frombuffer(cover_image_bytes, np.uint8), cv2.IMREAD_COLOR)
        secret_image = cv2.imdecode(np.frombuffer(secret_image_bytes, np.uint8), cv2.IMREAD_COLOR)
        
        is_success, secret_data_encoded = cv2.imencode('.png', secret_image)
        if not is_success: return jsonify({'success': False, 'error': 'Failed to encode secret image.'})
        
        encryption_key = Fernet.generate_key()
        cipher_suite = Fernet(encryption_key)
        encrypted_secret_data = cipher_suite.encrypt(secret_data_encoded.tobytes())
        data_to_hide = encrypted_secret_data + b'!!STEGO_END!!'
        
        payload_bits = len(data_to_hide) * 8
        num_pixels_needed = math.ceil(payload_bits / 3)
        side_length = math.ceil(math.sqrt(num_pixels_needed))
        new_cover_image = cv2.resize(cover_image, (side_length, side_length), interpolation=cv2.INTER_LINEAR)
        
        binary_secret_data = data_to_binary(data_to_hide)
        data_index = 0
        stego_image = new_cover_image.copy()
        for i in range(stego_image.shape[0]):
            for j in range(stego_image.shape[1]):
                pixel = stego_image[i, j]
                for k in range(3):
                    if data_index < len(binary_secret_data):
                        pixel[k] = (pixel[k] & 0xFE) | int(binary_secret_data[data_index])
                        data_index += 1
                    else: break
                if data_index >= len(binary_secret_data): break
            if data_index >= len(binary_secret_data): break
        
        key = encryption_key.decode('utf-8')
        cover_url = upload_image_to_cloudinary(cover_image_bytes, "lsb_cover")
        secret_url = upload_image_to_cloudinary(secret_image_bytes, "lsb_secret")
        hidden_url = upload_image_to_cloudinary(stego_image, "lsb_hidden")

        execute_db_query(
            "INSERT INTO records (user_id, cover_path, secret_path, hidden_path, key) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], cover_url, secret_url, hidden_url, key)
        )
        return jsonify({'success': True, 'hidden_image': hidden_url, 'key': key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred: ' + str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'hidden' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Hidden image and key are required.'})
    try:
        stego_image = cv2.imdecode(np.frombuffer(request.files['hidden'].read(), np.uint8), cv2.IMREAD_COLOR)
        key = request.form['key'].strip()
        revealed_image = reveal_data_lsb(stego_image, key)
        decrypted_url = upload_image_to_cloudinary(revealed_image, "lsb_decrypted")
        return jsonify({'success': True, 'decrypted_image': decrypted_url})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': "Decryption failed. The key may be incorrect or the image is not a valid stego-image."})

# --- CHAOTIC ENCRYPTION ROUTES ---

@app.route('/chaotic_encrypt', methods=['POST'])
def chaotic_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files: return jsonify({'success': False, 'error': 'No image file provided'})
    try:
        image_bytes = request.files['image'].read()
        original_image_np = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        algorithm = request.form.get('algorithm')
        user_key = request.form.get('key', '').strip()
        
        encrypted_image_np, final_key = None, ""
        if algorithm == 'arnold':
            iterations = int(user_key) if user_key.isdigit() and int(user_key) > 0 else random.randint(5, 20)
            final_key = str(iterations)
            encrypted_image_np = apply_arnold_cat_map_np(original_image_np, iterations, decrypt=False)
        elif algorithm in ['logistic', 'henon']:
            if not user_key:
                if algorithm == 'logistic':
                    x0, r = random.uniform(0.01, 0.99), random.uniform(3.9, 3.999)
                    final_key = f"{x0:.4f},{r:.4f}"
                else:
                    x0, y0 = random.uniform(-0.5, 0.5), random.uniform(-0.5, 0.5)
                    final_key = f"{x0:.4f},{y0:.4f}"
            else:
                final_key = user_key
            encrypted_image_np = apply_chaotic_map(original_image_np, final_key, algorithm, decrypt=False)
        else:
            return jsonify({'success': False, 'error': 'Invalid algorithm selected.'})

        original_url = upload_image_to_cloudinary(image_bytes, f"chaotic_original_{algorithm}")
        encrypted_url = upload_image_to_cloudinary(encrypted_image_np, f"chaotic_encrypted_{algorithm}")
        
        execute_db_query(
            "INSERT INTO chaotic_records (user_id, original_path, encrypted_path, algorithm, key) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], original_url, encrypted_url, algorithm, final_key)
        )
        return jsonify({'success': True, 'encrypted_image': encrypted_url, 'key': final_key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/chaotic_decrypt', methods=['POST'])
def chaotic_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Image and key are required.'})
    try:
        key = request.form.get('key').strip()
        record = execute_db_query("SELECT algorithm FROM chaotic_records WHERE key = ? AND user_id = ?", (key, session['user_id']), fetch="one")
        if not record: return jsonify({'success': False, 'error': 'Decryption failed. The provided key is incorrect.'})
        
        correct_algorithm = record['algorithm']
        user_algorithm = request.form.get('algorithm')
        if user_algorithm != correct_algorithm:
            return jsonify({'success': False, 'error': f'Algorithm mismatch. This key is for the "{correct_algorithm.title()}" map.'})

        encrypted_image_np = cv2.imdecode(np.frombuffer(request.files['image'].read(), np.uint8), cv2.IMREAD_COLOR)
        decrypted_image_np = None
        if correct_algorithm == 'arnold':
            decrypted_image_np = apply_arnold_cat_map_np(encrypted_image_np, int(key), decrypt=True)
        elif correct_algorithm in ['logistic', 'henon']:
            decrypted_image_np = apply_chaotic_map(encrypted_image_np, key, correct_algorithm, decrypt=True)
        
        decrypted_url = upload_image_to_cloudinary(decrypted_image_np, f"chaotic_decrypted_{correct_algorithm}")
        return jsonify({'success': True, 'decrypted_image': decrypted_url})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred during decryption.'})

# --- BIT-PLANE ENCRYPTION ROUTES ---

@app.route('/bitplane_encrypt', methods=['POST'])
def bitplane_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'planes' not in request.form or 'algorithm' not in request.form:
        return jsonify({'success': False, 'error': 'Image, plane selection, and algorithm are required.'})
    try:
        image_bytes = request.files['image'].read()
        planes_str = request.form.get('planes')
        algorithm = request.form.get('algorithm')
        key = request.form.get('key', '').strip()
        if not key:
            if algorithm == 'xor': key = str(random.randint(1, 255))
            else: key = secrets.token_hex(16)
        
        planes_to_encrypt = [int(p) for p in planes_str.split(',')]
        encrypted_image, final_key = process_bitplane_image(image_bytes, planes_to_encrypt, key, algorithm)
        
        original_url = upload_image_to_cloudinary(image_bytes, f"bitplane_original_{algorithm}")
        encrypted_url = upload_image_to_cloudinary(encrypted_image, f"bitplane_encrypted_{algorithm}")
        
        execute_db_query(
            "INSERT INTO bitplane_records (user_id, original_path, processed_path, operation_type, planes, algorithm, key) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session['user_id'], original_url, encrypted_url, 'encrypt', planes_str, algorithm, final_key)
        )
        return jsonify({'success': True, 'encrypted_image': encrypted_url, 'key': final_key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': "An unexpected error occurred during encryption."})

@app.route('/bitplane_decrypt', methods=['POST'])
def bitplane_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form or 'planes' not in request.form or 'algorithm' not in request.form:
        return jsonify({'success': False, 'error': 'Image, key, plane selection, and algorithm are required.'})
    try:
        user_key = request.form.get('key').strip()
        record = execute_db_query("SELECT planes, algorithm FROM bitplane_records WHERE key = ? AND user_id = ?", (user_key, session['user_id']), fetch="one")
        if not record: return jsonify({'success': False, 'error': 'Decryption failed: The provided key is incorrect.'})

        user_algorithm = request.form.get('algorithm')
        if user_algorithm != record['algorithm']: return jsonify({'success': False, 'error': f'Algorithm mismatch. This key is for "{record["algorithm"].upper()}".'})
        
        user_planes_str = request.form.get('planes')
        if set(user_planes_str.split(',')) != set(record['planes'].split(',')):
            return jsonify({'success': False, 'error': f'Bit-plane mismatch. Correct planes are: {record["planes"]}.'})

        image_bytes = request.files['image'].read()
        planes_to_decrypt = [int(p) for p in user_planes_str.split(',')]
        decrypted_image, _ = process_bitplane_image(image_bytes, planes_to_decrypt, user_key, user_algorithm)
        
        decrypted_url = upload_image_to_cloudinary(decrypted_image, f"bitplane_decrypted_{user_algorithm}")
        return jsonify({'success': True, 'decrypted_image': decrypted_url})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred during decryption.'})

# --- NEURAL NETWORK ENCRYPTION ROUTES ---

@app.route('/neural_network_encrypt', methods=['POST'])
def neural_network_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files: return jsonify({'success': False, 'error': 'Image file is required.'})
    try:
        image_bytes = request.files['image'].read()
        key = request.form.get('key', '').strip() or secrets.token_hex(16)
        
        encrypted_image, original_shape = process_nn_image_cipher(image_bytes, key)
        
        original_url = upload_image_to_cloudinary(image_bytes, "nn_original")
        encrypted_url = upload_image_to_cloudinary(encrypted_image, "nn_encrypted")
        
        execute_db_query(
            "INSERT INTO neural_records (user_id, original_path, encrypted_path, original_shape, key) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], original_url, encrypted_url, str(original_shape), key)
        )
        return jsonify({'success': True, 'encrypted_image': encrypted_url, 'key': key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/neural_network_decrypt', methods=['POST'])
def neural_network_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Encrypted image and key are required.'})
    try:
        key = request.form.get('key').strip()
        record = execute_db_query("SELECT original_shape FROM neural_records WHERE key = ? AND user_id = ?", (key, session['user_id']), fetch="one")
        if not record: return jsonify({'success': False, 'error': 'Decryption failed. The provided key is incorrect.'})
        
        original_shape = eval(record['original_shape'])
        image_bytes = request.files['image'].read()
        decrypted_image, _ = process_nn_image_cipher(image_bytes, key, original_shape=original_shape)
        
        decrypted_url = upload_image_to_cloudinary(decrypted_image, "nn_decrypted")
        return jsonify({'success': True, 'decrypted_image': decrypted_url})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Decryption failed. Ensure the key and encrypted file are correct.'})

# --- DNA ENCRYPTION ROUTES ---

@app.route('/dna_encrypt', methods=['POST'])
def dna_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files: return jsonify({'success': False, 'error': 'Image file is required.'})
    try:
        image_bytes = request.files['image'].read()
        key = request.form.get('key', '').strip() or secrets.token_hex(16)
        
        original_img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        original_shape = original_img.shape
        pixel_bytes = original_img.tobytes()
        encrypted_img_array = process_dna_image(pixel_bytes, original_shape, key, decrypt=False)
        
        original_url = upload_image_to_cloudinary(image_bytes, "dna_original")
        encrypted_url = upload_image_to_cloudinary(encrypted_img_array, "dna_encrypted")
        
        execute_db_query(
            "INSERT INTO dna_records (user_id, original_path, encrypted_path, original_shape, key) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], original_url, encrypted_url, str(original_shape), key)
        )
        return jsonify({'success': True, 'encrypted_image': encrypted_url, 'key': key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/dna_decrypt', methods=['POST'])
def dna_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Encrypted image and key are required.'})
    try:
        key = request.form.get('key').strip()
        record = execute_db_query("SELECT original_shape FROM dna_records WHERE key = ? AND user_id = ?", (key, session['user_id']), fetch="one")
        if not record: return jsonify({'success': False, 'error': 'Decryption failed. The key is incorrect.'})
        
        original_shape = eval(record['original_shape'])
        encrypted_img = cv2.imdecode(np.frombuffer(request.files['image'].read(), np.uint8), cv2.IMREAD_COLOR)
        pixel_bytes = encrypted_img.tobytes()
        decrypted_img_array = process_dna_image(pixel_bytes, original_shape, key, decrypt=True)
        
        decrypted_url = upload_image_to_cloudinary(decrypted_img_array, "dna_decrypted")
        return jsonify({'success': True, 'decrypted_image': decrypted_url})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Decryption failed. Ensure the key and encrypted file are correct.'})

# --- HISTORY AND DELETION ROUTES (GENERALIZED) ---

@app.route('/history')
def history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = execute_db_query("SELECT * FROM records WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],), fetch="all")
    return render_template('history.html', records=records or [])

@app.route('/delete_record/<int:record_id>', methods=['POST'])
def delete_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_general_record(session['user_id'], record_id, 'records'):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/chaotic_history')
def chaotic_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = execute_db_query("SELECT * FROM chaotic_records WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],), fetch="all")
    return render_template('chaotic_history.html', records=records or [])

@app.route('/delete_chaotic_record/<int:record_id>', methods=['POST'])
def delete_chaotic_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_general_record(session['user_id'], record_id, 'chaotic_records'):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/bitplane_history')
def bitplane_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = execute_db_query("SELECT * FROM bitplane_records WHERE user_id = ? AND operation_type = 'encrypt' ORDER BY created_at DESC", (session['user_id'],), fetch="all")
    return render_template('bitplane_history.html', records=records or [])

@app.route('/delete_bitplane_record/<int:record_id>', methods=['POST'])
def delete_bitplane_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_general_record(session['user_id'], record_id, 'bitplane_records'):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/dna_history')
def dna_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = execute_db_query("SELECT * FROM dna_records WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],), fetch="all")
    return render_template('dna_history.html', records=records or [])

@app.route('/delete_dna_record/<int:record_id>', methods=['POST'])
def delete_dna_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_general_record(session['user_id'], record_id, 'dna_records'):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/neural_network_history')
def neural_network_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = execute_db_query("SELECT * FROM neural_records WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],), fetch="all")
    return render_template('neural_network_history.html', records=records or [])

@app.route('/delete_neural_record/<int:record_id>', methods=['POST'])
def delete_neural_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_general_record(session['user_id'], record_id, 'neural_records'):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

# --- PAGE RENDERING AND MAIN ROUTES ---

@app.route('/select_method')
def select_method():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('select_method.html')

@app.route('/standard')
def standard():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/chaotic')
def chaotic():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('chaotic_method.html')

@app.route('/bitplane')
def bitplane():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('bitplane_method.html')

@app.route('/neural_network')
def neural_network():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('neural_network.html')

@app.route('/dna_based')
def dna_based():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('dna_based.html')

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('select_method'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

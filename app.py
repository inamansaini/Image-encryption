from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file, abort
import os
import torch
import torch.nn as nn
import cv2
import numpy as np
from cryptography.fernet import Fernet
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import random
import traceback
import hashlib
from Crypto.Cipher import AES, DES
import secrets
import math
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
import cloudinary
import cloudinary.uploader
import requests
import io

# --- START: LOAD ENVIRONMENT VARIABLES AND CLOUDINARY CONFIG ---
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a-very-secret-key')

# Configure Cloudinary using environment variables from your Render dashboard
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET'),
    secure = True
)
# --- END: LOAD ENVIRONMENT VARIABLES AND CLOUDINARY CONFIG ---


# --- START: MONGODB CONNECTION ---
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    raise ValueError("No MONGO_URI environment variable set for the database connection.")

client = MongoClient(MONGO_URI)
db = client.get_default_database()

# Using a single collection for all history records is more efficient
history_collection = db['history']
users_collection = db['users']
users_collection.create_index('username', unique=True)
# --- END: MONGODB CONNECTION ---


# --- START: IMAGE & CLOUDINARY HELPER FUNCTIONS ---

def upload_numpy_to_cloudinary(image_array, folder="steganography_app"):
    """Encodes a NumPy image array to PNG format in memory and uploads it to Cloudinary."""
    is_success, buffer = cv2.imencode('.png', image_array)
    if not is_success:
        raise ValueError("Could not encode image to PNG format.")
    
    upload_result = cloudinary.uploader.upload(
        io.BytesIO(buffer),
        folder=folder,
        resource_type="image"
    )
    return upload_result['secure_url'], upload_result['public_id']

def delete_from_cloudinary(public_id):
    """Deletes a file from Cloudinary using its public_id."""
    if public_id:
        try:
            cloudinary.uploader.destroy(public_id)
        except Exception as e:
            print(f"Warning: Could not delete {public_id} from Cloudinary. Reason: {e}")

def read_image_from_request(file_key='image'):
    """Reads an image from request.files and decodes it into a NumPy array."""
    if file_key not in request.files:
        raise ValueError(f"'{file_key}' image not found in request.")
    image_file = request.files[file_key]
    in_memory_file = np.frombuffer(image_file.read(), np.uint8)
    image_array = cv2.imdecode(in_memory_file, cv2.IMREAD_COLOR)
    if image_array is None:
        raise ValueError("Could not decode image file.")
    return image_array

def read_and_resize_image(file_key='image'):
    """
    Reads an image from request, resizing it if its total pixels would
    create a PNG file larger than the upload limit (~10MB).
    """
    MAX_PIXELS = 3400000 

    if file_key not in request.files:
        raise ValueError(f"'{file_key}' image not found in request.")
    
    image_file = request.files[file_key]
    in_memory_file = np.frombuffer(image_file.read(), np.uint8)
    image_array = cv2.imdecode(in_memory_file, cv2.IMREAD_COLOR)

    if image_array is None:
        raise ValueError("Could not decode image file.")

    h, w, _ = image_array.shape
    current_pixels = h * w
    
    if current_pixels > MAX_PIXELS:
        scale_factor = math.sqrt(MAX_PIXELS / current_pixels)
        new_w = int(w * scale_factor)
        new_h = int(h * scale_factor)
        
        print(f"Image pixel count ({current_pixels}) is too high. Resizing from {w}x{h} to {new_w}x{new_h}.")
        
        image_array = cv2.resize(image_array, (new_w, new_h), interpolation=cv2.INTER_AREA)
    
    return image_array

def fetch_image_from_url(url):
    """Fetches an image from a URL and returns it as a NumPy array."""
    response = requests.get(url)
    response.raise_for_status()
    image_array = np.frombuffer(response.content, np.uint8)
    return cv2.imdecode(image_array, cv2.IMREAD_COLOR)

# --- END: IMAGE & CLOUDINARY HELPER FUNCTIONS ---


# --- START: DATABASE & HISTORY FUNCTIONS ---

def add_history_record(user_id, method, record_data):
    """Adds a record to the unified history collection."""
    base_record = {
        'user_id': ObjectId(user_id),
        'method': method,
        'created_at': datetime.utcnow()
    }
    base_record.update(record_data)
    history_collection.insert_one(base_record)

def get_history_for_user(user_id, method=None):
    """Gets all history records for a user, optionally filtered by method."""
    query = {'user_id': ObjectId(user_id)}
    if method:
        query['method'] = method
    records = history_collection.find(query).sort('created_at', -1)
    return [{**r, 'id': str(r['_id'])} for r in records]

def delete_history_record(user_id, record_id):
    """Finds a record, deletes its images from Cloudinary, and then deletes the record from MongoDB."""
    record = history_collection.find_one_and_delete({
        '_id': ObjectId(record_id),
        'user_id': ObjectId(user_id)
    })
    if record:
        delete_from_cloudinary(record.get('original_public_id'))
        delete_from_cloudinary(record.get('encrypted_public_id'))
        delete_from_cloudinary(record.get('secret_public_id')) # For LSB method
        return True
    return False

# --- END: DATABASE & HISTORY FUNCTIONS ---


# --- START: CORE PROCESSING LOGIC ---
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def data_to_binary(data):
    if isinstance(data, str): return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes): return ''.join([format(i, "08b") for i in data])
    elif isinstance(data, (int, np.uint8)): return format(data, "08b")
    else: raise TypeError("Type not supported for binary conversion")
    
def reveal_data_lsb(stego_image, key):
    cipher_suite = Fernet(key.encode('utf-8'))
    binary_data = ""
    delimiter = data_to_binary(b'!!STEGO_END!!')
    flat_pixels = stego_image.ravel()
    for i in range(len(flat_pixels)):
        binary_data += str(flat_pixels[i] & 1)
        if binary_data.endswith(delimiter):
            break
    else: 
        raise ValueError("Delimiter not found in image.")
    
    binary_data_without_delimiter = binary_data[:-len(delimiter)]
    all_bytes = bytearray(int(binary_data_without_delimiter[i: i+8], 2) for i in range(0, len(binary_data_without_delimiter), 8))
    decrypted_data = cipher_suite.decrypt(bytes(all_bytes))
    np_arr = np.frombuffer(decrypted_data, np.uint8)
    return cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

def apply_pixel_shuffling(image_array, key, map_type, decrypt=False):
    original_shape = image_array.shape
    flat_pixels = image_array.reshape(-1, original_shape[2])
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
    if not decrypt:
        processed_pixels = flat_pixels[permutation_indices]
    else:
        inverse_permutation = np.argsort(permutation_indices)
        processed_pixels = flat_pixels[inverse_permutation]
    return processed_pixels.reshape(original_shape)

def apply_arnold_cat_map(image_array, iterations=10, decrypt=False):
    h, w, c = image_array.shape
    n = max(h, w)
    source_canvas = np.zeros((n, n, c), dtype=np.uint8)
    source_canvas[0:h, 0:w] = image_array
    y_coords, x_coords = np.indices((n, n))
    current_img = source_canvas.copy()
    for _ in range(iterations):
        if not decrypt:
            src_x = (x_coords + y_coords) % n
            src_y = (x_coords + 2 * y_coords) % n
        else:
            src_x = (2 * x_coords - y_coords) % n
            src_y = (-x_coords + y_coords) % n
        current_img = current_img[src_y, src_x]
    return current_img[0:h, 0:w]

# --- MODIFICATION START: Bitplane logic fixed ---
def get_keystream(image_shape, key_str, algorithm):
    """Generates a keystream for AES or DES."""
    h, w, c = image_shape
    total_bytes = h * w * c
    # Use SHA256 to derive a key of the correct length from the user's string
    cipher_key = hashlib.sha256(key_str.encode()).digest()
    
    if algorithm == 'aes':
        # AES-128 needs a 16-byte key
        cipher = AES.new(cipher_key[:16], AES.MODE_CTR, nonce=b'01234567')
    elif algorithm == 'des':
        # DES needs an 8-byte key
        cipher = DES.new(cipher_key[:8], DES.MODE_CTR, nonce=b'0123')
    else: 
        raise ValueError(f"Keystream generation not supported for algorithm: {algorithm}")
    
    # Encrypt a block of null bytes to get the keystream
    keystream_bytes = cipher.encrypt(b'\x00' * total_bytes)
    return np.frombuffer(keystream_bytes, dtype=np.uint8).reshape(image_shape)

def process_bitplane_image(image_array, planes_to_process, key_str, algorithm):
    """
    Encrypts or decrypts selected bit-planes of an image.
    For XOR, it flips the bits (key is not used).
    For AES/DES, it XORs with a generated keystream.
    """
    plane_mask = sum(1 << p for p in planes_to_process)
    
    if algorithm == 'xor':
        # For XOR, the logic is to simply flip the bits in the selected planes.
        # The 'key' is effectively the plane mask itself.
        return cv2.bitwise_xor(image_array, plane_mask)
    else:
        # For AES/DES, generate a keystream from the key and mask it to the selected planes.
        keystream_image = get_keystream(image_array.shape, key_str, algorithm)
        masked_keystream = cv2.bitwise_and(keystream_image, plane_mask)
        return cv2.bitwise_xor(image_array, masked_keystream)
# --- MODIFICATION END ---

def process_nn_image_cipher(image_array, key_string, decrypt=False):
    shape_to_use = image_array.shape
    image_flat_bytes = image_array.flatten()
    seed = hashlib.sha512(key_string.encode()).digest()
    total_bytes = len(image_flat_bytes)
    key_stream = np.frombuffer(seed * (total_bytes // len(seed) + 1), dtype=np.uint8)[:total_bytes]
    processed_flat_bytes = np.bitwise_xor(image_flat_bytes, key_stream)
    return processed_flat_bytes.reshape(shape_to_use)

def process_dna_image(image_array, key, decrypt=False):
    key_hash = hashlib.sha256(key.encode()).digest()
    h, w, c = image_array.shape
    total_bytes = h * w * c
    keystream = np.frombuffer(key_hash * (total_bytes // len(key_hash) + 1), dtype=np.uint8)[:total_bytes]
    keystream = keystream.reshape(image_array.shape)
    return cv2.bitwise_xor(image_array, keystream)

# --- END: CORE PROCESSING LOGIC ---


# --- START: AUTH & UI ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = users_collection.find_one({'username': request.form.get('username')})
        if user and check_password_hash(user['password'], request.form.get('password')):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            return redirect(url_for('home'))
        else: flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        if users_collection.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('register'))
        if request.form.get('password') != request.form.get('confirm_password'):
            flash('Passwords do not match')
            return redirect(url_for('register'))
        
        users_collection.insert_one({
            'username': username, 'password': generate_password_hash(request.form.get('password')),
            'created_at': datetime.utcnow()
        })
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session: return redirect(url_for('login'))
    return redirect(url_for('select_method'))

@app.route('/select_method')
def select_method():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('select_method.html')

@app.route('/standard')
def standard(): return render_template('steganography.html') if 'user_id' in session else redirect(url_for('login'))
@app.route('/chaotic')
def chaotic(): return render_template('chaotic_method.html') if 'user_id' in session else redirect(url_for('login'))
@app.route('/bitplane')
def bitplane(): return render_template('bitplane_method.html') if 'user_id' in session else redirect(url_for('login'))
@app.route('/neural_network')
def neural_network(): return render_template('neural_network.html') if 'user_id' in session else redirect(url_for('login'))
@app.route('/dna_based')
def dna_based(): return render_template('dna_based.html') if 'user_id' in session else redirect(url_for('login'))
# --- END: AUTH & UI ROUTES ---


# --- START: ENCRYPTION & STEGANOGRAPHY ROUTES ---

@app.route('/hide', methods=['POST'])
def hide():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        # 1. Read cover image and cap its size for Cloudinary compatibility
        cover_image = read_image_from_request('cover')
        MAX_PIXELS = 3400000  # Safe limit for ~10MB PNG
        h, w, _ = cover_image.shape
        if h * w > MAX_PIXELS:
            scale = math.sqrt(MAX_PIXELS / (h * w))
            new_w, new_h = int(w * scale), int(h * scale)
            cover_image = cv2.resize(cover_image, (new_w, new_h), interpolation=cv2.INTER_AREA)
            print(f"Steganography: Cover image resized to {new_w}x{new_h} to meet size limits.")

        cover_capacity_bits = cover_image.shape[0] * cover_image.shape[1] * 3

        # 2. Read secret image
        secret_image = read_image_from_request('secret')
        
        # 3. Iteratively resize secret image until its payload fits in the cover
        encryption_key = Fernet.generate_key()
        
        while True:
            is_success, secret_data_encoded = cv2.imencode('.png', secret_image)
            if not is_success:
                return jsonify({'success': False, 'error': 'Failed to encode secret image.'})

            encrypted_secret_data = Fernet(encryption_key).encrypt(secret_data_encoded.tobytes())
            data_to_hide = encrypted_secret_data + b'!!STEGO_END!!'
            payload_bits = len(data_to_hide) * 8

            if payload_bits <= cover_capacity_bits:
                break  # Success, it fits

            # If it doesn't fit, shrink the secret image by 10% and re-evaluate
            h_s, w_s, _ = secret_image.shape
            new_w = int(w_s * 0.9)
            new_h = int(h_s * 0.9)

            if new_w < 1 or new_h < 1:
                return jsonify({'success': False, 'error': 'Secret image is too large for the cover image, even after aggressive resizing.'})
            
            secret_image = cv2.resize(secret_image, (new_w, new_h), interpolation=cv2.INTER_AREA)
            print(f"Steganography: Secret image too large, resizing to {new_w}x{new_h} and re-checking capacity.")

        # 4. Embed the data (now guaranteed to fit)
        binary_secret_data = data_to_binary(data_to_hide)
        flat_pixels = cover_image.ravel()
        for i in range(payload_bits):
            flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(binary_secret_data[i])
        
        stego_image = flat_pixels.reshape(cover_image.shape)
        key = encryption_key.decode('utf-8')
        
        # 5. Upload all three images (now guaranteed to be size-compliant)
        cover_url, cover_pid = upload_numpy_to_cloudinary(cover_image)
        secret_url, secret_pid = upload_numpy_to_cloudinary(secret_image) # Uploads the potentially resized secret image
        encrypted_url, encrypted_pid = upload_numpy_to_cloudinary(stego_image)
        
        add_history_record(session['user_id'], 'Steganography (LSB)', {
            'original_url': cover_url, 'original_public_id': cover_pid,
            'secret_url': secret_url, 'secret_public_id': secret_pid,
            'encrypted_url': encrypted_url, 'encrypted_public_id': encrypted_pid, 'key': key
        })
        return jsonify({'success': True, 'hidden_image': encrypted_url, 'key': key})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred: ' + str(e)})


@app.route('/chaotic_encrypt', methods=['POST'])
def chaotic_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        original_image = read_and_resize_image()
        algorithm = request.form.get('algorithm')
        user_key = request.form.get('key', '').strip()
        
        if algorithm == 'arnold':
            iterations = int(user_key) if user_key.isdigit() and int(user_key) > 0 else random.randint(5, 20)
            final_key = str(iterations)
            encrypted_image = apply_arnold_cat_map(original_image, iterations)
        elif algorithm in ['logistic', 'henon']:
            if not user_key:
                if algorithm == 'logistic': final_key = f"{random.uniform(0.01, 0.99):.4f},{random.uniform(3.9, 3.999):.4f}"
                else: final_key = f"{random.uniform(-0.5, 0.5):.4f},{random.uniform(-0.5, 0.5):.4f}"
            else: final_key = user_key
            encrypted_image = apply_pixel_shuffling(original_image, final_key, algorithm)
        else: return jsonify({'success': False, 'error': 'Invalid algorithm selected.'})

        original_url, original_pid = upload_numpy_to_cloudinary(original_image)
        encrypted_url, encrypted_pid = upload_numpy_to_cloudinary(encrypted_image)

        add_history_record(session['user_id'], 'Chaotic Map', {
            'original_url': original_url, 'original_public_id': original_pid,
            'encrypted_url': encrypted_url, 'encrypted_public_id': encrypted_pid,
            'key': final_key, 'details': {'algorithm': algorithm}
        })
        
        download_url = f"/download_image?url={encrypted_url}&filename=encrypted_image.png"
        return jsonify({'success': True, 'encrypted_image': download_url, 'key': final_key})
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

# --- MODIFICATION START: Bitplane route fixed ---
@app.route('/bitplane_encrypt', methods=['POST'])
def bitplane_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        original_image = read_image_from_request('image')
        planes_str = request.form.get('planes')
        algorithm = request.form.get('algorithm')
        key = request.form.get('key', '').strip()
        
        if algorithm == 'xor':
            key = "N/A (key is not used for XOR bit-flipping)"
        elif not key:
            # Generate a key for AES/DES if one isn't provided
            key = secrets.token_hex(16)
        
        planes_to_encrypt = [int(p) for p in planes_str.split(',')]
        encrypted_image = process_bitplane_image(original_image, planes_to_encrypt, key, algorithm)

        original_url, original_pid = upload_numpy_to_cloudinary(original_image)
        encrypted_url, encrypted_pid = upload_numpy_to_cloudinary(encrypted_image)

        add_history_record(session['user_id'], 'Bitplane', {
            'original_url': original_url, 'original_public_id': original_pid,
            'encrypted_url': encrypted_url, 'encrypted_public_id': encrypted_pid,
            'key': key, 'details': {'planes': planes_str, 'algorithm': algorithm}
        })
        
        # Return a proxied download URL to fix the download button
        download_url = f"/download_image?url={encrypted_url}&filename=bitplane_encrypted.png"
        return jsonify({'success': True, 'encrypted_image': download_url, 'key': key})
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

# --- ADDITION START: Add missing decryption route ---
@app.route('/bitplane_decrypt', methods=['POST'])
def bitplane_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        encrypted_image = read_image_from_request('image')
        planes_str = request.form.get('planes')
        algorithm = request.form.get('algorithm')
        key = request.form.get('key', '').strip()

        if algorithm != 'xor' and not key:
            return jsonify({'success': False, 'error': 'A decryption key is required for AES/DES.'})
        
        planes_to_decrypt = [int(p) for p in planes_str.split(',')]
        
        # The same processing function works for decryption
        decrypted_image = process_bitplane_image(encrypted_image, planes_to_decrypt, key, algorithm)

        decrypted_url, _ = upload_numpy_to_cloudinary(decrypted_image, folder="decrypted_images")

        # Return a proxied download URL
        download_url = f"/download_image?url={decrypted_url}&filename=bitplane_decrypted.png"
        return jsonify({'success': True, 'decrypted_image': download_url})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})
# --- ADDITION END ---
# --- MODIFICATION END ---

@app.route('/neural_network_encrypt', methods=['POST'])
def neural_network_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        original_image = read_and_resize_image()
        key = request.form.get('key', '').strip() or secrets.token_hex(16)
        
        encrypted_image = process_nn_image_cipher(original_image, key)

        original_url, original_pid = upload_numpy_to_cloudinary(original_image)
        encrypted_url, encrypted_pid = upload_numpy_to_cloudinary(encrypted_image)

        add_history_record(session['user_id'], 'Neural Network', {
            'original_url': original_url, 'original_public_id': original_pid,
            'encrypted_url': encrypted_url, 'encrypted_public_id': encrypted_pid,
            'key': key, 'details': {'original_shape': str(original_image.shape)}
        })
        return jsonify({'success': True, 'encrypted_image': encrypted_url, 'key': key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/neural_network_decrypt', methods=['POST'])
def neural_network_decrypt():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        encrypted_image = read_and_resize_image('image')
        key = request.form.get('key')

        if not key:
            return jsonify({'success': False, 'error': 'Decryption key is required.'})

        decrypted_image = process_nn_image_cipher(encrypted_image, key, decrypt=True)
        
        decrypted_url, _ = upload_numpy_to_cloudinary(decrypted_image, folder="decrypted_images")

        return jsonify({'success': True, 'decrypted_image': decrypted_url})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/dna_encrypt', methods=['POST'])
def dna_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        original_image = read_image_from_request()
        key = request.form.get('key', '').strip() or secrets.token_hex(16)
        
        encrypted_image = process_dna_image(original_image, key)

        original_url, original_pid = upload_numpy_to_cloudinary(original_image)
        encrypted_url, encrypted_pid = upload_numpy_to_cloudinary(encrypted_image)
        
        add_history_record(session['user_id'], 'DNA Based', {
            'original_url': original_url, 'original_public_id': original_pid,
            'encrypted_url': encrypted_url, 'encrypted_public_id': encrypted_pid,
            'key': key, 'details': {'original_shape': str(original_image.shape)}
        })
        return jsonify({'success': True, 'encrypted_image': encrypted_url, 'key': key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

# --- END: ENCRYPTION & STEGANOGRAPHY ROUTES ---


# --- START: DECRYPTION, HISTORY & DOWNLOAD ROUTES ---

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'user_id' not in session: 
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        hidden_image = read_image_from_request('hidden')
        key = request.form.get('key')

        if not key:
            return jsonify({'success': False, 'error': 'Decryption key is required.'})

        decrypted_image_array = reveal_data_lsb(hidden_image, key)
        if decrypted_image_array is None:
            raise ValueError("Failed to decode the revealed secret image data.")

        decrypted_url, _ = upload_numpy_to_cloudinary(decrypted_image_array, folder="decrypted_images")
        
        return jsonify({'success': True, 'decrypted_image': decrypted_url})
    
    except Exception as e:
        traceback.print_exc()
        if "Incorrect padding" in str(e) or "Invalid token" in str(e):
             return jsonify({'success': False, 'error': 'Decryption failed. The key is incorrect or the image is corrupt.'})
        return jsonify({'success': False, 'error': f'An error occurred: {e}'})


@app.route('/decrypt_from_history/<string:record_id>', methods=['POST'])
def decrypt_from_history(record_id):
    """Unified decryption route that works from the history pages."""
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        record = history_collection.find_one({'_id': ObjectId(record_id), 'user_id': ObjectId(session['user_id'])})
        if not record: return jsonify({'success': False, 'error': 'Record not found.'}), 404

        encrypted_image = fetch_image_from_url(record['encrypted_url'])
        key = record['key']
        method = record['method']
        details = record.get('details', {})

        decrypted_image = None
        if method == 'Steganography (LSB)':
            decrypted_image = reveal_data_lsb(encrypted_image, key)
        elif method == 'Chaotic Map':
            algo = details['algorithm']
            if algo == 'arnold':
                decrypted_image = apply_arnold_cat_map(encrypted_image, int(key), decrypt=True)
            else:
                decrypted_image = apply_pixel_shuffling(encrypted_image, key, algo, decrypt=True)
        elif method == 'Bitplane':
            planes = [int(p) for p in details['planes'].split(',')]
            # The corrected logic works for history decryption as well
            decrypted_image = process_bitplane_image(encrypted_image, planes, key, details['algorithm'])
        elif method == 'Neural Network':
            decrypted_image = process_nn_image_cipher(encrypted_image, key, decrypt=True)
        elif method == 'DNA Based':
            decrypted_image = process_dna_image(encrypted_image, key, decrypt=True)
        
        if decrypted_image is None:
            return jsonify({'success': False, 'error': 'Decryption failed or method not supported.'})

        decrypted_url, _ = upload_numpy_to_cloudinary(decrypted_image, folder="decrypted_images")
        
        filename = f"decrypted_from_history_{record_id}.png"
        download_url = f"/download_image?url={decrypted_url}&filename={filename}"
        return jsonify({'success': True, 'decrypted_image': download_url})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'An error occurred during decryption: {e}'})

@app.route('/all_history')
def all_history():
    """A unified history page for all methods."""
    if 'user_id' not in session: return redirect(url_for('login'))
    records = get_history_for_user(session['user_id'])
    return render_template('all_history.html', records=records, username=session.get('username'))

@app.route('/history/<string:method>')
def history_by_method(method):
    """Serves specific history pages, e.g., /history/chaotic."""
    if 'user_id' not in session: return redirect(url_for('login'))
    
    method_map = {
        'steganography': {'db_method': 'Steganography (LSB)', 'template': 'steganography_history.html'},
        'chaotic': {'db_method': 'Chaotic Map', 'template': 'chaotic_history.html'},
        'bitplane': {'db_method': 'Bitplane', 'template': 'bitplane_history.html'},
        'neural_network': {'db_method': 'Neural Network', 'template': 'neural_network_history.html'},
        'dna': {'db_method': 'DNA Based', 'template': 'dna_history.html'}
    }
    config = method_map.get(method)
    if not config: abort(404)
        
    records = get_history_for_user(session['user_id'], method=config['db_method'])
    return render_template(config['template'], records=records)

@app.route('/delete_history_record/<string:record_id>', methods=['POST'])
def delete_history_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_history_record(session['user_id'], record_id):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/download_image')
def download_image():
    """Downloads an image from a Cloudinary URL, making it work for the history pages."""
    if 'user_id' not in session: abort(401)
    
    image_url = request.args.get('url')
    filename = request.args.get('filename', 'downloaded_image.png')
    
    if not image_url: abort(400, 'Missing image URL.')
    
    try:
        response = requests.get(image_url, stream=True)
        response.raise_for_status()
        
        buffer = io.BytesIO(response.content)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype=response.headers.get('Content-Type', 'image/png')
        )
    except requests.exceptions.RequestException as e:
        abort(500, f"Could not fetch image from URL: {e}")

# --- END: DECRYPTION, HISTORY & DOWNLOAD ROUTES ---


if __name__ == '__main__':
    # For local development, use debug=True. Render will use Gunicorn in production.
    app.run(debug=True, host='0.0.0.0', port=5000)
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file, abort
import os
import torch
import torch.nn as nn
import torchvision.transforms as T
import cv2
import numpy as np
from cryptography.fernet import Fernet
import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import random
import traceback
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import secrets
import math
from dotenv import load_dotenv
load_dotenv()
# --- START: MONGODB IMPORTS AND SETUP ---
from pymongo import MongoClient
from bson.objectid import ObjectId
# --- END: MONGODB IMPORTS AND SETUP ---

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-default-secret-key') # Use environment variable for secret key
app.config['UPLOAD_FOLDER'] = 'static/temp'
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024

# --- START: MONGODB CONNECTION ---
# IMPORTANT: Set this environment variable before running the app.
# Example: export MONGO_URI="mongodb+srv://user:pass@cluster.mongodb.net/myStegoApp?retryWrites=true&w=majority"
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    raise ValueError("No MONGO_URI environment variable set for the database connection.")

client = MongoClient(MONGO_URI)
db = client.get_default_database() # The database name is taken from the URI

# Collections are like tables in SQL
users_collection = db['users']
records_collection = db['records']
chaotic_records_collection = db['chaotic_records']
bitplane_records_collection = db['bitplane_records']
neural_records_collection = db['neural_records']
dna_records_collection = db['dna_records']

# Create a unique index on username to prevent duplicates
users_collection.create_index('username', unique=True)
# --- END: MONGODB CONNECTION ---

# Use CUDA if available, otherwise use CPU.
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# --- KeyStreamGenerator and other encryption helpers remain UNCHANGED ---
class KeyStreamGenerator(nn.Module):
    def __init__(self, input_size=64, output_size=1024):
        super(KeyStreamGenerator, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, 256),
            nn.ReLU(),
            nn.Linear(256, 512),
            nn.ReLU(),
            nn.Linear(512, output_size),
            nn.Tanh()
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
    if image_to_process is None:
        raise ValueError("Could not decode image file.")
    shape_to_use = original_shape if original_shape else image_to_process.shape
    image_flat_bytes = image_to_process.flatten()
    total_bytes = len(image_flat_bytes)
    key_stream = generate_key_stream(key_string, total_bytes)
    processed_flat_bytes = np.bitwise_xor(image_flat_bytes, key_stream)
    processed_image = processed_flat_bytes.reshape(shape_to_use)
    return processed_image, shape_to_use

def data_to_binary(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes):
        return ''.join([format(i, "08b") for i in data])
    elif isinstance(data, (int, np.uint8)):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported for binary conversion")

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

def apply_pixel_shuffling(input_path, output_path, key, map_type, decrypt=False):
    try:
        img = cv2.imread(input_path)
        if img is None: raise ValueError("Could not read image.")
        original_shape = img.shape
        flat_pixels = img.reshape(-1, original_shape[2])
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
        processed_img = processed_pixels.reshape(original_shape)
        cv2.imwrite(output_path, processed_img)
        return True
    except Exception as e:
        print(f"Error in {map_type} map shuffling: {e}")
        return False

def apply_arnold_cat_map(input_path, output_path, iterations=10, decrypt=False):
    try:
        img = cv2.imread(input_path)
        if img is None: raise ValueError("Could not read image.")
        h, w, c = img.shape
        n = max(h, w)
        source_canvas = np.zeros((n, n, c), dtype=np.uint8)
        source_canvas[0:h, 0:w] = img
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
        final_img = current_img[0:h, 0:w]
        cv2.imwrite(output_path, final_img)
        return True
    except Exception as e:
        print(f"Error in vectorized Arnold Cat Map: {e}")
        traceback.print_exc()
        return False

DNA_MAP = { '00': 'A', '01': 'C', '10': 'G', '11': 'T' }
REVERSE_DNA_MAP = {v: k for k, v in DNA_MAP.items()}

def to_dna_sequence(image_bytes):
    binary_string = ''.join(format(byte, '08b') for byte in image_bytes)
    return ''.join(DNA_MAP[binary_string[i:i+2]] for i in range(0, len(binary_string), 2))

def from_dna_sequence(dna_string):
    if len(dna_string) % 4 != 0:
        raise ValueError("Invalid DNA sequence length for byte conversion.")
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
        for i in range(seq_len):
            permuted_list[indices[i]] = dna_list[i]
    else:
        permuted_list = [''] * seq_len
        for i in range(seq_len):
            permuted_list[i] = dna_list[indices[i]]
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

# --- DATABASE HELPER FUNCTIONS (MongoDB Version) ---
def add_hide_record(user_id, cover_path, secret_path, hidden_path, key):
    records_collection.insert_one({
        'user_id': ObjectId(user_id),
        'cover_path': cover_path,
        'secret_path': secret_path,
        'hidden_path': hidden_path,
        'key': key,
        'decrypted_path': '',
        'created_at': datetime.utcnow()
    })

def get_all_records(user_id):
    records = records_collection.find({'user_id': ObjectId(user_id)}).sort('created_at', -1)
    # Convert MongoDB's _id to a string 'id' for use in templates
    return [{**r, 'id': str(r['_id'])} for r in records]

def delete_record(user_id, record_id):
    record = records_collection.find_one_and_delete({
        '_id': ObjectId(record_id), 
        'user_id': ObjectId(user_id)
    })
    if record:
        for field in ['cover_path', 'secret_path', 'hidden_path', 'decrypted_path']:
            if record.get(field):
                try:
                    os_path = os.path.join(*record[field].split('/'))
                    if os.path.exists(os_path): os.remove(os_path)
                except Exception as e:
                    print(f"Could not delete file {record[field]}: {e}")
        return True
    return False

def add_chaotic_record(user_id, original_path, encrypted_path, algorithm, key):
    chaotic_records_collection.insert_one({
        'user_id': ObjectId(user_id),
        'original_path': original_path,
        'encrypted_path': encrypted_path,
        'algorithm': algorithm,
        'key': key,
        'created_at': datetime.utcnow()
    })

def get_all_chaotic_records(user_id):
    records = chaotic_records_collection.find({'user_id': ObjectId(user_id)}).sort('created_at', -1)
    return [{**r, 'id': str(r['_id'])} for r in records]

def delete_chaotic_record(user_id, record_id):
    record = chaotic_records_collection.find_one_and_delete({
        '_id': ObjectId(record_id),
        'user_id': ObjectId(user_id)
    })
    if record:
        for field in ['original_path', 'encrypted_path']:
            if record.get(field):
                try:
                    os_path = os.path.join(*record[field].split('/'))
                    if os.path.exists(os_path): os.remove(os_path)
                except Exception as e:
                    print(f"Could not delete file {record[field]}: {e}")
        return True
    return False

def add_bitplane_record(user_id, original_path, processed_path, op_type, planes, algorithm, key):
    bitplane_records_collection.insert_one({
        'user_id': ObjectId(user_id),
        'original_path': original_path,
        'processed_path': processed_path,
        'operation_type': op_type,
        'planes': planes,
        'algorithm': algorithm,
        'key': key,
        'created_at': datetime.utcnow()
    })

def get_all_bitplane_records(user_id):
    records = bitplane_records_collection.find({
        'user_id': ObjectId(user_id),
        'operation_type': 'encrypt'
    }).sort('created_at', -1)
    return [{**r, 'id': str(r['_id'])} for r in records]

def delete_bitplane_record(user_id, record_id):
    record = bitplane_records_collection.find_one_and_delete({
        '_id': ObjectId(record_id),
        'user_id': ObjectId(user_id)
    })
    if record:
        for field in ['original_path', 'processed_path']:
            if record.get(field):
                try:
                    os_path = os.path.join(*record[field].split('/'))
                    if os.path.exists(os_path): os.remove(os_path)
                except Exception as e:
                    print(f"Could not delete file {record[field]}: {e}")
        return True
    return False

def add_dna_record(user_id, original_path, encrypted_path, original_shape, key):
    dna_records_collection.insert_one({
        'user_id': ObjectId(user_id),
        'original_path': original_path,
        'encrypted_path': encrypted_path,
        'original_shape': original_shape,
        'key': key,
        'created_at': datetime.utcnow()
    })

def get_all_dna_records(user_id):
    records = dna_records_collection.find({'user_id': ObjectId(user_id)}).sort('created_at', -1)
    return [{**r, 'id': str(r['_id'])} for r in records]

def delete_dna_record(user_id, record_id):
    record = dna_records_collection.find_one_and_delete({
        '_id': ObjectId(record_id),
        'user_id': ObjectId(user_id)
    })
    if record:
        for field in ['original_path', 'encrypted_path']:
            if record.get(field):
                try:
                    os_path = os.path.join(*record[field].split('/'))
                    if os.path.exists(os_path): os.remove(os_path)
                except Exception as e:
                    print(f"Could not delete file {record[field]}: {e}")
        return True
    return False

def add_neural_record(user_id, original_path, encrypted_path, original_shape, key):
    neural_records_collection.insert_one({
        'user_id': ObjectId(user_id),
        'original_path': original_path,
        'encrypted_path': encrypted_path,
        'original_shape': original_shape,
        'key': key,
        'created_at': datetime.utcnow()
    })

def get_all_neural_records(user_id):
    records = neural_records_collection.find({'user_id': ObjectId(user_id)}).sort('created_at', -1)
    return [{**r, 'id': str(r['_id'])} for r in records]

def delete_neural_record(user_id, record_id):
    record = neural_records_collection.find_one_and_delete({
        '_id': ObjectId(record_id),
        'user_id': ObjectId(user_id)
    })
    if record:
        for field in ['original_path', 'encrypted_path']:
            if record.get(field):
                try:
                    os_path = os.path.join(*record[field].split('/'))
                    if os.path.exists(os_path): os.remove(os_path)
                except Exception as e:
                    print(f"Could not delete file {record[field]}: {e}")
        return True
    return False
# --- END DATABASE HELPER FUNCTIONS ---

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# The init_db() function is no longer needed as MongoDB is schema-less.

# --- Auth Routes (MongoDB Version) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_collection.find_one({'username': username})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id']) # Store user's MongoDB ObjectId as a string
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
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        gender = request.form.get('gender')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        usage_reasons = ','.join(request.form.getlist('usage_reasons'))
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
            
        # Check if username already exists
        if users_collection.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password)
        
        users_collection.insert_one({
            'username': username,
            'full_name': full_name,
            'email': email,
            'gender': gender,
            'password': hashed_password,
            'usage_reasons': usage_reasons,
            'created_at': datetime.utcnow()
        })
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- All other routes remain the same, calling the new database functions ---
# The logic within these routes does not need to change because the helper
# functions now abstract the database interaction. The only change is
# that 'user_id' from the session is now a string representation of
# an ObjectId, which our helper functions handle correctly.

@app.route('/chaotic_decrypt', methods=['POST'])
def chaotic_decrypt():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form or not request.form['key'].strip():
        return jsonify({'success': False, 'error': 'Image and key are required.'})
    temp_path = None
    try:
        image = request.files['image']
        algorithm_from_user = request.form.get('algorithm')
        key = request.form.get('key').strip()
        
        # Validate key against MongoDB
        record = chaotic_records_collection.find_one({
            'key': key,
            'user_id': ObjectId(session['user_id'])
        })
            
        if not record:
            return jsonify({'success': False, 'error': 'Decryption failed. The provided key is incorrect.'})
            
        correct_algorithm = record['algorithm']
        if algorithm_from_user != correct_algorithm:
            return jsonify({'success': False, 'error': f'Algorithm mismatch. This key is for the "{correct_algorithm.title()}" map, not the "{algorithm_from_user.title()}" map.'})
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_filename = f"temp_encrypted_{timestamp}.png"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        image.save(temp_path)
        
        decrypted_filename = f"chaotic_decrypted_{timestamp}.png"
        decrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        
        success = False
        if correct_algorithm == 'arnold':
            iterations = int(key)
            success = apply_arnold_cat_map(temp_path, decrypted_os_path, iterations, decrypt=True)
        elif correct_algorithm in ['logistic', 'henon']:
            success = apply_pixel_shuffling(temp_path, decrypted_os_path, key, correct_algorithm, decrypt=True)
            
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
            
        if success:
            decrypted_url_path = f"/static/temp/{decrypted_filename}"
            return jsonify({'success': True, 'decrypted_image': decrypted_url_path})
        else:
            return jsonify({'success': False, 'error': 'Decryption failed. The key format may be invalid or the image data is corrupt.'})
    except Exception as e:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred during decryption.'})

@app.route('/bitplane_decrypt', methods=['POST'])
def bitplane_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form or 'planes' not in request.form or 'algorithm' not in request.form:
        return jsonify({'success': False, 'error': 'Image, key, plane selection, and algorithm are required.'})
    
    try:
        image_file = request.files['image']
        user_key = request.form.get('key').strip()
        user_planes_str = request.form.get('planes')
        user_algorithm = request.form.get('algorithm')

        if not user_key:
            return jsonify({'success': False, 'error': 'Decryption key is required.'})

        # --- VALIDATION AGAINST MONGODB DATABASE ---
        record = bitplane_records_collection.find_one({
            "key": user_key,
            "user_id": ObjectId(session['user_id'])
        })

        if not record:
            return jsonify({'success': False, 'error': 'Decryption failed: The provided key is incorrect or does not belong to this user.'})

        correct_algorithm = record['algorithm']
        if user_algorithm != correct_algorithm:
            return jsonify({'success': False, 'error': f'Algorithm mismatch. This key is for the "{correct_algorithm.upper()}" method, not "{user_algorithm.upper()}".'})
        
        correct_planes_str = record['planes']
        user_planes_set = set(user_planes_str.split(','))
        correct_planes_set = set(correct_planes_str.split(','))
        
        if user_planes_set != correct_planes_set:
            return jsonify({'success': False, 'error': f'Bit-plane mismatch. The correct planes for this key are: {correct_planes_str}.'})
        # --- END VALIDATION ---

        planes_to_decrypt = [int(p) for p in user_planes_str.split(',')]
        image_bytes = image_file.read()
        
        decrypted_image, _ = process_bitplane_image(image_bytes, planes_to_decrypt, user_key, user_algorithm)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        decrypted_filename = f"bitplane_decrypted_{timestamp}.png"
        decrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        cv2.imwrite(decrypted_os_path, decrypted_image)
        
        return jsonify({
            'success': True,
            'decrypted_image': f"/static/temp/{decrypted_filename}"
        })
    except ValueError as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred during decryption.'})

@app.route('/neural_network_decrypt', methods=['POST'])
def neural_network_decrypt():
    if 'user_id' not in session: 
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Encrypted image and key are required.'})
    try:
        image_file = request.files['image']
        key = request.form.get('key').strip()
        if not key:
            return jsonify({'success': False, 'error': 'Decryption key is missing.'})
        
        record = neural_records_collection.find_one({
            "key": key, 
            "user_id": ObjectId(session['user_id'])
        })
        
        if not record:
            return jsonify({'success': False, 'error': 'Decryption failed. The provided key is incorrect.'})
            
        original_shape = eval(record['original_shape'])
        image_bytes = image_file.read()
        decrypted_image, _ = process_nn_image_cipher(image_bytes, key, original_shape=original_shape)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        decrypted_filename = f"nn_decrypted_{timestamp}.png"
        decrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        cv2.imwrite(decrypted_os_path, decrypted_image)
        
        return jsonify({
            'success': True,
            'decrypted_image': f"/static/temp/{decrypted_filename}"
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Decryption failed. Ensure the key and encrypted file are correct.'})

@app.route('/dna_decrypt', methods=['POST'])
def dna_decrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Encrypted image and key are required.'})
    try:
        image_file = request.files['image']
        key = request.form.get('key').strip()
        if not key:
            return jsonify({'success': False, 'error': 'Decryption key is missing.'})
        
        record = dna_records_collection.find_one({
            "key": key, 
            "user_id": ObjectId(session['user_id'])
        })
            
        if not record:
            return jsonify({'success': False, 'error': 'Decryption failed. The key is incorrect.'})
            
        original_shape = eval(record['original_shape']) 
        img_np = np.frombuffer(image_file.read(), np.uint8)
        encrypted_img = cv2.imdecode(img_np, cv2.IMREAD_COLOR)
        if encrypted_img is None:
            return jsonify({'success': False, 'error': 'Could not decode encrypted image file.'})
        
        pixel_bytes = encrypted_img.tobytes()
        decrypted_img_array = process_dna_image(pixel_bytes, original_shape, key, decrypt=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        decrypted_filename = f"dna_decrypted_{timestamp}.png"
        decrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        cv2.imwrite(decrypted_os_path, decrypted_img_array)
        
        return jsonify({
            'success': True,
            'decrypted_image': f"/static/temp/{decrypted_filename}"
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Decryption failed. Ensure the key and encrypted file are correct.'})


# --- The rest of the routes and main execution block are unchanged ---
@app.route('/static/temp/<path:filename>')
def serve_temp_file(filename):
    if 'user_id' not in session: abort(401)
    if '..' in filename or filename.startswith('/'):
        abort(404)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    abort(404)

@app.route('/history')
def history():
    if 'user_id' not in session: return redirect(url_for('login'))
    all_records = get_all_records(session['user_id'])
    return render_template('steganography_history.html', records=all_records)

@app.route('/delete_record/<string:record_id>', methods=['POST'])
def delete_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_record(session['user_id'], record_id):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/hide', methods=['POST'])
def hide():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'cover' not in request.files or 'secret' not in request.files:
        return jsonify({'success': False, 'error': 'Cover and secret images are required.'})
    cover_file = request.files['cover']
    secret_file = request.files['secret']
    if cover_file.filename == '' or secret_file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file.'})
    try:
        cover_image_bytes = cover_file.read()
        secret_image_bytes = secret_file.read()
        cover_image = cv2.imdecode(np.frombuffer(cover_image_bytes, np.uint8), cv2.IMREAD_COLOR)
        secret_image = cv2.imdecode(np.frombuffer(secret_image_bytes, np.uint8), cv2.IMREAD_COLOR)
        if cover_image is None:
            return jsonify({'success': False, 'error': 'Could not decode the cover image.'})
        if secret_image is None:
            return jsonify({'success': False, 'error': 'Could not decode the secret image.'})
        is_success, secret_data_encoded = cv2.imencode('.png', secret_image)
        if not is_success:
            return jsonify({'success': False, 'error': 'Failed to encode secret image.'})
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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hidden_filename = f"hidden_{timestamp}.png"
        hidden_os_path = os.path.join(app.config['UPLOAD_FOLDER'], hidden_filename)
        cv2.imwrite(hidden_os_path, stego_image)
        cover_file.seek(0)
        secret_file.seek(0)
        cover_filename = f"cover_{timestamp}.png"
        secret_filename = f"secret_{timestamp}.png"
        cover_os_path = os.path.join(app.config['UPLOAD_FOLDER'], cover_filename)
        secret_os_path = os.path.join(app.config['UPLOAD_FOLDER'], secret_filename)
        cover_file.save(cover_os_path)
        secret_file.save(secret_os_path)
        add_hide_record(user_id=session['user_id'], cover_path=f"static/temp/{cover_filename}", secret_path=f"static/temp/{secret_filename}", hidden_path=f"static/temp/{hidden_filename}", key=key)
        return jsonify({'success': True, 'hidden_image': f"/static/temp/{hidden_filename}", 'key': key})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An unexpected error occurred: ' + str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'hidden' not in request.files or 'key' not in request.form:
        return jsonify({'success': False, 'error': 'Hidden image and key are required.'})
    hidden_file = request.files['hidden']
    key = request.form['key'].strip()
    if hidden_file.filename == '' or not key:
        return jsonify({'success': False, 'error': 'No file or key provided.'})
    try:
        stego_image = cv2.imdecode(np.frombuffer(hidden_file.read(), np.uint8), cv2.IMREAD_COLOR)
        revealed_image = reveal_data_lsb(stego_image, key)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        decrypted_filename = f"decrypted_{timestamp}.png"
        decrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        cv2.imwrite(decrypted_os_path, revealed_image)
        return jsonify({'success': True, 'decrypted_image': f"/static/temp/{decrypted_filename}"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': "Decryption failed. The key may be incorrect or the image is not a valid stego-image."})

@app.route('/select_method')
def select_method():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('select_method.html')

@app.route('/standard')
def standard():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('steganography.html')

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

@app.route('/chaotic_encrypt', methods=['POST'])
def chaotic_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files: return jsonify({'success': False, 'error': 'No image file provided'})
    original_os_path = None
    try:
        image = request.files['image']
        algorithm = request.form.get('algorithm')
        user_key = request.form.get('key', '').strip()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_filename = f"chaotic_original_{timestamp}.png"
        original_os_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        image.save(original_os_path)
        encrypted_filename = f"chaotic_encrypted_{timestamp}.png"
        encrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        success, final_key = False, ""
        if algorithm == 'arnold':
            iterations = int(user_key) if user_key.isdigit() and int(user_key) > 0 else random.randint(5, 20)
            final_key = str(iterations)
            success = apply_arnold_cat_map(original_os_path, encrypted_os_path, iterations, decrypt=False)
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
            success = apply_pixel_shuffling(original_os_path, encrypted_os_path, final_key, algorithm, decrypt=False)
        else:
            os.remove(original_os_path)
            return jsonify({'success': False, 'error': 'Invalid algorithm selected.'})
        if success:
            encrypted_db_path = f"static/temp/{encrypted_filename}"
            original_db_path = f"static/temp/{original_filename}"
            add_chaotic_record(session['user_id'], original_db_path, encrypted_db_path, algorithm, final_key)
            return jsonify({'success': True, 'encrypted_image': encrypted_db_path, 'key': final_key})
        else:
            if os.path.exists(original_os_path): os.remove(original_os_path)
            if os.path.exists(encrypted_os_path): os.remove(encrypted_os_path)
            return jsonify({'success': False, 'error': f'Failed to apply {algorithm} map.'})
    except Exception as e:
        if original_os_path and os.path.exists(original_os_path): os.remove(original_os_path)
        print(f"Error in chaotic_encrypt: {e}")
        return jsonify({'success': False, 'error': str(e)})

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
            if not (0 <= key_val <= 255):
                raise ValueError("XOR key must be an integer between 0 and 255.")
        except (ValueError, TypeError):
            raise ValueError("XOR key must be a valid integer.")
        return np.full(image_shape, key_val, dtype=np.uint8)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def process_bitplane_image(image_file_bytes, planes_to_process, key_str, algorithm):
    img_color = cv2.imdecode(np.frombuffer(image_file_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img_color is None:
        raise ValueError("Could not decode image file.")
    keystream_image = get_keystream(img_color.shape, key_str, algorithm)
    plane_mask = 0
    for p in planes_to_process:
        plane_mask |= (1 << p)
    masked_keystream = cv2.bitwise_and(keystream_image, plane_mask)
    processed_image = cv2.bitwise_xor(img_color, masked_keystream)
    return processed_image, key_str

@app.route('/bitplane_encrypt', methods=['POST'])
def bitplane_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files or 'planes' not in request.form or 'algorithm' not in request.form:
        return jsonify({'success': False, 'error': 'Image, plane selection, and algorithm are required.'})
    try:
        image_file = request.files['image']
        planes_str = request.form.get('planes')
        algorithm = request.form.get('algorithm')
        key = request.form.get('key', '').strip()
        if not key:
            if algorithm == 'xor':
                key = str(random.randint(1, 255))
            else: 
                key = secrets.token_hex(16)
        planes_to_encrypt = [int(p) for p in planes_str.split(',')]
        image_bytes = image_file.read()
        encrypted_image, final_key = process_bitplane_image(image_bytes, planes_to_encrypt, key, algorithm)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_filename = f"bitplane_original_{timestamp}.png"
        original_os_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        with open(original_os_path, 'wb') as f:
            f.write(image_bytes)
        encrypted_filename = f"bitplane_encrypted_{timestamp}.png"
        encrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        cv2.imwrite(encrypted_os_path, encrypted_image)
        add_bitplane_record(
            user_id=session['user_id'],
            original_path=f"static/temp/{original_filename}",
            processed_path=f"static/temp/{encrypted_filename}",
            op_type='encrypt',
            planes=planes_str,
            algorithm=algorithm, 
            key=final_key
        )
        return jsonify({
            'success': True,
            'encrypted_image': f"/static/temp/{encrypted_filename}",
            'key': final_key
        })
    except ValueError as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': "An unexpected error occurred during encryption."})

@app.route('/neural_network_encrypt', methods=['POST'])
def neural_network_encrypt():
    if 'user_id' not in session: 
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'Image file is required.'})
    try:
        image_file = request.files['image']
        key = request.form.get('key', '').strip()
        if not key:
            key = secrets.token_hex(16)
        image_bytes = image_file.read()
        encrypted_image, original_shape = process_nn_image_cipher(image_bytes, key)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_filename = f"nn_original_{timestamp}.png"
        original_os_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        with open(original_os_path, 'wb') as f:
            f.write(image_bytes)
        encrypted_filename = f"nn_encrypted_{timestamp}.png"
        encrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        cv2.imwrite(encrypted_os_path, encrypted_image)
        add_neural_record(
            user_id=session['user_id'],
            original_path=f"static/temp/{original_filename}",
            encrypted_path=f"static/temp/{encrypted_filename}",
            original_shape=str(original_shape),
            key=key
        )
        return jsonify({
            'success': True, 
            'preview_image': f"/static/temp/{encrypted_filename}",
            'download_file': f"/static/temp/{encrypted_filename}",
            'key': key
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/dna_encrypt', methods=['POST'])
def dna_encrypt():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if 'image' not in request.files: return jsonify({'success': False, 'error': 'Image file is required.'})
    try:
        image_file = request.files['image']
        key = request.form.get('key', '').strip()
        if not key:
            key = secrets.token_hex(16)
        img_np = np.frombuffer(image_file.read(), np.uint8)
        original_img = cv2.imdecode(img_np, cv2.IMREAD_COLOR)
        if original_img is None:
            return jsonify({'success': False, 'error': 'Could not decode image file.'})
        original_shape = original_img.shape
        pixel_bytes = original_img.tobytes()
        encrypted_img_array = process_dna_image(pixel_bytes, original_shape, key, decrypt=False)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_filename = f"dna_original_{timestamp}.png"
        original_os_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        cv2.imwrite(original_os_path, original_img)
        encrypted_filename = f"dna_encrypted_{timestamp}.png"
        encrypted_os_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        cv2.imwrite(encrypted_os_path, encrypted_img_array)
        add_dna_record(
            user_id=session['user_id'],
            original_path=f"static/temp/{original_filename}",
            encrypted_path=f"static/temp/{encrypted_filename}",
            original_shape=str(original_shape),
            key=key
        )
        return jsonify({
            'success': True,
            'encrypted_image': f"/static/temp/{encrypted_filename}",
            'key': key
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/chaotic_history')
def chaotic_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = get_all_chaotic_records(session['user_id'])
    return render_template('chaotic_history.html', records=records)

@app.route('/delete_chaotic_record/<string:record_id>', methods=['POST'])
def delete_chaotic_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_chaotic_record(session['user_id'], record_id):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/bitplane_history')
def bitplane_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = get_all_bitplane_records(session['user_id'])
    return render_template('bitplane_history.html', records=records)

@app.route('/delete_bitplane_record/<string:record_id>', methods=['POST'])
def delete_bitplane_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_bitplane_record(session['user_id'], record_id):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/dna_history')
def dna_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    try:
        records = get_all_dna_records(session['user_id'])
        return render_template('dna_history.html', records=records)
    except Exception as e:
        flash('Could not load DNA history page.', 'error')
        return redirect(url_for('select_method'))

@app.route('/delete_dna_record/<string:record_id>', methods=['POST'])
def delete_dna_record_route(record_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_dna_record(session['user_id'], record_id):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/neural_network_history')
def neural_network_history():
    if 'user_id' not in session: return redirect(url_for('login'))
    records = get_all_neural_records(session['user_id'])
    return render_template('neural_network_history.html', records=records)

@app.route('/delete_neural_record/<string:record_id>', methods=['POST'])
def delete_neural_record_route(record_id):
    if 'user_id' not in session: 
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    if delete_neural_record(session['user_id'], record_id):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Record not found'}), 404

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('select_method'))

if __name__ == '__main__':
    # For production, use a proper WSGI server like Gunicorn or uWSGI
    app.run(debug=True, host='0.0.0.0', port=5000)
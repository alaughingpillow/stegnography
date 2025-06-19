from flask import Flask, render_template, request, send_file
from PIL import Image
import os
import hmac
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import io

# --- Constants ---
DELIMITER = "::END_MSG_STEGOSAURUS_REX::"
SALT_SIZE = 16
HMAC_SIZE = 32
MIN_PADDING_SIZE = 32
MAX_PADDING_SIZE = 128
PADDING_LENGTH_INDICATOR_SIZE = 1

app = Flask(__name__, template_folder='../templates')

# --- Encryption/Decryption Functions (from your original script) ---
def generate_key_from_password(password: str, salt: bytes, purpose: str = "Fernet") -> bytes:
    """Derives a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def generate_hmac(data: bytes, key: bytes) -> bytes:
    """Generates HMAC-SHA256 for the given data."""
    return hmac.new(key, data, hashlib.sha256).digest()

def encrypt_message(message: str, password: str) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypts a message with padding and HMAC using a password.
    Returns: fernet_salt, hmac_key_salt, padding_length_byte, encrypted_final_payload
    """
    padding_length = os.urandom(1)[0] % (MAX_PADDING_SIZE - MIN_PADDING_SIZE + 1) + MIN_PADDING_SIZE
    random_padding = os.urandom(padding_length)
    payload_for_hmac = message.encode('utf-8') + random_padding + DELIMITER.encode('utf-8')
    hmac_key_salt = os.urandom(SALT_SIZE)
    derived_hmac_key = generate_key_from_password(password + "_hmac_integrity_check", hmac_key_salt, purpose="HMAC")
    hmac_value = generate_hmac(payload_for_hmac, derived_hmac_key)
    data_to_encrypt = payload_for_hmac + hmac_value
    fernet_salt = os.urandom(SALT_SIZE)
    fernet_key = generate_key_from_password(password, fernet_salt, purpose="Fernet")
    f = Fernet(fernet_key)
    encrypted_final_payload = f.encrypt(data_to_encrypt)
    return fernet_salt, hmac_key_salt, bytes([padding_length]), encrypted_final_payload

def decrypt_message(all_encrypted_parts: bytes, password: str) -> str:
    """Decrypts and verifies the message."""
    try:
        fernet_salt = all_encrypted_parts[:SALT_SIZE]
        hmac_key_salt = all_encrypted_parts[SALT_SIZE : SALT_SIZE * 2]
        padding_length_byte = all_encrypted_parts[SALT_SIZE * 2 : SALT_SIZE * 2 + PADDING_LENGTH_INDICATOR_SIZE]
        padding_length = padding_length_byte[0]
        encrypted_final_payload = all_encrypted_parts[SALT_SIZE * 2 + PADDING_LENGTH_INDICATOR_SIZE:]

        fernet_key = generate_key_from_password(password, fernet_salt, purpose="Fernet")
        f = Fernet(fernet_key)
        decrypted_data = f.decrypt(encrypted_final_payload)

        payload_before_hmac_len = len(decrypted_data) - HMAC_SIZE
        if payload_before_hmac_len < 0:
            raise ValueError("Decrypted data too short for HMAC.")

        payload_for_hmac_check = decrypted_data[:payload_before_hmac_len]
        extracted_hmac = decrypted_data[payload_before_hmac_len:]

        derived_hmac_key = generate_key_from_password(password + "_hmac_integrity_check", hmac_key_salt, purpose="HMAC")
        calculated_hmac = generate_hmac(payload_for_hmac_check, derived_hmac_key)

        if not hmac.compare_digest(calculated_hmac, extracted_hmac):
            raise ValueError("HMAC verification failed. Incorrect password or data tampered.")

        delimiter_bytes = DELIMITER.encode('utf-8')
        delimiter_index = payload_for_hmac_check.rfind(delimiter_bytes)
        if delimiter_index == -1:
            raise ValueError("Delimiter not found in payload.")

        message_end_index = delimiter_index - padding_length
        if message_end_index < 0:
            raise ValueError("Invalid padding or delimiter position.")

        original_message_bytes = payload_for_hmac_check[:message_end_index]
        return original_message_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


# --- Steganography Core Functions ---
def data_to_binary_stream(data_bytes: bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def binary_stream_to_bytes(binary_string: str) -> bytes:
    if len(binary_string) % 8 != 0:
        binary_string = binary_string[:-(len(binary_string) % 8)]
    return bytes(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))

def hide_data_in_image(image, data_to_hide_str, password=None):
    """Hides data within an image, returns image object."""
    img = image.convert("RGB")
    width, height = img.size
    pixels = img.load()
    max_capacity_bits = width * height * 3

    if password:
        f_salt, h_salt, pad_len_byte, enc_payload = encrypt_message(data_to_hide_str, password)
        all_data_bytes_to_hide = f_salt + h_salt + pad_len_byte + enc_payload
    else:
        payload_bytes = (data_to_hide_str + DELIMITER).encode('utf-8')
        all_data_bytes_to_hide = payload_bytes

    binary_data_to_embed = data_to_binary_stream(all_data_bytes_to_hide)
    data_len_bits = len(binary_data_to_embed)

    if data_len_bits > max_capacity_bits:
        raise ValueError(f"Data ({data_len_bits} bits) exceeds image capacity ({max_capacity_bits} bits).")

    data_idx = 0
    for y in range(height):
        if data_idx >= data_len_bits: break
        for x in range(width):
            if data_idx >= data_len_bits: break
            r, g, b = list(pixels[x, y])

            if data_idx < data_len_bits: r = (r & 0xFE) | int(binary_data_to_embed[data_idx]); data_idx += 1
            if data_idx < data_len_bits: g = (g & 0xFE) | int(binary_data_to_embed[data_idx]); data_idx += 1
            if data_idx < data_len_bits: b = (b & 0xFE) | int(binary_data_to_embed[data_idx]); data_idx += 1

            pixels[x, y] = (r, g, b)
    return img

def extract_data_from_image(image, password=None):
    """Extracts data from an image."""
    img = image.convert("RGB")
    width, height = img.size
    pixels = img.load()

    binary_data_stream_list = []
    for y_coord in range(height):
        for x_coord in range(width):
            r_val, g_val, b_val = pixels[x_coord, y_coord]
            binary_data_stream_list.append(str(r_val & 1))
            binary_data_stream_list.append(str(g_val & 1))
            binary_data_stream_list.append(str(b_val & 1))

    extracted_binary_lsb_data = "".join(binary_data_stream_list)
    all_extracted_bytes = binary_stream_to_bytes(extracted_binary_lsb_data)

    if password:
        return decrypt_message(all_extracted_bytes, password)
    else:
        delimiter_bytes = DELIMITER.encode('utf-8')
        delimiter_index = all_extracted_bytes.find(delimiter_bytes)
        if delimiter_index != -1:
            message_bytes = all_extracted_bytes[:delimiter_index]
            return message_bytes.decode('utf-8')
        else:
            raise ValueError("Delimiter not found. No message concealed or data corrupted.")


@app.route('/')
def index():
    """Renders the main page."""
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    """Handles the encoding request."""
    try:
        cover_image_file = request.files['cover_image']
        message = request.form['message']
        password = request.form.get('password') # Use .get for optional fields

        if not cover_image_file:
            return render_template('index.html', error_encode="No cover image selected.")
        if not message:
            return render_template('index.html', error_encode="Message payload is empty.")

        image = Image.open(cover_image_file.stream)
        
        # Use a BytesIO object to hold the image data in memory
        output_image = hide_data_in_image(image, message, password if password else None)
        byte_arr = io.BytesIO()
        output_image.save(byte_arr, format='PNG')
        byte_arr.seek(0) # Rewind the buffer to the beginning

        return send_file(
            byte_arr,
            mimetype='image/png',
            as_attachment=True,
            download_name='stego_image.png'
        )
    except Exception as e:
        return render_template('index.html', error_encode=f"Encoding failed: {e}")


@app.route('/decode', methods=['POST'])
def decode():
    """Handles the decoding request."""
    try:
        stego_image_file = request.files['stego_image']
        password = request.form.get('password')

        if not stego_image_file:
            return render_template('index.html', error_decode="No stego-image selected.")

        image = Image.open(stego_image_file.stream)
        extracted_data = extract_data_from_image(image, password if password else None)

        return render_template('index.html', extracted_message=extracted_data)
    except Exception as e:
        return render_template('index.html', error_decode=f"Decoding failed: {e}")

# This part is not needed for Vercel deployment but useful for local testing
# To run locally: `python api/index.py`
if __name__ == "__main__":
    app.run(debug=True)
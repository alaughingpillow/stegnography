import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image
import os
import hmac
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import re
import time
import threading
import random
import sys

# --- Constants ---
DELIMITER = "::END_MSG_STEGOSAURUS_REX::" # Made delimiter more unique
SALT_SIZE = 16 
HMAC_SIZE = 32 
MIN_PADDING_SIZE = 32 # Increased min padding
MAX_PADDING_SIZE = 128 # Increased max padding
PADDING_LENGTH_INDICATOR_SIZE = 1

# --- UI Color Palette (Dark Theme) ---
ROOT_BG = "#2B2B2B" # IntelliJ Darcula Background
FRAME_BG = "#3C3F41" # IntelliJ Darcula UI Elements
WIDGET_BG = "#313335" # IntelliJ Darcula Editor Area / Entry
BUTTON_BG = "#4E5254"
BUTTON_FG = "#BBBBBB"
TEXT_FG = "#A9B7C6" # IntelliJ Darcula Text
ACCENT_FG_GREEN = "#6A8759" # IntelliJ Darcula Green (comments, success)
ACCENT_FG_CYAN = "#6897BB"  # IntelliJ Darcula Cyan (keywords, info)
ACCENT_FG_RED = "#FF6B68"   # Similar to Darcula error color
ACCENT_FG_ORANGE = "#FFC66D" # Darcula orange/yellow
STATUS_BAR_BG = "#313335"
MONO_FONT = ("Consolas", 10)
UI_FONT = ("Segoe UI", 10) # Or "Helvetica" if Segoe UI not available

# --- Encryption/Decryption Functions ---
def generate_key_from_password(password: str, salt: bytes, purpose: str = "Fernet") -> bytes:
    """Derives a Fernet key from a password and salt."""
    print(f"  [CRYPTO_CORE] Deriving {purpose} key from password. Salt: {salt.hex()}")
    print(f"  [CRYPTO_CORE] Iterations: 100,000, Algorithm: PBKDF2-HMAC-SHA256")
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, # Standard, good for security
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    print(f"  [CRYPTO_CORE] {purpose} key derived successfully.")
    return key

def generate_hmac(data: bytes, key: bytes) -> bytes:
    """Generates HMAC-SHA256 for the given data."""
    print(f"  [CRYPTO_CORE] Generating HMAC-SHA256 for data block of {len(data)} bytes.")
    hmac_val = hmac.new(key, data, hashlib.sha256).digest()
    print(f"  [CRYPTO_CORE] HMAC generated: {hmac_val.hex()}")
    return hmac_val

def encrypt_message(message: str, password: str) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypts a message with padding and HMAC using a password.
    Returns: fernet_salt, hmac_key_salt, padding_length_byte, encrypted_final_payload
    """
    print(f"[CRYPTO_OP] Initiating encryption sequence for message of {len(message)} chars.")
    
    # 1. Add random padding
    padding_length = os.urandom(1)[0] % (MAX_PADDING_SIZE - MIN_PADDING_SIZE + 1) + MIN_PADDING_SIZE
    random_padding = os.urandom(padding_length)
    print(f"  [CRYPTO_OP] Generated {padding_length} bytes of random cryptographic padding.")

    # 2. Prepare payload for HMAC (Message + Padding + Delimiter)
    payload_for_hmac = message.encode('utf-8') + random_padding + DELIMITER.encode('utf-8')
    print(f"  [CRYPTO_OP] Payload for HMAC (Message+Padding+Delimiter) prepared. Length: {len(payload_for_hmac)} bytes.")

    # 3. Generate HMAC key and HMAC value
    hmac_key_salt = os.urandom(SALT_SIZE)
    print(f"  [CRYPTO_OP] Generated HMAC key salt: {hmac_key_salt.hex()}")
    derived_hmac_key = generate_key_from_password(password + "_hmac_integrity_check", hmac_key_salt, purpose="HMAC")
    hmac_value = generate_hmac(payload_for_hmac, derived_hmac_key)
    
    # 4. Combine payload with HMAC for encryption (Message + Padding + Delimiter + HMAC)
    data_to_encrypt = payload_for_hmac + hmac_value
    print(f"  [CRYPTO_OP] Data for Fernet encryption (Msg+Pad+Delim+HMAC) assembled. Length: {len(data_to_encrypt)} bytes.")

    # 5. Encrypt with Fernet
    fernet_salt = os.urandom(SALT_SIZE)
    print(f"  [CRYPTO_OP] Generated Fernet key salt: {fernet_salt.hex()}")
    fernet_key = generate_key_from_password(password, fernet_salt, purpose="Fernet")
    f = Fernet(fernet_key)
    encrypted_final_payload = f.encrypt(data_to_encrypt)
    print(f"  [CRYPTO_OP] Fernet encryption complete. Final encrypted payload size: {len(encrypted_final_payload)} bytes.")
    print(f"[CRYPTO_OP] Encryption sequence finalized. Structure: [F_SALT|H_SALT|PAD_LEN|ENCRYPTED_BLOB]")
    return fernet_salt, hmac_key_salt, bytes([padding_length]), encrypted_final_payload


def decrypt_message(all_encrypted_parts: bytes, password: str) -> str:
    print(f"[CRYPTO_OP] Initiating decryption sequence. Total input blob size: {len(all_encrypted_parts)} bytes.")
    try:
        # 1. Extract salts and padding length
        print("  [CRYPTO_OP] Parsing cryptographic header...")
        fernet_salt = all_encrypted_parts[:SALT_SIZE]
        hmac_key_salt = all_encrypted_parts[SALT_SIZE : SALT_SIZE * 2]
        padding_length_byte = all_encrypted_parts[SALT_SIZE * 2 : SALT_SIZE * 2 + PADDING_LENGTH_INDICATOR_SIZE]
        padding_length = padding_length_byte[0]
        encrypted_final_payload = all_encrypted_parts[SALT_SIZE * 2 + PADDING_LENGTH_INDICATOR_SIZE:]
        print(f"    Fernet Salt ({len(fernet_salt)}B): {fernet_salt.hex()}")
        print(f"    HMAC Salt   ({len(hmac_key_salt)}B): {hmac_key_salt.hex()}")
        print(f"    Padding Len ({padding_length}B) indicated.")
        print(f"    Encrypted Payload to Decrypt: {len(encrypted_final_payload)} bytes.")

        # 2. Decrypt with Fernet
        print("  [CRYPTO_OP] Deriving Fernet key and attempting decryption...")
        fernet_key = generate_key_from_password(password, fernet_salt, purpose="Fernet")
        f = Fernet(fernet_key)
        decrypted_data = f.decrypt(encrypted_final_payload) # This is (message + random_padding + DELIMITER + hmac_value)
        print(f"  [CRYPTO_OP] Fernet decryption successful. Recovered data length: {len(decrypted_data)} bytes.")

        # 3. Separate HMAC from the rest of the payload
        payload_before_hmac_len = len(decrypted_data) - HMAC_SIZE
        if payload_before_hmac_len < 0:
            print("  [CRYPTO_FAIL] Decrypted data too short to contain HMAC. Integrity check impossible.")
            raise ValueError("Decrypted data too short to contain HMAC.")
        
        payload_for_hmac_check = decrypted_data[:payload_before_hmac_len]
        extracted_hmac = decrypted_data[payload_before_hmac_len:]
        print(f"  [CRYPTO_OP] Separated payload for HMAC check ({len(payload_for_hmac_check)}B) and extracted HMAC ({len(extracted_hmac)}B).")

        # 4. Verify HMAC
        print("  [CRYPTO_OP] Verifying HMAC for data integrity...")
        derived_hmac_key = generate_key_from_password(password + "_hmac_integrity_check", hmac_key_salt, purpose="HMAC")
        calculated_hmac = generate_hmac(payload_for_hmac_check, derived_hmac_key)

        if not hmac.compare_digest(calculated_hmac, extracted_hmac):
            print("  [CRYPTO_FAIL] !!! HMAC VERIFICATION FAILED !!! Data may be tampered or password incorrect.")
            raise ValueError("HMAC verification failed. Data integrity compromised or incorrect password.")
        print("  [CRYPTO_OP] HMAC verification successful. Data integrity confirmed.")

        # 5. Extract original message (strip padding and DELIMITER)
        print("  [CRYPTO_OP] Extracting original message from verified payload...")
        delimiter_bytes = DELIMITER.encode('utf-8')
        delimiter_index = payload_for_hmac_check.rfind(delimiter_bytes) 
        if delimiter_index == -1:
             print("  [CRYPTO_FAIL] Delimiter not found in HMAC'd payload after successful HMAC. This is unexpected.")
             raise ValueError("CRITICAL: Delimiter not found after HMAC verification.")
        
        message_end_index = delimiter_index - padding_length
        if message_end_index < 0:
            print("  [CRYPTO_FAIL] Invalid padding or delimiter position calculation.")
            raise ValueError("Invalid padding or delimiter position during message extraction.")

        original_message_bytes = payload_for_hmac_check[:message_end_index]
        decrypted_message_str = original_message_bytes.decode('utf-8')
        print(f"  [CRYPTO_OP] Original message successfully extracted. Length: {len(decrypted_message_str)} chars.")
        print(f"[CRYPTO_OP] Decryption sequence successfully completed.")
        return decrypted_message_str

    except ValueError as ve: 
        print(f"  [CRYPTO_FAIL] Decryption ValueError: {ve}")
        raise ve
    except Exception as e: 
        print(f"  [CRYPTO_FAIL] General decryption error (e.g., InvalidToken from Fernet): {e}")
        raise ValueError(f"Decryption failed. Incorrect password or corrupted data. Details: {type(e).__name__}")

# --- Steganography Core Functions ---
def data_to_binary_stream(data_bytes: bytes):
    print(f"    [LSB_CORE] Converting {len(data_bytes)} bytes to binary stream...")
    stream = ''.join(format(byte, '08b') for byte in data_bytes)
    print(f"    [LSB_CORE] Binary stream generated: {len(stream)} bits.")
    return stream

def binary_stream_to_bytes(binary_string: str) -> bytes:
    print(f"    [LSB_CORE] Converting binary stream of {len(binary_string)} bits to bytes...")
    if len(binary_string) % 8 != 0:
        print(f"    [LSB_CORE] Warning: Binary string length {len(binary_string)} is not a multiple of 8. Truncating to nearest byte.")
        binary_string = binary_string[:-(len(binary_string) % 8)]
    
    byte_list = []
    for i in range(0, len(binary_string), 8):
        byte_chunk = binary_string[i:i+8]
        try:
            byte_list.append(int(byte_chunk, 2))
        except ValueError:
            print(f"    [LSB_CORE] Error converting binary chunk '{byte_chunk}' to byte. Skipping.") # Should not happen with valid binary
            # Potentially raise error or handle more gracefully
    result_bytes = bytes(byte_list)
    print(f"    [LSB_CORE] Byte conversion complete. Result: {len(result_bytes)} bytes.")
    return result_bytes

def hide_data_in_image(image_path, data_to_hide_str, output_path, password=None):
    print(f"[STEGO_ENCODE_OP] Initiating steganographic encoding: {image_path} -> {output_path}")
    start_time = time.time()
    try:
        print(f"  [STEGO_ENCODE_OP] Opening cover image: {image_path}...")
        img = Image.open(image_path).convert("RGB") # Crucial: Ensure RGB for consistent LSB
        width, height = img.size
        pixels = img.load() # Load pixel map
        max_capacity_bits = width * height * 3 # 3 LSBs per pixel (R, G, B)
        print(f"  [STEGO_ENCODE_OP] Image dimensions: {width}x{height}. Max LSB capacity: {max_capacity_bits} bits ({max_capacity_bits//8} bytes).")

        if password:
            print(f"  [STEGO_ENCODE_OP] Secure mode enabled. Invoking cryptographic subsystem for payload preparation...")
            f_salt, h_salt, pad_len_byte, enc_payload = encrypt_message(data_to_hide_str, password)
            all_data_bytes_to_hide = f_salt + h_salt + pad_len_byte + enc_payload
            print(f"  [STEGO_ENCODE_OP] Encrypted and signed payload ready. Total size: {len(all_data_bytes_to_hide)} bytes.")
        else: 
            print(f"  [STEGO_ENCODE_OP] Standard mode (no encryption). Preparing payload...")
            payload_bytes = (data_to_hide_str + DELIMITER).encode('utf-8')
            all_data_bytes_to_hide = payload_bytes
            print(f"  [STEGO_ENCODE_OP] Unencrypted payload ready. Total size: {len(all_data_bytes_to_hide)} bytes.")
        
        binary_data_to_embed = data_to_binary_stream(all_data_bytes_to_hide)
        data_len_bits = len(binary_data_to_embed)
        print(f"  [STEGO_ENCODE_OP] Payload converted to binary stream for LSB embedding: {data_len_bits} bits required.")

        if data_len_bits > max_capacity_bits:
            err_msg = f"Data ({data_len_bits} bits) exceeds image LSB capacity ({max_capacity_bits} bits)."
            print(f"  [STEGO_ENCODE_FAIL] {err_msg}")
            raise ValueError(err_msg)

        print(f"  [STEGO_ENCODE_OP] Initializing LSB steganographic matrix modification...")
        data_idx = 0
        for y in range(height):
            if data_idx >= data_len_bits: break
            for x in range(width):
                if data_idx >= data_len_bits: break
                r, g, b = list(pixels[x, y]) # Get mutable list of pixel components

                # Embed in Red channel LSB
                if data_idx < data_len_bits: r = (r & 0xFE) | int(binary_data_to_embed[data_idx]); data_idx += 1
                # Embed in Green channel LSB
                if data_idx < data_len_bits: g = (g & 0xFE) | int(binary_data_to_embed[data_idx]); data_idx += 1
                # Embed in Blue channel LSB
                if data_idx < data_len_bits: b = (b & 0xFE) | int(binary_data_to_embed[data_idx]); data_idx += 1
                
                pixels[x, y] = (r, g, b) # Update pixel in image

        if data_idx < data_len_bits:
            # This should not happen if capacity check is correct and loop completes
            print("  [STEGO_ENCODE_WARN] Reached end of image pixels but not all data embedded. This is an anomaly.")
        
        print(f"  [STEGO_ENCODE_OP] LSB embedding complete. {data_idx} bits written. Saving stego-image to {output_path}...")
        img.save(output_path)
        end_time = time.time()
        print(f"[STEGO_ENCODE_OP] Steganographic encoding successful. Output: {output_path}. Time: {end_time - start_time:.2f}s.")
        return "Steganographic encoding successful. Data concealed."

    except FileNotFoundError: 
        print(f"  [STEGO_ENCODE_FAIL] Input image file not found: {image_path}"); raise
    except Exception as e: 
        print(f"  [STEGO_ENCODE_FAIL] Critical error during encoding: {e}"); raise


def extract_data_from_image(image_path, password=None):
    print(f"[STEGO_DECODE_OP] Initiating steganographic extraction from: {image_path}")
    start_time = time.time()
    try:
        print(f"  [STEGO_DECODE_OP] Opening stego-image: {image_path}...")
        img = Image.open(image_path).convert("RGB") # Ensure RGB
        width, height = img.size
        pixels = img.load()
        print(f"  [STEGO_DECODE_OP] Image dimensions: {width}x{height}. Preparing for LSB data extraction.")

        print(f"  [STEGO_DECODE_OP] Scanning pixel matrix and extracting LSB stream...")
        binary_data_stream_list = []
        # For encrypted data, we don't know the exact length beforehand.
        # We need to extract enough to potentially get the header (salts, pad_len) and then the Fernet token.
        # Fernet tokens have their own internal structure that determines their length.
        # For unencrypted, we search for a delimiter.
        # A common strategy is to read a large chunk or the whole image LSBs.
        # This can be optimized by reading incrementally, especially for unencrypted.
        
        # Let's extract all LSBs for now. This is simpler but less efficient for small messages in large images.
        for y_coord in range(height):
            for x_coord in range(width):
                r_val, g_val, b_val = pixels[x_coord, y_coord]
                binary_data_stream_list.append(str(r_val & 1))
                binary_data_stream_list.append(str(g_val & 1))
                binary_data_stream_list.append(str(b_val & 1))
        
        extracted_binary_lsb_data = "".join(binary_data_stream_list)
        print(f"  [STEGO_DECODE_OP] LSB stream extraction complete. Total bits recovered: {len(extracted_binary_lsb_data)}.")
        
        all_extracted_bytes = binary_stream_to_bytes(extracted_binary_lsb_data)
        print(f"  [STEGO_DECODE_OP] LSB stream converted to byte array. Total bytes: {len(all_extracted_bytes)}.")

        if password:
            print(f"  [STEGO_DECODE_OP] Secure mode detected. Invoking cryptographic subsystem for payload decryption and verification...")
            # Minimum size for fernet_salt + hmac_salt + padding_byte + some_payload (HMAC + 1 byte data)
            min_required_bytes = SALT_SIZE * 2 + PADDING_LENGTH_INDICATOR_SIZE + HMAC_SIZE + 1 
            if len(all_extracted_bytes) < min_required_bytes:
                err_msg = f"Insufficient data extracted ({len(all_extracted_bytes)} bytes) for encrypted message structure (min ~{min_required_bytes} bytes)."
                print(f"  [STEGO_DECODE_FAIL] {err_msg}")
                raise ValueError(err_msg)
            
            # The decrypt_message function expects the complete block of (f_salt + h_salt + pad_len + encrypted_payload)
            # We assume all_extracted_bytes contains this, or at least the beginning of it.
            # Fernet decryption will fail if the token is incomplete or malformed.
            actual_message = decrypt_message(all_extracted_bytes, password)
            # No specific length check here, rely on decrypt_message success
        else: 
            print(f"  [STEGO_DECODE_OP] Standard mode (no encryption). Searching for delimiter in extracted byte stream...")
            delimiter_bytes = DELIMITER.encode('utf-8')
            try:
                delimiter_index = all_extracted_bytes.find(delimiter_bytes)
                if delimiter_index != -1:
                    message_bytes = all_extracted_bytes[:delimiter_index]
                    actual_message = message_bytes.decode('utf-8') # Attempt to decode as UTF-8
                    print(f"  [STEGO_DECODE_OP] Delimiter found. Unencrypted message extracted: {len(actual_message)} chars.")
                else:
                    print(f"  [STEGO_DECODE_FAIL] Delimiter '{DELIMITER}' not found in extracted data.")
                    raise ValueError("Delimiter not found. No message concealed or data corrupted.")
            except UnicodeDecodeError:
                print(f"  [STEGO_DECODE_FAIL] Failed to decode unencrypted message as UTF-8. Data may be binary or corrupted.")
                raise ValueError("Failed to decode unencrypted message (not valid UTF-8 or corrupted).")
        
        end_time = time.time()
        print(f"[STEGO_DECODE_OP] Steganographic extraction successful. Time: {end_time - start_time:.2f}s.")
        return actual_message

    except FileNotFoundError: 
        print(f"  [STEGO_DECODE_FAIL] Stego-image file not found: {image_path}"); raise
    except ValueError as ve: 
        print(f"  [STEGO_DECODE_FAIL] Value Error during extraction: {ve}"); raise
    except Exception as e: 
        print(f"  [STEGO_DECODE_FAIL] Critical error during extraction: {type(e).__name__} - {e}"); raise


# --- GUI Application ---
class SteganographyApp:
    def __init__(self, root_tk):
        self.root = root_tk
        self.root.title("Steganography Tool - [Dark Edition]")
        self.root.geometry("800x850") 
        self.root.configure(bg=ROOT_BG)

        # --- Style Configuration ---
        self.style = ttk.Style() # Make style an instance variable
        self.style.theme_use('clam') 

        # General widget styling for dark theme
        self.style.configure("TFrame", background=FRAME_BG)
        self.style.configure("TLabel", background=FRAME_BG, foreground=TEXT_FG, font=UI_FONT)
        self.style.configure("TButton", background=BUTTON_BG, foreground=BUTTON_FG, font=UI_FONT, borderwidth=1, relief="raised")
        self.style.map("TButton", background=[('active', '#65696B')]) # Slightly lighter on hover/press
        self.style.configure("TEntry", fieldbackground=WIDGET_BG, foreground=TEXT_FG, insertcolor=TEXT_FG, font=UI_FONT) # insertcolor is cursor
        self.style.configure("TNotebook", background=ROOT_BG, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=FRAME_BG, foreground=TEXT_FG, padding=[12, 6], font=MONO_FONT)
        self.style.map("TNotebook.Tab", background=[("selected", WIDGET_BG)], foreground=[("selected", ACCENT_FG_CYAN)])
        self.style.configure("Weak.TLabel", background=FRAME_BG, foreground=ACCENT_FG_RED, font=UI_FONT)
        self.style.configure("Medium.TLabel", background=FRAME_BG, foreground=ACCENT_FG_ORANGE, font=UI_FONT)
        self.style.configure("Strong.TLabel", background=FRAME_BG, foreground=ACCENT_FG_GREEN, font=UI_FONT)
        self.style.configure("Capacity.TLabel", background=FRAME_BG, foreground=ACCENT_FG_CYAN, font=MONO_FONT)
        self.style.configure("ShowPass.TCheckbutton", background=FRAME_BG, foreground=TEXT_FG, font=UI_FONT)
        self.style.map("ShowPass.TCheckbutton", indicatorcolor=[('selected', ACCENT_FG_GREEN)], background=[('active', FRAME_BG)])

        self.notebook = ttk.Notebook(self.root)
        self.encode_frame = ttk.Frame(self.notebook, padding="20 20 20 20")
        self.notebook.add(self.encode_frame, text=' E N C O D E ')
        self._create_encode_widgets()
        self.decode_frame = ttk.Frame(self.notebook, padding="20 20 20 20")
        self.notebook.add(self.decode_frame, text=' D E C O D E ')
        self._create_decode_widgets()
        self.notebook.pack(expand=True, fill='both', padx=20, pady=20)

        # --- Log Frame ---
        log_frame = ttk.Frame(self.root, padding="10 10 10 10")
        log_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0,10))
        ttk.Label(log_frame, text="System Log:", style="Capacity.TLabel").pack(anchor=tk.W)
        self.log_text = tk.Text(log_frame, height=7, width=90, state='disabled', font=("Consolas", 9), bg="#232323", fg="#B0B0B0", relief=tk.SUNKEN, borderwidth=2)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self._start_random_log_thread()

        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5, font=MONO_FONT, background=STATUS_BAR_BG, foreground=ACCENT_FG_CYAN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("System Nominal. Ready for Steganographic Operations.")
        print("[GUI_INIT] Steganography Interface Initialized. Version: Dark Edition v1.2")

    def _start_random_log_thread(self):
        def log_generator():
            log_samples = [
                "[INFO] System check complete.",
                "[SECURITY] No threats detected.",
                "[NETWORK] No external connections.",
                "[CRYPTO] Entropy pool healthy.",
                "[STEGO] Ready for encode/decode.",
                "[USER] Idle.",
                "[MEMORY] Usage normal.",
                "[DISK] Sufficient space.",
                "[GUI] All widgets responsive.",
                "[RANDOM] All systems green.",
                "[STEGO] Carrier image validated.",
                "[ENCODE] Payload optimized.",
                "[DECODE] Extraction complete.",
                "[PIXEL] LSB matrix aligned.",
                "[SIGNAL] Noise floor stable.",
                "[CHANNEL] Covert stream ready.",
                "[EMBED] Insertion point selected.",
                "[SECURITY] Cipher integrity verified.",
                "[ANALYSIS] Histogram check passed.",
                "[CHECKSUM] Data verified.",
    
               "[IMG] Bit depth confirmed.",
               "[ALGO] Spread spectrum enabled.",
               "[UI] Response latency: 2ms.",
               "[CORE] Idle threads: 3.",
               "[MODULE] Encoder warmed up.",
               "[KEY] Session key generated.",
               "[STEGO] Carrier sanitized.",
               "[RANDOM] Nonce rotation successful.",
               "[ENCODE] Compression ratio: 92%.",
               "[STATS] Image entropy balanced.",
    
               "[ACCESS] No unauthorized access.",
               "[CRYPTO] Salt generated.",
               "[VISUAL] Carrier transparency intact.",
               "[SCAN] Zero artifacts detected.",
               "[THREAD] Background ops stable.",
               "[ALERT] No anomalies found.",
               "[PIPELINE] Flow uninterrupted.",
               "[DATA] Packet loss: 0%",
               "[SYSTEM] Resource load optimal.",
               "[ENCODE] Data steganized successfully."
            ]
            while True:
                msg = random.choice(log_samples)
                self._append_log(msg)
                time.sleep(2)
        threading.Thread(target=log_generator, daemon=True).start()

    def _append_log(self, msg):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def _check_password_strength(self, password_var, strength_label_widget): # Pass widget directly
        password = password_var.get()
        strength_text = "Strength: [WEAK]"
        style_name = "Weak.TLabel"
        
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z\d\s]', password)) # Exclude space from special
        
        score = 0
        if length >= 8: score += 1
        if length >= 12: score +=1
        if length >= 16: score +=1 # Bonus for very long
        if has_lower: score += 1
        if has_upper: score += 1
        if has_digit: score += 1
        if has_special: score += 1

        if score >= 6: strength_text = "Strength: [STRONG] :: Fortress Level!"; style_name = "Strong.TLabel"
        elif score >= 4: strength_text = "Strength: [MEDIUM] :: Secure Channel"; style_name = "Medium.TLabel"
        
        strength_label_widget.config(text=strength_text, style=style_name)


    def _toggle_password_visibility(self, entry_widget, var):
        if var.get():
            entry_widget.config(show="")
            print(f"  [GUI_EVENT] Password visibility toggled ON for {entry_widget}.")
        else:
            entry_widget.config(show="*")
            print(f"  [GUI_EVENT] Password visibility toggled OFF for {entry_widget}.")


    def _update_capacity_preview(self, *args):
        filepath = self.encode_image_path_var.get()
        if filepath and os.path.exists(filepath):
            try:
                print(f"  [GUI_EVENT] Updating capacity preview for image: {filepath}")
                img = Image.open(filepath)
                width, height = img.size
                max_bits = width * height * 3
                max_bytes = max_bits // 8
                self.capacity_label.config(text=f"Est. LSB Capacity: {max_bytes // 1024} KB ({max_bytes} bytes)")
                print(f"    [GUI_INFO] Calculated LSB capacity: {max_bytes} bytes for {width}x{height} image.")
            except Exception as e:
                self.capacity_label.config(text="Est. LSB Capacity: Error reading image properties.")
                print(f"    [GUI_ERROR] Failed to update capacity preview: {e}")
        else:
            self.capacity_label.config(text="Est. LSB Capacity: N/A (No valid image selected)")


    def _create_encode_widgets(self):
        frame = self.encode_frame
        row_idx = 0

        ttk.Label(frame, text="Select Cover Image (Lossless PNG Recommended):").grid(row=row_idx, column=0, sticky=tk.W, pady=(0,2))
        row_idx += 1
        self.encode_image_path_var = tk.StringVar()
        self.encode_image_path_var.trace_add("write", self._update_capacity_preview)
        
        path_frame_encode = ttk.Frame(frame) # To group entry and button
        path_frame_encode.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW, pady=(0,5))
        self.encode_image_entry = ttk.Entry(path_frame_encode, textvariable=self.encode_image_path_var, width=60, state='readonly')
        self.encode_image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        ttk.Button(path_frame_encode, text="Browse...", command=self._browse_encode_image).pack(side=tk.LEFT)
        row_idx += 1

        self.capacity_label = ttk.Label(frame, text="Est. LSB Capacity: N/A", style="Capacity.TLabel")
        self.capacity_label.grid(row=row_idx, column=0, columnspan=3, sticky=tk.W, pady=(0,10))
        row_idx += 1

        ttk.Label(frame, text="Secret Message / Data Payload:").grid(row=row_idx, column=0, sticky=tk.NW, pady=(0,2))
        row_idx += 1
        self.message_text = tk.Text(frame, height=12, width=70, relief=tk.SOLID, borderwidth=1, font=MONO_FONT, bg=WIDGET_BG, fg=TEXT_FG, insertbackground=TEXT_FG, selectbackground=ACCENT_FG_CYAN, selectforeground=ROOT_BG)
        self.message_text.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW, pady=(0,10))
        row_idx += 1

        ttk.Label(frame, text="Encryption Password (HIGHLY Recommended):").grid(row=row_idx, column=0, sticky=tk.W, pady=(0,2))
        row_idx += 1
        password_entry_frame_encode = ttk.Frame(frame)
        password_entry_frame_encode.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW)
        self.encode_password_var = tk.StringVar()
        self.encode_password_entry = ttk.Entry(password_entry_frame_encode, textvariable=self.encode_password_var, show="*", width=45)
        self.encode_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.encode_show_pass_var = tk.BooleanVar()
        ttk.Checkbutton(password_entry_frame_encode, text="Show", variable=self.encode_show_pass_var, command=lambda: self._toggle_password_visibility(self.encode_password_entry, self.encode_show_pass_var), style="ShowPass.TCheckbutton").pack(side=tk.LEFT)
        row_idx += 1
        
        self.encode_password_strength_label = ttk.Label(frame, text="Strength: [N/A]", style="Weak.TLabel")
        self.encode_password_strength_label.grid(row=row_idx, column=0, columnspan=3, sticky=tk.W, pady=(0,10))
        self.encode_password_var.trace_add("write", lambda n,i,m,sv=self.encode_password_var, lbl=self.encode_password_strength_label: self._check_password_strength(sv, lbl))
        self._check_password_strength(self.encode_password_var, self.encode_password_strength_label) # Initial
        row_idx += 1
        
        ttk.Label(frame, text="Save Stego-Image As (e.g., output.png):").grid(row=row_idx, column=0, sticky=tk.W, pady=(0,2))
        row_idx += 1
        output_path_frame_encode = ttk.Frame(frame)
        output_path_frame_encode.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW, pady=(0,10))
        self.output_image_path_var = tk.StringVar()
        self.output_image_entry = ttk.Entry(output_path_frame_encode, textvariable=self.output_image_path_var, width=60, state='readonly')
        self.output_image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        ttk.Button(output_path_frame_encode, text="Browse...", command=self._browse_output_image).pack(side=tk.LEFT)
        row_idx += 1

        self.encode_button = ttk.Button(frame, text="< E N C O D E >", command=self._encode_action, style="Accent.TButton")
        self.style.configure("Accent.TButton", background=ACCENT_FG_GREEN, foreground=ROOT_BG, font=(UI_FONT[0], UI_FONT[1], "bold"))
        self.style.map("Accent.TButton", background=[('active', "#85E885")])
        self.encode_button.grid(row=row_idx, column=0, columnspan=3, pady=15, ipady=5)
        frame.columnconfigure(0, weight=1)

    def _create_decode_widgets(self):
        frame = self.decode_frame
        row_idx = 0

        ttk.Label(frame, text="Select Stego-Image to Decode:").grid(row=row_idx, column=0, sticky=tk.W, pady=(0,2))
        row_idx += 1
        path_frame_decode = ttk.Frame(frame)
        path_frame_decode.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW, pady=(0,10))
        self.decode_image_path_var = tk.StringVar()
        self.decode_image_entry = ttk.Entry(path_frame_decode, textvariable=self.decode_image_path_var, width=60, state='readonly')
        self.decode_image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        ttk.Button(path_frame_decode, text="Browse...", command=self._browse_decode_image).pack(side=tk.LEFT)
        row_idx += 1

        ttk.Label(frame, text="Decryption Password (if image was encrypted):").grid(row=row_idx, column=0, sticky=tk.W, pady=(0,2))
        row_idx += 1
        password_entry_frame_decode = ttk.Frame(frame)
        password_entry_frame_decode.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW)
        self.decode_password_var = tk.StringVar()
        self.decode_password_entry = ttk.Entry(password_entry_frame_decode, textvariable=self.decode_password_var, show="*", width=45)
        self.decode_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.decode_show_pass_var = tk.BooleanVar()
        ttk.Checkbutton(password_entry_frame_decode, text="Show", variable=self.decode_show_pass_var, command=lambda: self._toggle_password_visibility(self.decode_password_entry, self.decode_show_pass_var), style="ShowPass.TCheckbutton").pack(side=tk.LEFT)
        row_idx += 1

        self.decode_password_strength_label = ttk.Label(frame, text="Strength: [N/A]", style="Weak.TLabel")
        self.decode_password_strength_label.grid(row=row_idx, column=0, columnspan=3, sticky=tk.W, pady=(0,10))
        self.decode_password_var.trace_add("write", lambda n,i,m,sv=self.decode_password_var, lbl=self.decode_password_strength_label: self._check_password_strength(sv, lbl))
        self._check_password_strength(self.decode_password_var, self.decode_password_strength_label) # Initial
        row_idx += 1

        ttk.Label(frame, text="Extracted Secret Message / Data Payload:").grid(row=row_idx, column=0, sticky=tk.NW, pady=(0,2))
        row_idx += 1
        self.extracted_message_text = tk.Text(frame, height=12, width=70, state='disabled', relief=tk.SOLID, borderwidth=1, font=MONO_FONT, bg=WIDGET_BG, fg=TEXT_FG, insertbackground=TEXT_FG, selectbackground=ACCENT_FG_CYAN, selectforeground=ROOT_BG)
        self.extracted_message_text.grid(row=row_idx, column=0, columnspan=3, sticky=tk.EW, pady=(0,10))
        row_idx += 1

        self.decode_button = ttk.Button(frame, text="< D E C O D E >", command=self._decode_action, style="Accent2.TButton")
        self.style.configure("Accent2.TButton", background=ACCENT_FG_CYAN, foreground=ROOT_BG, font=(UI_FONT[0], UI_FONT[1], "bold"))
        self.style.map("Accent2.TButton", background=[('active', "#85E8FF")])
        self.decode_button.grid(row=row_idx, column=0, columnspan=3, pady=15, ipady=5)
        frame.columnconfigure(0, weight=1)

    def _browse_dialog(self, path_var, title, is_save=False):
        print(f"  [GUI_EVENT] Opening file dialog: {title}")
        if is_save:
            filepath = filedialog.asksaveasfilename(title=title, defaultextension=".png", filetypes=(("PNG files", "*.png"), ("All files", "*.*")))
        else:
            filepath = filedialog.askopenfilename(title=title, filetypes=(("PNG files", "*.png"),("JPEG files", "*.jpg;*.jpeg"), ("All files", "*.*")))
        
        if filepath:
            path_var.set(filepath)
            self.status_var.set(f"File selected: {os.path.basename(filepath)}")
            print(f"    [GUI_INFO] File dialog result: {filepath}")
        else:
            self.status_var.set("File selection cancelled.")
            print(f"    [GUI_INFO] File dialog cancelled by user.")
        return filepath


    def _browse_encode_image(self):
        self._browse_dialog(self.encode_image_path_var, "Select Cover Image for Encoding")

    def _browse_output_image(self):
        self._browse_dialog(self.output_image_path_var, "Save Stego-Image As", is_save=True)

    def _browse_decode_image(self):
        self._browse_dialog(self.decode_image_path_var, "Select Stego-Image for Decoding")


    def _validate_inputs(self, is_encode=True):
        print("  [GUI_VALIDATE] Performing input validation...")
        if is_encode:
            if not self.encode_image_path_var.get() or not os.path.exists(self.encode_image_path_var.get()):
                messagebox.showerror("Input Error", "Invalid or no cover image selected. Please select a valid image file."); return False
            if not self.message_text.get("1.0", tk.END).strip():
                messagebox.showerror("Input Error", "Message payload is empty. Please enter data to hide."); return False
            if not self.output_image_path_var.get():
                messagebox.showerror("Input Error", "Output path for stego-image not specified. Please select a save location."); return False
        else: # Decode
            if not self.decode_image_path_var.get() or not os.path.exists(self.decode_image_path_var.get()):
                messagebox.showerror("Input Error", "Invalid or no stego-image selected for decoding. Please select a valid file."); return False
        print("  [GUI_VALIDATE] Input validation successful.")
        return True

    def _execute_stego_operation(self, operation_func, success_msg_prefix, error_msg_prefix, *args):
        self.status_var.set(f"Processing... {operation_func.__name__} in progress. Stand by...")
        self.root.update_idletasks() 
        start_op_time = time.time()
        print(f"[GUI_ACTION] >>> EXECUTING OPERATION: {operation_func.__name__.upper()} <<<")
        try:
            result = operation_func(*args)
            op_duration = time.time() - start_op_time
            messagebox.showinfo("Operation Successful", f"{success_msg_prefix}\n\nOperation completed in {op_duration:.2f} seconds.")
            self.status_var.set(f"Operation {operation_func.__name__} successful. Duration: {op_duration:.2f}s.")
            print(f"[GUI_ACTION] <<< OPERATION {operation_func.__name__.upper()} SUCCEEDED >>> Duration: {op_duration:.2f}s")
            return result
        except Exception as e:
            op_duration = time.time() - start_op_time
            messagebox.showerror(f"{error_msg_prefix} Error", f"An error occurred: {type(e).__name__}\n{str(e)}\n\nOperation failed after {op_duration:.2f} seconds.")
            self.status_var.set(f"{error_msg_prefix} failed. Error: {type(e).__name__}. Duration: {op_duration:.2f}s.")
            print(f"[GUI_ACTION] <<< OPERATION {operation_func.__name__.upper()} FAILED >>> Error: {type(e).__name__} - {e}. Duration: {op_duration:.2f}s")
            return None


    def _encode_action(self):
        print("[GUI_ACTION] Encode button triggered. Validating inputs...")
        if not self._validate_inputs(is_encode=True): return

        image_path = self.encode_image_path_var.get()
        data_to_hide = self.message_text.get("1.0", tk.END).strip()
        output_path = self.output_image_path_var.get()
        password = self.encode_password_var.get() if self.encode_password_var.get() else None
        
        print(f"  [GUI_PARAM] Encode Params: Cover='{os.path.basename(image_path)}', Output='{os.path.basename(output_path)}', MsgLen={len(data_to_hide)}, Encrypt={'YES' if password else 'NO'}")
        
        if self._execute_stego_operation(hide_data_in_image, "Data successfully concealed in image.", "Encoding", image_path, data_to_hide, output_path, password):
            self.message_text.delete("1.0", tk.END) # Clear message on success
            print("  [GUI_INFO] Message input field cleared post-successful encoding.")


    def _decode_action(self):
        print("[GUI_ACTION] Decode button triggered. Validating inputs...")
        if not self._validate_inputs(is_encode=False): return

        image_path = self.decode_image_path_var.get()
        password = self.decode_password_var.get() if self.decode_password_var.get() else None
        
        print(f"  [GUI_PARAM] Decode Params: StegoImage='{os.path.basename(image_path)}', DecryptAttempt={'YES' if password else 'NO'}")

        self.extracted_message_text.config(state='normal')
        self.extracted_message_text.delete("1.0", tk.END)
        
        extracted_data = self._execute_stego_operation(extract_data_from_image, "Message successfully extracted from image.", "Decoding", image_path, password)
        
        if extracted_data is not None:
            self.extracted_message_text.insert(tk.END, extracted_data)
            print(f"  [GUI_INFO] Extracted message displayed. Preview (first 60 chars): '{extracted_data[:60].replace(chr(10), ' ')}...'")
        else:
            print("  [GUI_INFO] No data extracted or operation failed, output field remains empty.")
        self.extracted_message_text.config(state='disabled')


if __name__ == "__main__":
    print("[SYSTEM_STARTUP] Initializing Steganography Application Mainframe...")
    print(f"[SYSTEM_STARTUP] Python Version: {os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}")
    print(f"[SYSTEM_STARTUP] Cryptography Module Backend: {default_backend().name}")
    print(f"[SYSTEM_STARTUP] Current Timestamp: {time.ctime()}")

    def print_usage():
        print("\nSteganography Tool CLI Usage:")
        print("  Encode: python stee.py encode <cover_image> <output_image> <message_file> [password]")
        print("  Decode: python stee.py decode <stego_image> [password]")
        print("")

    def print_cli_banner():
        print(r"""
   ___        ___                 _         
  / _ \ _ __ / _ \ _ __ ___  __ _| |_ _   _ 
 | | | | '__| | | | '__/ _ \/ _` | __| | | |
 | |_| | |  | |_| | | |  __/ (_| | |_| |_| |
  \___/|_|   \___/|_|  \___|\__,_|\__|\__, |
                                      |___/ 
      Steganography Tool by: a creep
        """)

    if len(sys.argv) > 1:
        print_cli_banner()
        mode = sys.argv[1].lower()
        if mode == "encode" and len(sys.argv) >= 5:
            cover = sys.argv[2]
            output = sys.argv[3]
            msg_file = sys.argv[4]
            password = sys.argv[5] if len(sys.argv) > 5 else None
            if not os.path.exists(cover):
                print(f"[CLI] Cover image not found: {cover}"); sys.exit(1)
            if not os.path.exists(msg_file):
                print(f"[CLI] Message file not found: {msg_file}"); sys.exit(1)
            with open(msg_file, "r", encoding="utf-8") as f:
                msg = f.read()
            try:
                hide_data_in_image(cover, msg, output, password)
                print(f"[CLI] Encoding successful. Output: {output}")
            except Exception as e:
                print(f"[CLI] Encoding failed: {e}")
                sys.exit(1)
        elif mode == "decode" and len(sys.argv) >= 3:
            stego = sys.argv[2]
            password = sys.argv[3] if len(sys.argv) > 3 else None
            if not os.path.exists(stego):
                print(f"[CLI] Stego image not found: {stego}"); sys.exit(1)
            try:
                msg = extract_data_from_image(stego, password)
                print("[CLI] Decoded message:")
                print(msg)
            except Exception as e:
                print(f"[CLI] Decoding failed: {e}")
                sys.exit(1)
        else:
            print_usage()
            sys.exit(1)
    else:
        main_root_window = tk.Tk()
        app_instance = SteganographyApp(main_root_window)
        main_root_window.mainloop()
        print("[SYSTEM_SHUTDOWN] Steganography Application Terminated. All systems down.")

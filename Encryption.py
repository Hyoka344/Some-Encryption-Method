import os
import base64
import argparse
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import io
import threading
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from pqcrypto.kem.kyber1024 import generate_keypair, encrypt as kyber_encrypt, decrypt as kyber_decrypt
from pqcrypto.sign.dilithium5 import generate_keypair as dilithium_generate_keypair
from pqcrypto.sign.dilithium5 import sign as dilithium_sign, verify as dilithium_verify

# Ditingkatkan dari Kyber512 menjadi Kyber1024 untuk keamanan lebih tinggi
# Ditambahkan Dilithium5 untuk tanda tangan digital quantum-resistant
# Ditambahkan ChaCha20-Poly1305 sebagai alternatif AES-GCM
# Menggunakan cascading encryption dengan multiple algoritma

class MultiLayerEncryption:
    """
    Implementasi enkripsi berlapis dengan algoritma quantum-resistant
    """
    
    @staticmethod
    def generate_keys(key_dir: str, password: str = None):
        """Generate dan simpan kunci Kyber dan Dilithium"""
        os.makedirs(key_dir, exist_ok=True)
        
        # Generate Kyber keys (untuk enkripsi)
        kyber_public_key, kyber_private_key = generate_keypair()
        
        # Generate Dilithium keys (untuk tanda tangan digital)
        dilithium_public_key, dilithium_private_key = dilithium_generate_keypair()
        
        # Jika password disediakan, enkripsi kunci privat
        if password:
            salt = get_random_bytes(16)
            derived_key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)
            
            # Enkripsi kunci privat
            cipher = AES.new(derived_key, AES.MODE_GCM)
            kyber_private_encrypted, kyber_tag = cipher.encrypt_and_digest(kyber_private_key)
            kyber_private_key = salt + cipher.nonce + kyber_tag + kyber_private_encrypted
            
            cipher = AES.new(derived_key, AES.MODE_GCM)
            dilithium_private_encrypted, dilithium_tag = cipher.encrypt_and_digest(dilithium_private_key)
            dilithium_private_key = salt + cipher.nonce + dilithium_tag + dilithium_private_encrypted
        
        # Simpan kunci
        with open(f"{key_dir}/kyber_public_key.bin", "wb") as f:
            f.write(kyber_public_key)
        with open(f"{key_dir}/kyber_private_key.bin", "wb") as f:
            f.write(kyber_private_key)
        with open(f"{key_dir}/dilithium_public_key.bin", "wb") as f:
            f.write(dilithium_public_key)
        with open(f"{key_dir}/dilithium_private_key.bin", "wb") as f:
            f.write(dilithium_private_key)
        
        return key_dir
    
    @staticmethod
    def load_private_key(private_key_path: str, password: str = None):
        """Load dan dekripsi kunci privat jika dienkripsi dengan password"""
        with open(private_key_path, "rb") as f:
            key_data = f.read()
        
        # Jika password disediakan, dekripsi kunci privat
        if password:
            salt = key_data[:16]
            nonce = key_data[16:32]
            tag = key_data[32:48]
            encrypted_key = key_data[48:]
            
            derived_key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            
            try:
                return cipher.decrypt_and_verify(encrypted_key, tag)
            except ValueError:
                raise ValueError("Password salah atau kunci rusak")
        
        return key_data
    
    @staticmethod
    def encrypt_data(kyber_public_key_path: str, dilithium_private_key_path: str, 
                     data: bytes, password: str = None, use_chacha: bool = False):
        """
        Enkripsi data dengan multiple layer:
        1. AES-256-GCM atau ChaCha20-Poly1305 untuk enkripsi simetris
        2. Kyber1024 untuk enkripsi kunci simetris
        3. Dilithium5 untuk tanda tangan digital
        """
        # Baca kunci publik untuk enkripsi
        with open(kyber_public_key_path, "rb") as f:
            kyber_public_key = f.read()
        
        # Baca kunci privat untuk tanda tangan
        dilithium_private_key = MultiLayerEncryption.load_private_key(
            dilithium_private_key_path, password)
        
        # Layer 1: Buat kunci simetris
        symmetric_key1 = get_random_bytes(32)
        symmetric_key2 = get_random_bytes(32)
        
        # Layer 2: Enkripsi kunci simetris dengan Kyber
        kyber_ct1, shared_secret1 = kyber_encrypt(kyber_public_key, symmetric_key1)
        kyber_ct2, shared_secret2 = kyber_encrypt(kyber_public_key, symmetric_key2)
        
        # Layer 3: Enkripsi data dengan AES-GCM atau ChaCha20-Poly1305
        if use_chacha:
            cipher1 = ChaCha20_Poly1305.new(key=shared_secret1)
            nonce1 = cipher1.nonce
            ciphertext1, tag1 = cipher1.encrypt_and_digest(data)
            
            # Enkripsi lagi dengan layer kedua
            cipher2 = ChaCha20_Poly1305.new(key=shared_secret2)
            nonce2 = cipher2.nonce
            ciphertext2, tag2 = cipher2.encrypt_and_digest(ciphertext1)
        else:
            cipher1 = AES.new(shared_secret1, AES.MODE_GCM)
            nonce1 = cipher1.nonce
            ciphertext1, tag1 = cipher1.encrypt_and_digest(data)
            
            # Enkripsi lagi dengan layer kedua
            cipher2 = AES.new(shared_secret2, AES.MODE_GCM)
            nonce2 = cipher2.nonce
            ciphertext2, tag2 = cipher2.encrypt_and_digest(ciphertext1)
        
        # Calculate hash of the data for integrity
        data_hash = hashlib.sha3_512(data).digest()
        
        # Tanda tangan digital dengan Dilithium
        if use_chacha:
            signature = dilithium_sign(kyber_ct1 + kyber_ct2 + nonce1 + tag1 + nonce2 + tag2 + data_hash, dilithium_private_key)
            algo_byte = b'\x01'  # Gunakan 1 untuk ChaCha
        else:
            signature = dilithium_sign(kyber_ct1 + kyber_ct2 + nonce1 + tag1 + nonce2 + tag2 + data_hash, dilithium_private_key)
            algo_byte = b'\x00'  # Gunakan 0 untuk AES
        
        # Gabungkan semua komponen
        encrypted_data = (
            algo_byte +                   # 1 byte untuk tipe algoritma
            len(kyber_ct1).to_bytes(2, byteorder='big') +  # 2 bytes untuk panjang kyber_ct1
            kyber_ct1 +                   # Kyber ciphertext untuk kunci pertama
            kyber_ct2 +                   # Kyber ciphertext untuk kunci kedua
            nonce1 +                      # Nonce untuk cipher pertama
            tag1 +                        # Tag autentikasi untuk cipher pertama
            nonce2 +                      # Nonce untuk cipher kedua
            tag2 +                        # Tag autentikasi untuk cipher kedua
            len(signature).to_bytes(2, byteorder='big') +  # 2 bytes untuk panjang signature
            signature +                   # Tanda tangan digital
            ciphertext2                   # Ciphertext terenkripsi dua kali
        )
        
        return encrypted_data
    
    @staticmethod
    def decrypt_data(kyber_private_key_path: str, dilithium_public_key_path: str, 
                     encrypted_data: bytes, password: str = None):
        """Dekripsi data"""
        # Load kunci
        kyber_private_key = MultiLayerEncryption.load_private_key(
            kyber_private_key_path, password)
        
        with open(dilithium_public_key_path, "rb") as f:
            dilithium_public_key = f.read()
        
        # Parse komponen enkripsi
        algo_byte = encrypted_data[0:1]
        use_chacha = (algo_byte == b'\x01')
        
        kyber_ct1_len = int.from_bytes(encrypted_data[1:3], byteorder='big')
        current_pos = 3
        
        kyber_ct1 = encrypted_data[current_pos:current_pos+kyber_ct1_len]
        current_pos += kyber_ct1_len
        
        # Untuk Kyber1024, ukuran ciphertext adalah tetap
        kyber_ct2 = encrypted_data[current_pos:current_pos+kyber_ct1_len]
        current_pos += kyber_ct1_len
        
        # Untuk AES dan ChaCha, nonce dan tag adalah 16 dan 16 byte
        nonce1 = encrypted_data[current_pos:current_pos+16]
        current_pos += 16
        tag1 = encrypted_data[current_pos:current_pos+16]
        current_pos += 16
        
        nonce2 = encrypted_data[current_pos:current_pos+16]
        current_pos += 16
        tag2 = encrypted_data[current_pos:current_pos+16]
        current_pos += 16
        
        # Ambil panjang signature
        sig_len = int.from_bytes(encrypted_data[current_pos:current_pos+2], byteorder='big')
        current_pos += 2
        
        # Ambil signature
        signature = encrypted_data[current_pos:current_pos+sig_len]
        current_pos += sig_len
        
        # Sisa adalah ciphertext
        ciphertext2 = encrypted_data[current_pos:]
        
        # Dekripsi kunci simetris dengan Kyber
        shared_secret1 = kyber_decrypt(kyber_ct1, kyber_private_key)
        shared_secret2 = kyber_decrypt(kyber_ct2, kyber_private_key)
        
        # Dekripsi layer kedua
        if use_chacha:
            cipher2 = ChaCha20_Poly1305.new(key=shared_secret2, nonce=nonce2)
            try:
                ciphertext1 = cipher2.decrypt_and_verify(ciphertext2, tag2)
            except ValueError:
                raise ValueError("Autentikasi gagal pada layer ChaCha ke-2")
            
            # Dekripsi layer pertama
            cipher1 = ChaCha20_Poly1305.new(key=shared_secret1, nonce=nonce1)
            try:
                plaintext = cipher1.decrypt_and_verify(ciphertext1, tag1)
            except ValueError:
                raise ValueError("Autentikasi gagal pada layer ChaCha ke-1")
        else:
            cipher2 = AES.new(shared_secret2, AES.MODE_GCM, nonce=nonce2)
            try:
                ciphertext1 = cipher2.decrypt_and_verify(ciphertext2, tag2)
            except ValueError:
                raise ValueError("Autentikasi gagal pada layer AES ke-2")
            
            # Dekripsi layer pertama
            cipher1 = AES.new(shared_secret1, AES.MODE_GCM, nonce=nonce1)
            try:
                plaintext = cipher1.decrypt_and_verify(ciphertext1, tag1)
            except ValueError:
                raise ValueError("Autentikasi gagal pada layer AES ke-1")
        
        # Calculate hash of the decrypted data
        data_hash = hashlib.sha3_512(plaintext).digest()
        
        # Verifikasi tanda tangan digital
        message_to_verify = kyber_ct1 + kyber_ct2 + nonce1 + tag1 + nonce2 + tag2 + data_hash
        try:
            dilithium_verify(message_to_verify, signature, dilithium_public_key)
        except ValueError:
            raise ValueError("Verifikasi tanda tangan gagal! Data mungkin telah dimodifikasi.")
        
        return plaintext

    @staticmethod
    def encrypt_file(kyber_public_key_path: str, dilithium_private_key_path: str, 
                     input_file: str, encrypted_file: str, password: str = None, use_chacha: bool = False):
        """Enkripsi file"""
        with open(input_file, "rb") as f:
            plaintext = f.read()
        
        encrypted_data = MultiLayerEncryption.encrypt_data(
            kyber_public_key_path, dilithium_private_key_path, plaintext, password, use_chacha)
        
        with open(encrypted_file, "wb") as f:
            f.write(encrypted_data)
        
        return encrypted_file
    
    @staticmethod
    def decrypt_file(kyber_private_key_path: str, dilithium_public_key_path: str, 
                     encrypted_file: str, output_file: str, password: str = None):
        """Dekripsi file"""
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        
        plaintext = MultiLayerEncryption.decrypt_data(
            kyber_private_key_path, dilithium_public_key_path, encrypted_data, password)
        
        with open(output_file, "wb") as f:
            f.write(plaintext)
        
        return output_file
    
    @staticmethod
    def encrypt_text(kyber_public_key_path: str, dilithium_private_key_path: str, 
                     text: str, password: str = None, use_chacha: bool = False):
        """Enkripsi string teks"""
        plaintext = text.encode('utf-8')
        
        encrypted_data = MultiLayerEncryption.encrypt_data(
            kyber_public_key_path, dilithium_private_key_path, plaintext, password, use_chacha)
        
        # Base64 encode untuk representasi text
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    @staticmethod
    def decrypt_text(kyber_private_key_path: str, dilithium_public_key_path: str, 
                     encrypted_text: str, password: str = None):
        """Dekripsi string teks"""
        encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
        
        plaintext = MultiLayerEncryption.decrypt_data(
            kyber_private_key_path, dilithium_public_key_path, encrypted_data, password)
        
        return plaintext.decode('utf-8')


# ======================== GUI ========================

class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("Quantum-Resistant Encryption Suite")
        self.geometry("800x600")
        self.configure(bg="#f0f0f0")
        
        # Set tema dan style
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        
        # Style konfigurasi
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        self.style.configure('TButton', font=('Helvetica', 10, 'bold'), background='#4a7abc')
        self.style.configure('Header.TLabel', font=('Helvetica', 16, 'bold'))
        self.style.configure('Subheader.TLabel', font=('Helvetica', 12, 'bold'))
        
        # Buat notebook (tab controller)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab untuk manajemen kunci
        self.key_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.key_tab, text="Manajemen Kunci")
        self.setup_key_tab()
        
        # Tab untuk enkripsi file
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_tab, text="Enkripsi File")
        self.setup_file_tab()
        
        # Tab untuk enkripsi teks
        self.text_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.text_tab, text="Enkripsi Teks")
        self.setup_text_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("Siap")
        
        # Register window close event
        self.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_key_tab(self):
        # Frame utama dengan padding
        main_frame = ttk.Frame(self.key_tab, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Header
        header = ttk.Label(main_frame, text="Manajemen Kunci", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        # Frame untuk membuat kunci
        key_frame = ttk.LabelFrame(main_frame, text="Buat Kunci Baru")
        key_frame.pack(fill='x', padx=5, pady=5)
        
        # Folder kunci
        dir_frame = ttk.Frame(key_frame)
        dir_frame.pack(fill='x', padx=5, pady=5)
        
        dir_label = ttk.Label(dir_frame, text="Direktori Kunci:")
        dir_label.pack(side=tk.LEFT, padx=5)
        
        self.key_dir_var = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "quantum_keys"))
        dir_entry = ttk.Entry(dir_frame, textvariable=self.key_dir_var, width=40)
        dir_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        dir_button = ttk.Button(dir_frame, text="Browse", command=self.browse_key_dir)
        dir_button.pack(side=tk.LEFT, padx=5)
        
        # Password untuk kunci privat
        pw_frame = ttk.Frame(key_frame)
        pw_frame.pack(fill='x', padx=5, pady=5)
        
        pw_label = ttk.Label(pw_frame, text="Password Kunci Privat (opsional):")
        pw_label.pack(side=tk.LEFT, padx=5)
        
        self.key_pw_var = tk.StringVar()
        pw_entry = ttk.Entry(pw_frame, textvariable=self.key_pw_var, show="*", width=20)
        pw_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        # Tombol generate
        btn_frame = ttk.Frame(key_frame)
        btn_frame.pack(fill='x', padx=5, pady=10)
        
        gen_button = ttk.Button(btn_frame, text="Generate Kunci", command=self.generate_keys)
        gen_button.pack(side=tk.RIGHT, padx=5)
        
        # Status kunci
        status_frame = ttk.LabelFrame(main_frame, text="Status Kunci")
        status_frame.pack(fill='both', expand=True, padx=5, pady=10)
        
        self.key_status_text = scrolledtext.ScrolledText(status_frame, wrap=tk.WORD, height=10)
        self.key_status_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.key_status_text.config(state=tk.DISABLED)
        
        refresh_button = ttk.Button(status_frame, text="Refresh Status", command=self.check_key_status)
        refresh_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Check key status awal
        self.check_key_status()
    
    def setup_file_tab(self):
        # Frame utama dengan padding
        main_frame = ttk.Frame(self.file_tab, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Header
        header = ttk.Label(main_frame, text="Enkripsi dan Dekripsi File", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        # Frame untuk enkripsi file
        enc_frame = ttk.LabelFrame(main_frame, text="Enkripsi File")
        enc_frame.pack(fill='x', padx=5, pady=5)
        
        # File input untuk enkripsi
        input_frame = ttk.Frame(enc_frame)
        input_frame.pack(fill='x', padx=5, pady=5)
        
        input_label = ttk.Label(input_frame, text="File Input:")
        input_label.pack(side=tk.LEFT, padx=5)
        
        self.enc_input_var = tk.StringVar()
        input_entry = ttk.Entry(input_frame, textvariable=self.enc_input_var, width=40)
        input_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        input_button = ttk.Button(input_frame, text="Browse", 
                                 command=lambda: self.browse_file(self.enc_input_var))
        input_button.pack(side=tk.LEFT, padx=5)
        
        # File output terenkripsi
        output_frame = ttk.Frame(enc_frame)
        output_frame.pack(fill='x', padx=5, pady=5)
        
        output_label = ttk.Label(output_frame, text="File Output:")
        output_label.pack(side=tk.LEFT, padx=5)
        
        self.enc_output_var = tk.StringVar()
        output_entry = ttk.Entry(output_frame, textvariable=self.enc_output_var, width=40)
        output_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        output_button = ttk.Button(output_frame, text="Browse", 
                                  command=lambda: self.browse_save_file(self.enc_output_var))
        output_button.pack(side=tk.LEFT, padx=5)
        
        # Kunci publik
        pub_key_frame = ttk.Frame(enc_frame)
        pub_key_frame.pack(fill='x', padx=5, pady=5)
        
        pub_key_label = ttk.Label(pub_key_frame, text="Kunci Publik:")
        pub_key_label.pack(side=tk.LEFT, padx=5)
        
        self.enc_pub_key_var = tk.StringVar()
        pub_key_entry = ttk.Entry(pub_key_frame, textvariable=self.enc_pub_key_var, width=40)
        pub_key_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        pub_key_button = ttk.Button(pub_key_frame, text="Browse", 
                                   command=lambda: self.browse_file(self.enc_pub_key_var, 
                                                                  [("Key Files", "*.bin")]))
        pub_key_button.pack(side=tk.LEFT, padx=5)
        
        # Kunci privat Dilithium untuk tanda tangan
        dil_key_frame = ttk.Frame(enc_frame)
        dil_key_frame.pack(fill='x', padx=5, pady=5)
        
        dil_key_label = ttk.Label(dil_key_frame, text="Kunci Tanda Tangan:")
        dil_key_label.pack(side=tk.LEFT, padx=5)
        
        self.enc_dil_key_var = tk.StringVar()
        dil_key_entry = ttk.Entry(dil_key_frame, textvariable=self.enc_dil_key_var, width=40)
        dil_key_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        dil_key_button = ttk.Button(dil_key_frame, text="Browse", 
                                   command=lambda: self.browse_file(self.enc_dil_key_var, 
                                                                  [("Key Files", "*.bin")]))
        dil_key_button.pack(side=tk.LEFT, padx=5)
        
        # Password untuk kunci privat
        pw_frame = ttk.Frame(enc_frame)
        pw_frame.pack(fill='x', padx=5, pady=5)
        
        pw_label = ttk.Label(pw_frame, text="Password Kunci (jika ada):")
        pw_label.pack(side=tk.LEFT, padx=5)
        
        self.enc_pw_var = tk.StringVar()
        pw_entry = ttk.Entry(pw_frame, textvariable=self.enc_pw_var, show="*", width=20)
        pw_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        # Pilihan enkripsi
        algo_frame = ttk.Frame(enc_frame)
        algo_frame.pack(fill='x', padx=5, pady=5)
        
        self.enc_algo_var = tk.BooleanVar(value=False)
        algo_check = ttk.Checkbutton(algo_frame, text="Gunakan ChaCha20-Poly1305 (default: AES-GCM)", 
                                    variable=self.enc_algo_var)
        algo_check.pack(side=tk.LEFT, padx=5)
        
        # Tombol enkripsi
        enc_button = ttk.Button(enc_frame, text="Enkripsi File", command=self.encrypt_file)
        enc_button.pack(side=tk.RIGHT, padx=5, pady=10)
        
        # Frame untuk dekripsi file
        dec_frame = ttk.LabelFrame(main_frame, text="Dekripsi File")
        dec_frame.pack(fill='x', padx=5, pady=5)
        
        # File input terenkripsi
        input_dec_frame = ttk.Frame(dec_frame)
        input_dec_frame.pack(fill='x', padx=5, pady=5)
        
        input_dec_label = ttk.Label(input_dec_frame, text="File Terenkripsi:")
        input_dec_label.pack(side=tk.LEFT, padx=5)
        
        self.dec_input_var = tk.StringVar()
        input_dec_entry = ttk.Entry(input_dec_frame, textvariable=self.dec_input_var, width=40)
        input_dec_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        input_dec_button = ttk.Button(input_dec_frame, text="Browse", 
                                     command=lambda: self.browse_file(self.dec_input_var))
        input_dec_button.pack(side=tk.LEFT, padx=5)
        
        # File output hasil dekripsi
        output_dec_frame = ttk.Frame(dec_frame)
        output_dec_frame.pack(fill='x', padx=5, pady=5)
        
        output_dec_label = ttk.Label(output_dec_frame, text="File Output:")
        output_dec_label.pack(side=tk.LEFT, padx=5)
        
        self.dec_output_var = tk.StringVar()
        output_dec_entry = ttk.Entry(output_dec_frame, textvariable=self.dec_output_var, width=40)
        output_dec_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        output_dec_button = ttk.Button(output_dec_frame, text="Browse", 
                                      command=lambda: self.browse_save_file(self.dec_output_var))
        output_dec_button.pack(side=tk.LEFT, padx=5)
        
        # Kunci privat Kyber
        priv_key_frame = ttk.Frame(dec_frame)
        priv_key_frame.pack(fill='x', padx=5, pady=5)
        
        priv_key_label = ttk.Label(priv_key_frame, text="Kunci Privat:")
        priv_key_label.pack(side=tk.LEFT, padx=5)
        
        self.dec

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import datetime

class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EllipticCrypt")
        self.root.geometry("900x650")
        self.root.configure(bg="#1f2937")

        self.private_key = None
        self.public_key = None

        self.setup_gui()

    def setup_gui(self):
        title = tk.Label(
            self.root,
            text="EllipticCrypt",
            bg="#1f2937",
            fg="white",
            font=("Helvetica", 24, "bold"),
        )
        title.pack(pady=20)

        input_frame = tk.LabelFrame(
            self.root,
            text="Input Text",
            bg="#374151",
            fg="white",
            font=("Helvetica", 12, "bold"),
            padx=10,
            pady=10,
        )
        input_frame.pack(fill="x", padx=20, pady=10)

        self.input_text = tk.Text(
            input_frame, height=5, bg="#111827", fg="white", insertbackground="white", font=("Courier", 12)
        )
        self.input_text.pack(fill="x", padx=5, pady=5)

        button_frame = tk.Frame(self.root, bg="#1f2937")
        button_frame.pack(fill="x", padx=20, pady=10)

        generate_btn = tk.Button(
            button_frame,
            text="Generate Keys",
            command=self.generate_keys,
            bg="#10b981",
            fg="white",
            font=("Helvetica", 10, "bold"),
            width=15,
        )
        generate_btn.pack(side="left", padx=5)

        upload_btn = tk.Button(
            button_frame,
            text="Upload Private Key",
            command=self.upload_private_key,
            bg="#3b82f6",
            fg="white",
            font=("Helvetica", 10, "bold"),
            width=15,
        )
        upload_btn.pack(side="left", padx=5)

        clear_btn = tk.Button(
            button_frame,
            text="Clear Fields",
            command=self.clear_fields,
            bg="#f97316",
            fg="white",
            font=("Helvetica", 10, "bold"),
            width=15,
        )
        clear_btn.pack(side="left", padx=5)

        self.key_status = tk.Label(
            button_frame,
            text="No keys loaded",
            bg="#1f2937",
            fg="white",
            font=("Helvetica", 10, "italic"),
        )
        self.key_status.pack(side="left", padx=10)

        action_frame = tk.Frame(self.root, bg="#1f2937")
        action_frame.pack(fill="x", padx=20, pady=10)

        encrypt_btn = tk.Button(
            action_frame,
            text="Encrypt",
            command=self.encrypt_text,
            bg="#9b5de5",
            fg="white",
            font=("Helvetica", 12, "bold"),
            width=20,
        )
        encrypt_btn.pack(side="left", padx=10)

        decrypt_btn = tk.Button(
            action_frame,
            text="Decrypt",
            command=self.decrypt_text,
            bg="#ef4444",
            fg="white",
            font=("Helvetica", 12, "bold"),
            width=20,
        )
        decrypt_btn.pack(side="left", padx=10)

        output_frame = tk.LabelFrame(
            self.root,
            text="Output Text",
            bg="#374151",
            fg="white",
            font=("Helvetica", 12, "bold"),
            padx=10,
            pady=10,
        )
        output_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.output_text = tk.Text(
            output_frame, height=7, bg="#111827", fg="white", insertbackground="white", font=("Courier", 12)
        )
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)

    def generate_keys(self):
        try:
            self.private_key = ec.generate_private_key(ec.SECP256K1())
            self.public_key = self.private_key.public_key()

            self.key_status.config(text="Keys generated successfully")
            messagebox.showinfo("Success", "Keys generated successfully!")

            self.save_keys()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {e}")

    def save_keys(self):
        try:
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open("private_key.pem", "wb") as f:
                f.write(private_pem)

            with open("public_key.pem", "wb") as f:
                f.write(public_pem)

            messagebox.showinfo("Keys Saved", "Private and public keys saved to the current directory.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keys: {e}")

    def upload_private_key(self):
        try:
            filepath = filedialog.askopenfilename(
                title="Select Private Key File",
                filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")],
            )
            if filepath:
                with open(filepath, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                self.public_key = self.private_key.public_key()
                self.key_status.config(text="Private key loaded successfully")
                messagebox.showinfo("Success", "Private key loaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {e}")

    def derive_key_and_iv(self, shared_key):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        key_material = hkdf.derive(shared_key)
        return key_material[:32], key_material[32:]

    def encrypt_text(self):
        try:
            if not self.public_key:
                messagebox.showerror("Error", "Please generate or load keys first!")
                return

            plaintext = self.input_text.get("1.0", tk.END).strip()
            if not plaintext:
                messagebox.showerror("Error", "Input text is empty!")
                return

            ephemeral_private_key = ec.generate_private_key(ec.SECP256K1())
            ephemeral_public_key = ephemeral_private_key.public_key()

            shared_key = ephemeral_private_key.exchange(ec.ECDH(), self.public_key)
            
            key, iv = self.derive_key_and_iv(shared_key)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            padded_data = self.pad_data(plaintext.encode())
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            combined_data = len(ephemeral_public_key_bytes).to_bytes(2, 'big') + \
                           ephemeral_public_key_bytes + \
                           iv + \
                           ciphertext

            encrypted_text = base64.b64encode(combined_data).decode('utf-8')

            formatted_text = ""
            chunk_size = 64  
            for i in range(0, len(encrypted_text), chunk_size):
                formatted_text += encrypted_text[i:i+chunk_size] + "\n"

            display_text = "-----BEGIN ENCRYPTED MESSAGE-----\n"
            display_text += formatted_text
            display_text += "-----END ENCRYPTED MESSAGE-----"

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", display_text)

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_text(self):
        try:
            if not self.private_key:
                messagebox.showerror("Error", "Please load private key first!")
                return

            input_text = self.input_text.get("1.0", tk.END).strip()
            if "-----BEGIN ENCRYPTED MESSAGE-----" in input_text and "-----END ENCRYPTED MESSAGE-----" in input_text:
                input_text = input_text.split("-----BEGIN ENCRYPTED MESSAGE-----")[1]
                input_text = input_text.split("-----END ENCRYPTED MESSAGE-----")[0]

            input_text = ''.join(input_text.split())
            
            combined_data = base64.b64decode(input_text)
            
            
            key_length = int.from_bytes(combined_data[:2], 'big')
            ephemeral_public_key_bytes = combined_data[2:2+key_length]
            iv = combined_data[2+key_length:2+key_length+16]  
            ciphertext = combined_data[2+key_length+16:]
            
        
            ephemeral_public_key = serialization.load_der_public_key(
                ephemeral_public_key_bytes,
                backend=default_backend()
            )

            
            shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
            
            
            key, _ = self.derive_key_and_iv(shared_key)

            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self.unpad_data(padded_plaintext)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", plaintext.decode('utf-8'))

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def pad_data(self, data):
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad_data(self, padded_data):
        
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    def clear_fields(self):
        
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.key_status.config(text="No keys loaded")


if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()
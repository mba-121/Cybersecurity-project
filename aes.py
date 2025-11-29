import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt data
def encrypt_data(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)  # Using ECB mode
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return ct_bytes.hex().upper()

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    try:
        encrypted_data = bytes.fromhex(encrypted_data.strip())  # Convert hex to bytes
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)  # Using ECB mode
        pt = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return pt.decode('utf-8')
    except ValueError as ve:
        return f"Decryption failed: {ve}"
    except KeyError:
        return "Decryption failed. Invalid key or data."

# Input validation function
def validate_key(key):
    if len(key) != 16:
        messagebox.showerror("Invalid Key", "Key must be 16 characters long.")
        return False
    return True

# Function to handle Encryption button
def on_encrypt():
    text = entry_text.get()
    key = entry_key.get()

    if not validate_key(key):
        return

    if not text.strip():
        messagebox.showerror("Invalid Input", "Text cannot be empty.")
        return

    encrypted = encrypt_data(text.strip(), key)
    result_label.config(text=f"Encrypted Text: {encrypted}")

# Function to handle Decryption button
def on_decrypt():
    encrypted_text = entry_text.get()
    key = entry_key.get()

    if not validate_key(key):
        return

    if not encrypted_text.strip():
        messagebox.showerror("Invalid Input", "Encrypted text cannot be empty.")
        return

    decrypted = decrypt_data(encrypted_text.strip(), key)
    result_label.config(text=f"Decrypted Text: {decrypted}")

# Create the main window
root = tk.Tk()
root.title("AES-128 Encryption/Decryption Tool")
root.configure(bg="#f2f2f2")

# Title Label
title_label = tk.Label(root, text="AES-128 Cipher Tool", font=("Helvetica", 16, "bold"), bg="#4CAF50", fg="white", pady=10)
title_label.grid(row=0, column=0, columnspan=2, sticky="nsew")

# Create and place widgets
label_text = tk.Label(root, text="Enter Text/Encrypted Data:", bg="#f2f2f2")
label_text.grid(row=1, column=0, padx=10, pady=10, sticky="e")

entry_text = tk.Entry(root, width=40)
entry_text.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

label_key = tk.Label(root, text="Enter Key (16 characters):", bg="#f2f2f2")
label_key.grid(row=2, column=0, padx=10, pady=10, sticky="e")

entry_key = tk.Entry(root, width=40)
entry_key.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

button_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt, width=15, bg="#2196F3", fg="white", font=("Helvetica", 10, "bold"))
button_encrypt.grid(row=3, column=0, padx=10, pady=10, sticky="e")

button_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt, width=15, bg="#FF5722", fg="white", font=("Helvetica", 10, "bold"))
button_decrypt.grid(row=3, column=1, padx=10, pady=10, sticky="w")

result_label = tk.Label(root, text="Result will be shown here", fg="blue", font=("Helvetica", 12), bg="#f2f2f2")
result_label.grid(row=4, column=0, columnspan=2, padx=10, pady=20, sticky="nsew")

# Configure the grid to be responsive
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(4, weight=1)

# Adjust window size
root.geometry("500x300")

# Run the application
root.mainloop()

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import hashlib

# Function to encrypt the file and overwrite the original
def encrypt_file(file_path, password, algorithm):
    try:
        # Generate salt and key from password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(password.encode())

        # Create Cipher
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Pad the file data to be a multiple of 16 bytes
        padding_length = 16 - len(file_data) % 16
        file_data += bytes([padding_length]) * padding_length

        # Encrypt file data
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        # Hash the password and store it at the beginning of the file
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Write the password hash, salt, iv, and encrypted data to the file
        with open(file_path, 'wb') as f:
            f.write(password_hash.encode() + b'\n')  # Store password hash
            f.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", "File encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

# Function to decrypt the file and overwrite the original
def decrypt_file(file_path, password, algorithm):
    try:
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Extract the stored password hash, salt, IV, and encrypted data
        password_hash_end = file_data.find(b'\n')
        stored_password_hash = file_data[:password_hash_end].decode()  # Extract password hash from the first line
        salt = file_data[password_hash_end + 1:password_hash_end + 17]  # After hash, salt starts at byte 64 (16 bytes)
        iv = file_data[password_hash_end + 17:password_hash_end + 33]  # After salt, IV starts at byte 80 (16 bytes)
        encrypted_data = file_data[password_hash_end + 33:]  # Encrypted data starts after salt and IV

        # Verify if the entered password matches the stored password hash
        entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
        if entered_password_hash != stored_password_hash:
            messagebox.showerror("Password Mismatch", "Passwords do not match.")
            return

        # Derive the key from the entered password
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(password.encode())

        # Create Cipher
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding (padding length is stored in the last byte)
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]  # Remove the padding from the end

        # Overwrite the original file with the decrypted data
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", "File decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

# Function to handle file selection
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

# Function to handle password authentication
def authenticate_password():
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    if password != confirm_password:
        messagebox.showerror("Password Mismatch", "Passwords do not match.")
        return False
    return True

# Function to perform the encryption or decryption
def perform_action():
    file_path = file_entry.get()
    password = password_entry.get()
    algorithm_choice = algorithm_var.get()

    if not file_path or not password or algorithm_choice == "Select Algorithm":
        messagebox.showerror("Input Error", "Please fill in all fields.")
        return

    # Select the encryption algorithm
    if algorithm_choice == "AES":
        algorithm = algorithms.AES
    elif algorithm_choice == "TripleDES":
        algorithm = algorithms.TripleDES
    elif algorithm_choice == "Blowfish":
        algorithm = algorithms.Blowfish
    else:
        messagebox.showerror("Algorithm Error", "Unsupported algorithm.")
        return

    if action_var.get() == "Encrypt":
        if authenticate_password():
            encrypt_file(file_path, password, algorithm)
    elif action_var.get() == "Decrypt":
        if authenticate_password():
            decrypt_file(file_path, password, algorithm)
    else:
        messagebox.showerror("Action Error", "Invalid action selected.")

# Set up the Tkinter GUI
root = tk.Tk()
root.title("File Encryption/Decryption Tool")
root.geometry("600x400")  # Set the size of the window
root.config(bg="#f5f5f5")  # Initial light theme background color

# Main frame to hold everything in a neat layout
frame = tk.Frame(root, bg="#f5f5f5", padx=20, pady=20)
frame.pack(padx=10, pady=10, fill="both", expand=True)

# Select action (Encrypt/Decrypt) dropdown at the top
action_label = tk.Label(frame, text="Select action:", bg="#f5f5f5", font=("Arial", 10, "bold"))
action_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
action_var = tk.StringVar(frame)
action_var.set("Encrypt")
action_dropdown = tk.OptionMenu(frame, action_var, "Encrypt", "Decrypt")
action_dropdown.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

# File selection
file_label = tk.Label(frame, text="Select file:", bg="#f5f5f5", font=("Arial", 10))
file_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
file_entry = tk.Entry(frame, width=40, font=("Arial", 10))
file_entry.grid(row=1, column=1, padx=5, pady=5)
file_button = tk.Button(frame, text="Browse", command=select_file, font=("Arial", 10))
file_button.grid(row=1, column=2, padx=5, pady=5)

# Password and password confirmation
password_label = tk.Label(frame, text="Enter password:", bg="#f5f5f5", font=("Arial", 10))
password_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
password_entry = tk.Entry(frame, show="*", width=40, font=("Arial", 10))
password_entry.grid(row=2, column=1, padx=5, pady=5)

confirm_password_label = tk.Label(frame, text="Confirm password:", bg="#f5f5f5", font=("Arial", 10))
confirm_password_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)
confirm_password_entry = tk.Entry(frame, show="*", width=40, font=("Arial", 10))
confirm_password_entry.grid(row=3, column=1, padx=5, pady=5)

# Algorithm selection dropdown
algorithm_label = tk.Label(frame, text="Select encryption algorithm:", bg="#f5f5f5", font=("Arial", 10))
algorithm_label.grid(row=4, column=0, sticky="w", padx=5, pady=5)
algorithm_var = tk.StringVar(frame)
algorithm_var.set("Select Algorithm")
algorithm_dropdown = tk.OptionMenu(frame, algorithm_var, "AES", "TripleDES", "Blowfish")
algorithm_dropdown.grid(row=4, column=1, sticky="ew", padx=10, pady=5)

# Perform action button
action_button = tk.Button(frame, text="Start", command=perform_action, font=("Arial", 10, "bold"))
action_button.grid(row=5, column=0, columnspan=3, pady=15)

# Run the Tkinter event loop
root.mainloop()

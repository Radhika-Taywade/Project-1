#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import hashlib
from cryptography.fernet import Fernet

# Simulate user data storage (username and password hashes)
user_data = {
    'alice': '5f4dcc3b5aa765d61d8327deb882cf99',  # Hashed 'password'
    'bob': '7c6a180b36896a0a8c02787eeafb0e4c',    # Hashed 'securepass'
}

# Generate a random encryption key
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

def encrypt_message(message):
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
    return decrypted_message

def authenticate_user(username, password):
    if username in user_data:
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        if user_data[username] == hashed_password:
            return True
    return False

# Simulating a user sending a message
sender = 'alice'
recipient = 'bob'
message = "Hello, Bob! This is a secret message."

# Encrypt the message
encrypted_message = encrypt_message(message)

# Simulate recipient decryption
if authenticate_user(sender, 'password'):
    decrypted_message = decrypt_message(encrypted_message)
    print(f"Decrypted message for {recipient}: {decrypted_message}")
else:
    print("Authentication failed.")


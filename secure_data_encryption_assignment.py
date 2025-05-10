import streamlit as st
import json
import os
import hashlib
import base64
import time
from cryptography.fernet import Fernet

DATA_FILE = "user_data.json"
SALT = b"some_salt"
LOCKOUT_DURATION = 60

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def hash_password(password):
    return base64.b64encode(
        hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000)
    ).decode()

def generate_fernet_key(passkey):
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_text(text, passkey):
    key = generate_fernet_key(passkey)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_text(token, passkey):
    try:
        key = generate_fernet_key(passkey)
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except:
        return None

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

data = load_data()

st.sidebar.title("🔐 Navigation")
choice = st.sidebar.selectbox("Menu", ["Home", "Register", "Login", "Store Data", "Retrieve Data"])

st.title("🔒 Secure Data Encryption System")

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("This app lets you securely store and retrieve encrypted data.")

elif choice == "Register":
    st.subheader("📝 Register")
    username = st.text_input("Enetr a username")
    password = st.text_input("Enter a password", type="password")

    if st.button("Register"):
        if username in data:
            st.warning("User already exists.")
        else:
            data[username] = {
                "password": hash_password(password),
                "data": []
            }
            save_data(data)
            st.success("Registered successfully!")

elif choice == "Login":
    st.subheader("🔐 Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in data and data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"Invalid credentials. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("Locked for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Login required.")
    else:
        st.subheader("📥 Store Encrypted Data")
        plain_text = st.text_area("Enter data")
        passkey = st.text_input("Encryption passkey", type="password")

        if st.button("Encrypt & Save"):
            if plain_text and passkey:
                encrypted = encrypt_text(plain_text, passkey)
                data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(data)
                st.success("Data encrypted and stored!")
            else:
                st.error("All fields are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Login required.")
    else:
        st.subheader("📤 Retrieve Data")
        entries = data[st.session_state.authenticated_user]["data"]

        if not entries:
            st.info("No data stored.")
        else:
            for i, item in enumerate(entries):
                st.code(item)

            encrypted_input = st.text_area("Paste encrypted text")
            passkey = st.text_input("Enter passkey", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted text: {result}")
                else:
                    st.error("Incorrect passkey or corrupted data.")

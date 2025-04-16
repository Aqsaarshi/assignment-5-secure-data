import streamlit as st
import hashlib
import base64
import time
from cryptography.fernet import Fernet
import uuid

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Generate Fernet key from passkey
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Reset failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# Change page helper
def change_page(page):
    st.session_state.current_page = page

# Generate a unique ID
def generate_data_id():
    return str(uuid.uuid4())

# UI Title
st.title("🔐 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Force redirect if attempts exceed
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Reauthorization required.")

# Home Page
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **store and retrieve encrypted data** securely.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")
    
    st.info(f"Stored Entries: {len(st.session_state.stored_data)}")

# Store Data Page
elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match.")
            else:
                data_id = generate_data_id()
                encrypted = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted,
                    "passkey": hash_passkey(passkey)
                }
                st.success("✅ Data stored successfully!")
                st.code(data_id)
                st.info("⚠️ Save your Data ID to retrieve it later.")
        else:
            st.error("⚠️ All fields are required!")

# Retrieve Data Page
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    st.info(f"Attempts Remaining: {3 - st.session_state.failed_attempts}")
    
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passkey, data_id)
                if decrypted:
                    st.success("✅ Decryption Successful!")
                    st.code(decrypted)
                else:
                    st.error(f"❌ Incorrect! Attempts left: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Data ID not found.")
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts. Redirecting...")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("⚠️ All fields are required.")

# Login Page
elif st.session_state.current_page == "Login":
    st.subheader("🔐 Login to Continue")
    if time.time() - st.session_state.last_attempt_time < 10:
        wait_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Wait {wait_time} seconds before retrying.")
    else:
        master_pass = st.text_input("Enter Master Password:", type="password")
        if st.button("Login"):
            if master_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Access Restored!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect Master Password.")

# Footer
st.markdown("---")
st.markdown("🔐 Educational Project | Developed by Aqsa")

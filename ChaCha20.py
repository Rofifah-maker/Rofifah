import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Fungsi enkripsi dan dekripsi
def generate_key():
    return os.urandom(32)

def generate_nonce():
    return os.urandom(16)

def encrypt_chacha20(plaintext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return ciphertext

def decrypt_chacha20(ciphertext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    return plaintext

# --- Streamlit UI ---
st.title("🔐 Enkripsi & Dekripsi dengan ChaCha20")

tab1, tab2 = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

with tab1:
    st.subheader("Masukkan Pesan untuk Dienkripsi")
    plaintext = st.text_area("Pesan Asli", height=150)

    if st.button("Enkripsi"):
        if plaintext:
            key = generate_key()
            nonce = generate_nonce()
            ciphertext = encrypt_chacha20(plaintext, key, nonce)

            st.success("Pesan berhasil dienkripsi!")
            st.text("Ciphertext (Hex):")
            st.code(ciphertext.hex())

            st.text("Key (Base64):")
            st.code(base64.b64encode(key).decode())

            st.text("Nonce (Base64):")
            st.code(base64.b64encode(nonce).decode())

        else:
            st.warning("Masukkan pesan terlebih dahulu!")

with tab2:
    st.subheader("Masukkan Data untuk Dekripsi")

    ciphertext_hex = st.text_area("Ciphertext (Hex)", height=100)
    key_b64 = st.text_input("Key (Base64)")
    nonce_b64 = st.text_input("Nonce (Base64)")

    if st.button("Dekripsi"):
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            key = base64.b64decode(key_b64)
            nonce = base64.b64decode(nonce_b64)

            plaintext = decrypt_chacha20(ciphertext, key, nonce)
            st.success("Pesan berhasil didekripsi!")
            st.text("Pesan Asli:")
            st.code(plaintext)

        except Exception as e:
            st.error(f"Gagal mendekripsi! Pastikan input benar.\n\nError: {e}")

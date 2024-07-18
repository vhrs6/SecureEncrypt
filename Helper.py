import streamlit as st
import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import tempfile
import hashlib
import zipfile
import toml
import smtplib
import ssl
from email.message import EmailMessage



def calculate_hash(image_bytes):
    return hashlib.sha256(image_bytes).hexdigest()



def compress_and_encrypt_image(image, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    _, compressed_image = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, 85])
    compressed_image_bytes = compressed_image.tobytes()

    encrypted_image_bytes = (
        encryptor.update(compressed_image_bytes) + encryptor.finalize()
    )

    return encrypted_image_bytes, iv, calculate_hash(compressed_image_bytes)



def save_key_iv_to_file(key, iv):
    key_iv_text = f"Key: {key}\nIV: {iv.hex()}"
    temp_txt_path = os.path.join(tempfile.gettempdir(), "key_iv.txt")
    with open(temp_txt_path, "w") as temp_txt:
        temp_txt.write(key_iv_text)
    return temp_txt_path



def save_encrypted_image_to_file(encrypted_image_bytes):
    encrypted_image_file = os.path.join(tempfile.gettempdir(), "encrypted_image.enc")
    with open(encrypted_image_file, "wb") as f:
        f.write(encrypted_image_bytes)
    return encrypted_image_file


def create_zip_file(text_file_path, encrypted_image_path):
    zip_file_path = os.path.join(tempfile.gettempdir(), "encrypted_files.zip")
    with zipfile.ZipFile(zip_file_path, "w") as zipf:
        zipf.write(text_file_path, arcname="key_iv.txt")
        zipf.write(encrypted_image_path, arcname="encrypted_image.enc")
    return zip_file_path

def send_email(
    receiver_email, subject, body, text_attachment_path, image_attachment_path
):
    
    
    credentials = toml.load('./pages/credentials.toml')
    sender_email = credentials['email']['sender_email']
    sender_password = credentials['email']['sender_password']

    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.set_content(body)

    with open(text_attachment_path, "rb") as text_attachment:
        msg.add_attachment(
            text_attachment.read(),
            maintype="application",
            subtype="octet-stream",
            filename=os.path.basename(text_attachment_path),
        )

    with open(image_attachment_path, "rb") as image_attachment:
        msg.add_attachment(
            image_attachment.read(),
            maintype="application",
            subtype="octet-stream",
            filename=os.path.basename(image_attachment_path),
        )

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send email: {e}")
        return False


def decrypt_image(encrypted_image_bytes, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()

    decompressed_image_bytes = (
        decryptor.update(encrypted_image_bytes) + decryptor.finalize()
    )

    decompressed_image = cv2.imdecode(
        np.frombuffer(decompressed_image_bytes, np.uint8), cv2.IMREAD_COLOR
    )

    return decompressed_image, calculate_hash(decompressed_image_bytes)

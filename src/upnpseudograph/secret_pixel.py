import io
import logging
import os
import random
import sys

from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from upnpseudograph import utils

"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

log = logging.getLogger(__name__)

def encrypt_data(data, public_key):
    # Generate a random session key
    session_key = os.urandom(32)  # 32 bytes for 256-bit key

    # Derive a symmetric key from the session key
    salt = os.urandom(16)  # 16 bytes for 128-bit salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)

    # Encrypt the data with AES
    iv = os.urandom(16)  # 16 bytes for 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt the session key with RSA
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_session_key, salt, iv, encrypted_data

def decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key):
    # Decrypt the session key with RSA
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Derive the symmetric key from the session key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)

    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data


def encode_bytes(image_bytes, data, public_key=None):
    # Read the original image
    img = Image.open(io.BytesIO(image_bytes))
    width, height = img.size
    log.debug("Attempting to embed %s bytes.", len(data))

    seed = width + height
    prng = random.Random(seed)  # Create a new instance of a random number generator


    # Check if the image is in a mode that can be converted to RGB or RGBA
    if img.mode not in ['RGB', 'RGBA', 'P', 'L']:
        raise ValueError("Image mode must be RGB, RGBA, P (palette-based), or L (grayscale).")

    # Convert to RGB if it's P or L mode (palette-based or grayscale)
    if img.mode == 'P' or img.mode == 'L':
        img = img.convert('RGB')

    # Convert to RGBA if not already in that format
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    # This will give you the original format of the image
    host_format = img.format  

    # If the format is None, try to determine it from the file extension
    if host_format is None:
        raise Exception("NO HOST FORMAT")

    supported_formats = {'TGA', 'TIFF', 'BMP', 'PNG'}
    if host_format not in supported_formats:
        raise Exception("NOT SUPPORTED")

    pixels = np.array(img)

    payload = None

    if public_key:
        # Encrypt the compressed data
        encrypted_session_key, salt, iv, encrypted_data = encrypt_data(data, public_key)

        # Concatenate the encrypted session key, salt, iv, and encrypted data
        payload = (len(data).to_bytes(4, 'big') + encrypted_session_key + salt + iv + encrypted_data)
    else:
        payload = data

    # Calculate the number of pixels needed
    file_size = len(payload)
    num_pixels_required = file_size * 8  # 8 bits per byte
    if num_pixels_required > pixels.size // 4:  # Divide by 4 for RGBA channels
        raise OverflowError("Image is not large enough to hide the data.")

    # Generate a list of unique indices to hide the data
    pixel_indices = list(range(pixels.size // 4))
    prng.shuffle(pixel_indices)  # Shuffle using the seeded PRNG

    # Embed the file size in the first 64 pixels (8 bytes for file size)
    for i in range(64):
        idx = pixel_indices[i]
        bit = (file_size >> (63 - i)) & 0x1
        if (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1) != bit:
            pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] ^= 0x1

    # Embed each bit of the data to encode in the image using LSB matching
    for i, byte in enumerate(payload):
        for bit in range(8):
            idx = pixel_indices[64 + i * 8 + bit]
            if (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1) != ((byte >> (7 - bit)) & 0x1):
                pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] ^= 0x1

    # Save the new image
    new_img = Image.fromarray(pixels, 'RGBA')
    new_img_bytes = io.BytesIO()
    new_img.save(new_img_bytes, format=host_format)
    return new_img_bytes.getvalue()


def extract_bytes(image_bytes, private_key=None):
    try:
        # Read the original image
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode not in ['RGB', 'RGBA']:
            raise ValueError("Image must be in RGB or RGBA format.")
        width, height = img.size

        seed = width + height
        prng = random.Random(seed)  # Create a new instance of a random number generator

        # Convert to RGBA if not already in that format
        if img.mode != 'RGBA':
            img = img.convert('RGBA')

        pixels = np.array(img)

        # Flatten the image array for easier processing
        flat_pixels = pixels.flatten()

        # Use only the red channel for RGBA
        channel_multiplier = 4

        # Extract the file size from the first 64 pixels
        file_size = 0
        for i in range(64):
            file_size = (file_size << 1) | (flat_pixels[i * channel_multiplier] & 0x1)

        # Calculate the number of bytes that can be extracted
        num_bytes_to_extract = file_size

        # Prepare a list to store the extracted bytes
        extracted_bytes = []

        # Generate a list of unique indices to extract the data
        pixel_indices = list(range(pixels.size // 4))
        prng.shuffle(pixel_indices)  # Shuffle using the seeded PRNG

        # Extract the file size from the first 64 pixels
        file_size = 0
        for i in range(64):
            idx = pixel_indices[i]
            file_size = (file_size << 1) | (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1)

        # Calculate the number of bytes that can be extracted
        num_bytes_to_extract = file_size

        # Extract the hidden bits and reconstruct the bytes using the same indices
        extracted_bytes = []
        for i in range(num_bytes_to_extract):
            byte = 0
            for bit in range(8):
                idx = pixel_indices[64 + i * 8 + bit]
                byte = (byte << 1) | (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1)
            extracted_bytes.append(byte)

        # Convert the extracted bytes to a byte array
        data_to_decode = bytes(extracted_bytes)

        if private_key:
            # Determine the size of the encrypted session key based on the private key size
            encrypted_session_key_size = private_key.key_size // 8
            
            # Extract the session key, salt, iv, and encrypted data
            offset = 4
            encrypted_session_key = data_to_decode[offset:offset + encrypted_session_key_size]
            salt = data_to_decode[offset + encrypted_session_key_size:offset + encrypted_session_key_size + 16]
            iv = data_to_decode[offset + encrypted_session_key_size + 16:offset + encrypted_session_key_size + 32]
            encrypted_data = data_to_decode[offset + encrypted_session_key_size + 32:]

            # Decrypt the data
            decrypted_data = decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key)

            return decrypted_data
        else:
            return data_to_decode
    except Exception as e:
        log.debug("Exceptiong %s encountered extracting bytes.", e, exc_info=sys.exc_info())
        return None

if __name__ == '__main__':
    private_key = utils.generate_rsa()
    public_key = private_key.public_key()
    image_bytes = open('test.png', 'rb').read()
    encoded_image = encode_bytes(image_bytes, b'secret', public_key)
    open('test_encrypted.png', 'wb').write(encoded_image)
    decoded_message = extract_bytes(encoded_image, private_key)
    n_bytes = utils.get_compact_key(public_key)
    public_key_image = encode_bytes(image_bytes, n_bytes)
    open('test_n_bytes.png', 'wb').write(public_key_image)
    decoded_n_bytes = extract_bytes(public_key_image)
    assert decoded_n_bytes == n_bytes
    print(decoded_message)

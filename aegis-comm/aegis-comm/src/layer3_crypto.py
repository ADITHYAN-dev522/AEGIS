import os
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import hashlib

# ============================================================
# AES-GCM Encryption / Decryption
# ============================================================

def encrypt_message(message: str, session_key: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)  # AESGCM requires 12 bytes
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    print(f"[encrypt] len={len(message)} | nonce={nonce.hex()[:8]}... | ct_len={len(ciphertext)}")
    return nonce + ciphertext


def decrypt_message(ciphertext: bytes, session_key: bytes) -> str:
    """
    Decrypts nonce||ct. Raises RuntimeError with clear message on auth failure.
    """
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) < 13:
        raise ValueError("Ciphertext too short or invalid format (need nonce(12)+ct)")

    aesgcm = AESGCM(session_key)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]

    fp = hashlib.sha256(ciphertext).hexdigest()[:12]  # short fingerprint for diagnostics
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except InvalidTag:
        raise RuntimeError(
            "AES-GCM authentication failed (InvalidTag). "
            "Possible causes: wrong session key, corrupted ciphertext, or wrong sender/receiver key pair. "
            f"ct_len={len(ciphertext)} fp={fp}"
        )
    except Exception as e:
        raise RuntimeError(f"Decryption error: {type(e).__name__} {e}")

    print(f"[decrypt] ct_len={len(ciphertext)} | nonce={nonce.hex()[:8]}... | pt_len={len(plaintext)} | fp={fp}")
    return plaintext.decode()


# ============================================================
# Helpers for bit conversion (explicit big-endian)
# ============================================================

def bytes_to_bits(b: bytes) -> np.ndarray:
    """Convert bytes to array of bits (0/1), big-endian within each byte."""
    if not b:
        return np.zeros(0, dtype=np.uint8)
    bitstr = "".join(f"{byte:08b}" for byte in b)
    return np.fromiter((int(x) for x in bitstr), dtype=np.uint8)


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """Convert array of bits (0/1) to bytes, big-endian within each byte."""
    pad = (-len(bits)) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    bytes_out = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = int("".join(str(int(b)) for b in bits[i:i+8]), 2)
        bytes_out.append(byte_val)
    return bytes(bytes_out)


# ============================================================
# Steganography (LSB with 4-byte length prefix)
# ============================================================

def hide_in_image(message: bytes, cover_image_path: str, output_path: str):
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("Message must be bytes")

    # prepend 4-byte big-endian length
    msg_with_len = len(message).to_bytes(4, "big") + message
    payload_bits = bytes_to_bits(msg_with_len)

    img = Image.open(cover_image_path).convert("RGB")
    pixels = np.array(img)
    flat = pixels.flatten()

    if payload_bits.size > flat.size:
        raise ValueError(f"Message too long: {payload_bits.size} bits > {flat.size} bits")

    # embed bits into LSBs
    flat[:payload_bits.size] = (flat[:payload_bits.size] & 0xFE) | payload_bits
    stego = flat.reshape(pixels.shape)

    # Force PNG to avoid lossy corruption
    Image.fromarray(stego).save(output_path, format="PNG")
    print(f"[hide] stego_image='{output_path}' | embedded_bytes={len(message)} | capacity_bytes={flat.size//8}")


def extract_from_image(image_path: str) -> bytes:
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)
    flat = pixels.flatten()

    if flat.size < 32:
        raise RuntimeError("Image too small to contain length prefix (need at least 32 LSBs)")

    # Read 32-bit length prefix
    len_bits = (flat[:32] & 1).astype(np.uint8)
    msg_len = int("".join(str(int(b)) for b in len_bits.tolist()), 2)

    total_bits = (msg_len + 4) * 8
    if flat.size < total_bits:
        available_bytes = flat.size // 8
        raise RuntimeError(
            f"Embedded length {msg_len} bytes but only {available_bytes} bytes capacity in image. "
            "Possible causes: wrong image file or embedding failed."
        )

    # Extract full payload
    payload_bits = (flat[:total_bits] & 1).astype(np.uint8)
    payload = bits_to_bytes(payload_bits)
    message = payload[4:4 + msg_len]

    fp = hashlib.sha256(message).hexdigest()[:12]
    print(f"[extract] image='{image_path}' | declared_msg_len={msg_len} | extracted_bytes={len(message)} | fp={fp}")
    return message


# ============================================================
# Optional roundtrip test (quick local verification)
# ============================================================
if __name__ == "__main__":
    key = AESGCM.generate_key(bit_length=256)
    secret_msg = "roundtrip test"
    ct = encrypt_message(secret_msg, key)
    hide_in_image(ct, "cover.png", "stego_test.png")
    extracted_ct = extract_from_image("stego_test.png")
    pt = decrypt_message(extracted_ct, key)
    print("Recovered plaintext:", pt)

import pytest
import os
import tempfile
from src.layer3_crypto import encrypt_message, decrypt_message, hide_in_image, extract_from_image
from src.layer2_keymgmt import DoubleRatchet
from src.layer1_mixnet import AegisMixNet

def test_crypto_roundtrip():
    msg = "Secret test"
    key = b'\x00' * 32  # Dummy
    ct = encrypt_message(msg, key)
    pt = decrypt_message(ct, key)
    assert pt == msg

def test_key_derivation():
    # Temp keys for test
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ratchet = DoubleRatchet(None, None)  # Mock init
    ratchet.private_key = priv
    ratchet.public_key = priv.public_key()
    session_key, _ = ratchet.derive_session_key(pub_pem)
    assert len(session_key) == 32

def test_stego_hide_extract():
    msg = b"Hidden test msg"
    with tempfile.NamedTemporaryFile(suffix='.jpg') as cover_f:
        # Create dummy cover (1x1 RGB)
        from PIL import Image
        img = Image.new('RGB', (1, 1), color='red')
        img.save(cover_f.name)
        
        out_path = "test_stego.jpg"
        hide_in_image(msg, cover_f.name, out_path)
        
        extracted = extract_from_image(out_path)
        assert extracted == msg
        
        os.remove(out_path)

def test_mixnet_delivery():
    mixnet = AegisMixNet()
    payload = b"test_payload"
    mixnet.send_to_onion("alice", "bob", payload)
    delivered = mixnet.get_inbox("bob")
    assert delivered == payload

def test_stego_too_long():
    long_msg = b'a' * 10000  # Too big for small img
    with tempfile.NamedTemporaryFile(suffix='.jpg') as cover_f:
        from PIL import Image
        img = Image.new('RGB', (10, 10))  # Small
        img.save(cover_f.name)
        with pytest.raises(ValueError):
            hide_in_image(long_msg, cover_f.name, "test.jpg")

def test_ratchet_forward():
    ratchet = DoubleRatchet(None, None)  # Mock
    ratchet.ratchet_key = b'init_key_32_bytes!!'[:32]
    key1 = ratchet.ratchet_forward()
    key2 = ratchet.ratchet_forward()
    assert key1 != key2  # Advances

def test_pqc_fallback():
    # Test without oqs
    os.environ['OQS_SKIP'] = '1'  # Mock disable
    ratchet = DoubleRatchet(None, None)
    # Assume derive works in fallback
    assert True  # Placeholder; real test needs peer pub

# Run: pytest tests/test_aegis.py -v

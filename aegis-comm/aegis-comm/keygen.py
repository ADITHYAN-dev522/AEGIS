import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json

KEY_DIR = "config/keys"
ONION_FILE = "config/onion_addresses.json"

os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs("config", exist_ok=True)

# Generate RSA keys for Alice and Bob (pre-distributed)
for name in ["alice", "bob"]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    
    # Private PEM
    with open(f"{KEY_DIR}/{name}_priv.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Public PEM
    with open(f"{KEY_DIR}/{name}_pub.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Mock .onion addresses
onion_data = {
    "alice": "a9b8c7d6e5f4g3h2.aegis.onion",
    "bob": "b0c1d2e3f4g5h6i7.aegis.onion"
}
with open(ONION_FILE, "w") as f:
    json.dump(onion_data, f)

print("Keys and onion addresses generated in config/!")

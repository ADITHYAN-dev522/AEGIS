# =============================================================================
# WARNING — TEST/PROTOTYPE ONLY
#
# This module implements a deterministically derived "session key" for
# testing, debugging, and hackathon/prototyping purposes **only**.
#
# DO NOT USE THIS CODE IN PRODUCTION OR ANY REAL SECURITY DEPLOYMENT.
# The current key-derivation is intentionally simplified so two local
# processes can reproduce the same AES key for development convenience.
# It is **not** a secure authenticated key-agreement:
#   - It is NOT an ECDH or Kyber-based authenticated exchange.
#   - It does NOT protect against active MITM, key substitution, or replay.
#   - It does not perform proper ephemeral key exchange, forward secrecy,
#     identity authentication, or secure key confirmation.
#
# If you are moving beyond prototype, replace this module with a proper
# implementation that meets modern cryptographic best practices:
#   - Use an authenticated key agreement (e.g., X25519/ECDH with signatures
#     for authentication, or a properly integrated Kyber encapsulation).
#   - Use HKDF (not ad-hoc SHA256 concatenation) with context/labels and a
#     unique per-session salt/nonce for key derivation.
#   - Protect private keys at rest (filesystem encryption or hardware keys).
#   - Validate peer identities (certificates or cryptographic signatures).
#   - Rotate keys and implement true double-ratchet or protocol-specific
#     ratcheting for long-lived sessions and forward secrecy.
#   - Use well-reviewed libraries and follow their recommended usage.
#
# This comment exists to prevent accidental promotion of this file into
# production — keep it here and follow the checklist above when hardening.
# =============================================================================

import os
import hashlib
from typing import Tuple

# cryptography imports only for loading keys (we don't perform ECDH here)
from cryptography.hazmat.primitives import serialization

# Optional PQC stub handling (works if oqs-python installed)
try:
    from oqs import KeyEncapsulation
    PQC_ENABLED = True
    # NOTE: Kyber usage is nontrivial to wire correctly across peers; leaving as optional stub.
    kyber = KeyEncapsulation('Kyber512')
except Exception:
    PQC_ENABLED = False
    kyber = None
    # Do not crash — PQC optional for now.


class DoubleRatchet:
    def __init__(self, private_key_path: str, public_key_path: str):
        # load PEM bytes and key objects (we keep PEM bytes for deterministic KDF)
        try:
            with open(private_key_path, "rb") as f:
                self.private_pem = f.read()
                self.private_key = serialization.load_pem_private_key(self.private_pem, password=None)
        except Exception as e:
            raise ValueError(f"Private key load error: {e}")

        try:
            with open(public_key_path, "rb") as f:
                self.public_pem = f.read()
                self.public_key = serialization.load_pem_public_key(self.public_pem)
        except Exception as e:
            raise ValueError(f"Public key load error: {e}")

        # ratchet key for forward secrecy simulation (both sides will have independent ratchet_key)
        self.ratchet_key = os.urandom(32)
        self.step = 0

    def ratchet_forward(self) -> bytes:
        """Advance ratchet deterministically from previous state."""
        self.step += 1
        self.ratchet_key = hashlib.sha256(self.ratchet_key + str(self.step).encode()).digest()
        return self.ratchet_key[:32]

    def derive_session_key(self, peer_public_pem: bytes, use_pqc: bool = False) -> Tuple[bytes, bytes]:
        """
        Derive a session AES key deterministically from both public PEMs so both parties
        produce the same key for testing. Returns (aes_key_bytes, current_ratchet_key).
        WARNING: This is a testing-friendly deterministic derivation — replace with real
        asymmetric key agreement (ECDH or Kyber encapsulation) for production.
        """
        # If PQC requested but unavailable, fall back cleanly
        if use_pqc and PQC_ENABLED and kyber:
            # PQC usage across separate processes requires exchanging and using peer kyber keys properly.
            # For now, we won't attempt to use kyber here because wiring would require network/keyformat changes.
            print("PQC requested but falling back to deterministic hybrid KDF (compat mode).")

        # Deterministic shared secret: order the two public PEM bytes and hash the concatenation.
        a = self.public_pem
        b = peer_public_pem
        if a <= b:
            ordered = a + b
        else:
            ordered = b + a

        shared_secret = hashlib.sha256(ordered).digest()  # 32 bytes

        # Simple KDF: derive AES-256 key deterministically (32 bytes)
        aes_key = hashlib.sha256(shared_secret + b"Aegis session v1").digest()
        return aes_key, self.ratchet_key

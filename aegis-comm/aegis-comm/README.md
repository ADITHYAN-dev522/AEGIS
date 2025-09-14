# Project Aegis: Secure Military Communication Platform

## Overview
Aegis is a prototype for untraceable, steganographic messaging for high-stakes ops (e.g., military). It layers:
- *Anonymity*: Private mix network (simulated).
- *Keys*: Pre-distributed + Double Ratchet for forward secrecy.
- *Crypto*: AES-256-GCM with PQC key exchange.
- *Stego*: LSB hiding in images.

For hackathons: Demo end-to-end send/receive in <5 mins.

## Quick Start
1. pip install -r requirements.txt
2. python keygen.py (generates keys in config/keys/)
3. Sender: python src/aegis_cli.py --mode send --recipient bob --message "Your message here"
   - Outputs: stego_output.jpg (hidden message) + logs routing.
4. Receiver: python src/aegis_cli.py --mode receive --sender alice
   - Extracts/decrypts from stego_output.jpg and prints message.
5. *GUI Demo*: python src/gui.py – Open, switch to Send tab, type message, pick cover image, hit Send. Switch to
   Receive tab to extract/decrypt.

## New: GUI Features
- *Send Tab*: Message input, recipient dropdown (alice/bob), cover image picker, Send button + logs.
- *Receive Tab*: Sender dropdown, Load Stego button, Decrypt display.
- Logs pane for mixnet/processing steps.
- Runs sender/receiver in same window for easy demo.

## Architecture Layers
- *Layer 1*: layer1_mixnet.py - Routes via mock relays.
- *Layer 2*: layer2_keymgmt.py - Handles keys/ratchet.
- *Layer 3*: layer3_crypto.py - Encrypts + hides in image.
- *CLI*: aegis_cli.py - Ties it together.

## Dependencies
See requirements.txt. No extras needed.

## Testing
pytest tests/test_aegis.py

## Limitations (Hackathon Edition)
- Mixnet is local sim (no real P2P).
- Stego is basic LSB (use SteganoGAN for prod).
- PQC is stubbed (full Kyber via oqs-python).
- Keys are file-based (add QR in demo).

## Future Enhancements
- Real Tor integration.
- GUI with Tkinter.
- Hardware token sim (YubiKey).


## Enabling Post-Quantum Cryptography (Optional)
To enable quantum-resistant key exchange with Kyber512 (removing the "No liboqs shared libraries found" warning), install the `liboqs` C library and `oqs-python` wrapper. This is optional—RSA fallback works fine for demos—but adds cutting-edge PQC for quantum threat resistance.

1. **Install Build Dependencies (Kali):**
   ```bash
   sudo apt update
   sudo apt install build-essential cmake libssl-dev git
2. **Clone Github Repo(Kali):**
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
    cd /tmp/liboqs
    cmake -S . -B build -DBUILD_SHARED_LIBS=ON
    cmake --build build --parallel 8
    sudo cmake --install build
    cd ~/aegis-comm
3. **Reinstall oqs-python:**
   source venv/bin/activate  # If not already active
   pip uninstall oqs-python -y
   pip install oqs-python



Built with ❤ for hackathons. Questions? Ping me!

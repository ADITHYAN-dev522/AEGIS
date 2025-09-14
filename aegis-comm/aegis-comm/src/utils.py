# src/utils.py placeholder
import qrcode
from PIL import Image
import io

def generate_qr(data: str, filename: str = None):
    """Generate QR for key exchange demo."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    if filename:
        img.save(filename)
    return img

def load_image(path: str) -> Image.Image:
    return Image.open(path)

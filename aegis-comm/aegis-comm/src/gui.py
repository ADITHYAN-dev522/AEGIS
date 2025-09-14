import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import os, time

import ttkbootstrap as tb
from ttkbootstrap.tooltip import ToolTip
from ttkbootstrap.toast import ToastNotification
from ttkbootstrap.constants import *

from src.layer1_mixnet import AegisMixNet
from src.layer2_keymgmt import DoubleRatchet
from src.layer3_crypto import (
    encrypt_message,
    hide_in_image,
    decrypt_message,
    extract_from_image,
)


class AegisGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Project Aegis – Secure Comms")
        self.root.geometry("820x650")

        # vibrant theme
        style = tb.Style("flatly")

        self.key_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config/keys")
        )

        # HEADER
        header = ttk.Label(
            root,
            text="🛡️ Project Aegis – Next-Gen Secure Communication",
            font=("Segoe UI", 16, "bold"),
            bootstyle="inverse-primary",
            anchor="center",
            padding=10,
        )
        header.pack(fill="x", pady=(0, 10))

        # Notebook for tabs
        notebook = ttk.Notebook(root, bootstyle="primary")
        notebook.pack(fill="both", expand=True, padx=15, pady=10)

        # Send Tab
        self.send_frame = ttk.Frame(notebook, padding=15)
        notebook.add(self.send_frame, text="✉️ Send")
        self.setup_send_tab()

        # Receive Tab
        self.receive_frame = ttk.Frame(notebook, padding=15)
        notebook.add(self.receive_frame, text="📥 Receive")
        self.setup_receive_tab()

        # Logs
        ttk.Label(root, text="🔎 Activity Logs", font=("Segoe UI", 11, "bold")).pack(
            anchor="w", padx=15, pady=(10, 2)
        )
        self.logs = scrolledtext.ScrolledText(root, height=8, font=("Consolas", 10))
        self.logs.pack(fill="x", padx=15, pady=5)

        # Progress Bar
        self.progress = ttk.Progressbar(
            root, mode="indeterminate", bootstyle="info-striped"
        )
        self.progress.pack(fill="x", padx=15, pady=5)

        # Status Bar
        self.status = ttk.Label(root, text="✅ Ready", anchor="w", bootstyle="inverse-dark")
        self.status.pack(side="bottom", fill="x")

    def log(self, msg):
        self.logs.insert(tk.END, f"{msg}\n")
        self.logs.see(tk.END)
        self.status.config(text=msg)

    def toast(self, title, msg, bootstyle="success"):
        """Show non-blocking toast notification"""
        ToastNotification(
            title=title,
            message=msg,
            duration=3000,
            bootstyle=bootstyle,
            position=(10, 70, "ne"),
        ).show_toast()

    # ===================== SEND TAB =====================

    def setup_send_tab(self):
        ttk.Label(self.send_frame, text="Recipient:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", padx=10, pady=5
        )
        self.recip_var = tk.StringVar(value="bob")
        recip_combo = ttk.Combobox(
            self.send_frame,
            textvariable=self.recip_var,
            values=["alice", "bob"],
            state="readonly",
            width=15,
        )
        recip_combo.grid(row=0, column=1, sticky="w", padx=10, pady=5)
        ToolTip(recip_combo, "Choose recipient for your encrypted message")

        ttk.Label(self.send_frame, text="Message:", font=("Segoe UI", 10, "bold")).grid(
            row=1, column=0, sticky="nw", padx=10, pady=5
        )
        self.msg_entry = tk.Text(self.send_frame, height=4, width=55, wrap="word")
        self.msg_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Button(
            self.send_frame, text="📂 Pick Cover Image", command=self.pick_cover, bootstyle="info-outline"
        ).grid(row=2, column=0, pady=5, sticky="w")
        self.cover_var = tk.StringVar(value="../sample_cover.png")
        ttk.Label(self.send_frame, textvariable=self.cover_var).grid(
            row=2, column=1, sticky="w"
        )

        ttk.Button(
            self.send_frame, text="🚀 Send Securely", command=self.send_msg, bootstyle="success"
        ).grid(row=3, column=1, pady=10, sticky="e")

    # ===================== RECEIVE TAB =====================

    def setup_receive_tab(self):
        ttk.Label(
            self.receive_frame, text="Sender:", font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.sender_var = tk.StringVar(value="alice")
        sender_combo = ttk.Combobox(
            self.receive_frame,
            textvariable=self.sender_var,
            values=["alice", "bob"],
            state="readonly",
            width=15,
        )
        sender_combo.grid(row=0, column=1, sticky="w", padx=10, pady=5)
        ToolTip(sender_combo, "Select sender to decrypt from")

        ttk.Button(
            self.receive_frame, text="📂 Load Stego Image", command=self.pick_stego, bootstyle="warning-outline"
        ).grid(row=1, column=0, pady=5, sticky="w")
        self.stego_var = tk.StringVar()
        ttk.Label(self.receive_frame, textvariable=self.stego_var).grid(
            row=1, column=1, sticky="w"
        )

        ttk.Button(
            self.receive_frame, text="🔓 Decrypt Message", command=self.receive_msg, bootstyle="danger"
        ).grid(row=2, column=1, pady=10, sticky="e")

        self.decrypted_label = ttk.Label(
            self.receive_frame, text="Decrypted: ", font=("Segoe UI", 11, "italic")
        )
        self.decrypted_label.grid(row=3, column=0, columnspan=2, pady=5)

    # ===================== FILE PICKERS =====================

    def pick_cover(self):
        file = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if file:
            self.cover_var.set(file)

    def pick_stego(self):
        file = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if file:
            self.stego_var.set(file)

    # ===================== SEND =====================

    def send_msg(self):
        sender = "alice" if self.recip_var.get() == "bob" else "bob"
        recipient = self.recip_var.get()
        message = self.msg_entry.get("1.0", tk.END).strip()
        cover = self.cover_var.get()

        if not message or not os.path.exists(cover):
            messagebox.showerror("Error", "Message or cover image missing!")
            return

        try:
            self.progress.start()
            self.log("🔒 Encrypting and hiding message...")
            ratchet = DoubleRatchet(
                f"{self.key_dir}/{sender}_priv.pem", f"{self.key_dir}/{sender}_pub.pem"
            )
            peer_pub = open(f"{self.key_dir}/{recipient}_pub.pem", "rb").read()
            session_key, _ = ratchet.derive_session_key(peer_pub, use_pqc=True)

            nonce_ct = encrypt_message(message, session_key)
            stego_out = f"stego_{sender}_{int(time.time())}.png"
            hide_in_image(nonce_ct, cover, stego_out)

            mixnet = AegisMixNet()
            mixnet.send_to_onion(sender, recipient, nonce_ct)

            self.log(f"✅ Sent: {message}")
            self.msg_entry.delete("1.0", tk.END)
            self.toast("Success", f"Message hidden in {stego_out}", "success")
        except Exception as e:
            self.log(f"❌ Send error: {e}")
            self.toast("Error", str(e), "danger")
        finally:
            self.progress.stop()

    # ===================== RECEIVE =====================

    def receive_msg(self):
        sender = self.sender_var.get()
        recipient = "bob" if sender == "alice" else "alice"
        stego = self.stego_var.get()

        if not stego:
            messagebox.showerror("Error", "Stego image missing!")
            return

        try:
            self.progress.start()
            self.log("🔑 Extracting and decrypting...")
            ratchet = DoubleRatchet(
                f"{self.key_dir}/{recipient}_priv.pem",
                f"{self.key_dir}/{recipient}_pub.pem",
            )
            peer_pub = open(f"{self.key_dir}/{sender}_pub.pem", "rb").read()
            session_key, _ = ratchet.derive_session_key(peer_pub, use_pqc=True)

            nonce_ct = extract_from_image(stego)
            decrypted = decrypt_message(nonce_ct, session_key)

            self.decrypted_label.config(text=f"Decrypted: {decrypted}")
            self.log(f"📩 Received: {decrypted}")
            self.toast("Decryption Success", decrypted, "info")
        except Exception as e:
            self.log(f"❌ Receive error: {e}")
            self.toast("Error", str(e), "danger")
        finally:
            self.progress.stop()


if __name__ == "__main__":
    try:
        root = tb.Window(themename="flatly")  # vibrant theme
        app = AegisGUI(root)
        root.mainloop()
    except Exception as e:
        print("Fatal GUI error:", e)

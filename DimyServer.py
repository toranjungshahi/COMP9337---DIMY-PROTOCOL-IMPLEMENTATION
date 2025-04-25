# -*- coding: utf-8 -*-
"""
Toran Shahi z5342008 William William z5268184
"""

import socket
import threading
from bitarray import bitarray
import sys


class BackendServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cbfs = {}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()

            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()

    def handle_client(self, conn, addr):
        print(f"New connection from {addr}")
        try:
            with conn:
                data = conn.recv(1024)  # Receive up to 1024 bytes
                if data:
                    node_id, message_type, bf_data = data.split(b":", 2)
                    node_id = int(node_id.decode())
                    bf = bitarray()
                    bf.frombytes(bf_data)

                    if message_type == b"QBF":
                        print(f"Received QBF from Node {node_id}")
                        result = self.match_qbf(node_id, bf)
                    elif message_type == b"CBF":
                        print(f"Received CBF from Node {node_id}")
                        result = self.add_cbf(node_id, bf)
                    else:
                        result = "Unknown message type"

                    print(f"Sending result to Node {node_id}: {result}")
                    conn.sendall(result.encode())
        except Exception as e:
            print(f"Error handling client {addr}: {e}")

    def match_qbf(self, node_id, qbf):
        print(f"Performing QBF-CBF matching operation for Node {node_id}")
        if not self.cbfs:
            return "No matches found"
        for cbf_node_id, cbf in self.cbfs.items():
            if (
                cbf_node_id != node_id and (qbf & cbf) == cbf
            ):  # If CBF is a subset of QBF
                return f"Potential COVID-19 exposure detected (contact with Node {cbf_node_id})"
        return "No matches found"

    def add_cbf(self, node_id, cbf):
        self.cbfs[node_id] = cbf
        return f"CBF received and stored successfully for Node {node_id}"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <server_port>")
        sys.exit(1)

    server_port = int(sys.argv[1])
    server = BackendServer("127.0.0.1", server_port)
    server.start()
# COMP9337 / Implementation of DIMY protocol

 This project implements the DIMY (Did I Meet You) protocol, a privacy-preserving digital contact
 tracing system developed in response to the COVID-19 pandemic. The system utilizes advanced
 cryptographic techniques including Ephemeral IDs, Shamir’s Secret Sharing, and Diffie-Hellman key
 exchange to enable secure proximity detection between mobile devices without compromising individual
 privacy. A key innovation is the use of Bloom filters for efficient storage and querying of encounter
 data while maintaining a small memory footprint. The implementation simulates the original DIMY
 protocol by running 3 DIMY nodes, a centralised backend server and an attacker node on same host.

 While successfully demonstrating the core concepts of the original DIMY protocol, the implementation
 has used UDP broadcasting instead of Bluetooth Low Energy for simulation purpose. The project provides 
 valuable insights into the feasibility of privacy-conscious contact tracing systems and the challenges 
 involved in their design and implementation. It represents a significant step forward in balancing public
 health needs with individual privacy and system efficiency in the face of infectious disease outbreaks.

This is a combined work of myself and [William](https://github.com/WilliamDjo)

## Usage

To run the DIMY implementation, follow these steps:

 1. Ensure Python 3.7+ is installed on your system.
 2. Install required packages:
```
 pip install cryptography sslib bitarray mmh3
```
 3. Start the backend server:
```
 python DimyServer.py <server_port>
```
 4. Run multiple instances of the DIMY node:
```
 python Dimy.py <server_ip> <server_port> <node_number> <receiver_port>
```
Or can use run_3nodes.py file to run three Dimy nodes simultaneously.
```python run_3nodes.py
```
 5. To run the attacker node:
```python Attacker .py <server_ip> <server_port> <port_to_attack>
```
 Replace <server_ip>, <server_port>, <node_number>, <receiver_port>, and <port_to_attack>
 with appropriate values.


## Successfully Implemented Features

 - EphID generation and broadcasting using UDP
 - Shamir’s Secret Sharing (3-out-of-5) for EphID distribution
 - EphID reconstruction from received shares
 - EncID creation using Diffie-Hellman key exchange
 - Daily Bloom Filters (DBFs) for storing EncIDs
 - Query Bloom Filters (QBFs) for querying exposure risk
 - Contact Bloom Filters (CBFs) for reporting positive cases
 - Backend server for handling QBF and CBF uploads
 - Message drop mechanism to simulate packet loss
 - Attacker node capable of intercepting and reconstructing EphIDs
 
##  Features with Limitations

 - The simulation runs for a shorter duration than the real-world scenario
 - Bluetooth Low Energy (BLE) communication is simulated using UDP broadcasting
 - The backend server uses a centralized design instead of a blockchain

 ## Design Trade-offs and Special Features

 **Design Trade-offs**

 - Used UDP broadcasting instead of BLE for simplicity and cross-platform compatibility
 - Implemented a centralized server instead of a blockchain for easier development and testing
 - Shortened time intervals (e.g., 90 seconds for DBF instead of a day) to facilitate testing
 - Since the simulation is implemented with multiple nodes running on same host the code is creating
 new sender and receiver processes every 15 seconds. Whereas, if simulated by running nodes in
 different host, just starting a single sender and receiver process/method at the start of the node
 would suffice.

 **Special Features**

 - Multi-threaded design allowing simultaneous broadcasting, receiving, and user input handling
 - Flexible configuration of Bloom filter sizes and hash functions
 - Comprehensive logging for debugging and demonstration purposes

## Possible Improvements

 - Implement actual BLE communication for more realistic simulation
 - Use a distributed ledger or blockchain for the backend to enhance security and decentralization
 - Optimize Bloom filter parameters for better space efficiency and lower false positive rates
 - Implement more robust error handling and recovery mechanisms
 - Add unit tests and integration tests for better code quality assurance
 - Borrowed Code Segments

 ## The implementation uses the following third-party libraries:

 - cryptography for cryptographic operations
 - sslib for Shamir’s Secret Sharing
 - bitarray for efficient bit array operations
 - mmh3 for Murmur3 hash function used in Bloom filters

 No substantial code segments were directly borrowed from external sources. The implementation
 is based on the DIMY protocol description provided in the assignment specification and the referenced
 paper.

## Note on Attacker.py

 While the Attacker.py successfully demonstrates the interception of EphIDs and construction of EncID,
 the sending of CBF is not fully functional in the current implementation. However, if it were fully
 operational, the attacker would be able to create and send a fake Contact Bloom Filter (CBF) to the
 backend server. This capability could potentially allow the attacker to:

 1. Report false positive COVID-19 cases, causing unnecessary alerts and panic.
 2. Track specific individuals by crafting CBFs with targeted EncIDs.
 3. Overwhelm the system with fake reports, potentially causing a denial of service.

 These potential attack vectors highlight the importance of implementing robust authentication and
 validation mechanisms in the backend server to prevent such malicious activities in real-world contact
 tracing systems.

## [Demonstration Video](https://youtu.be/5cX5PKoUveQ)

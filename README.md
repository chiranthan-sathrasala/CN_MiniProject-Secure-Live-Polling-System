# Secure Live Polling and Voting System

## Project Overview
This project implements a secure networked application using low-level socket programming over UDP. It features multiple concurrent clients, custom binary packet formatting, duplicate vote detection, and strictly utilizes DTLS (Datagram Transport Layer Security) for all data exchanges.

## Architecture
* **Server:** Python script running on an Ubuntu VM, bound to `0.0.0.0:5005`.
* **Clients:** Python scripts distributed across the local network.
* **Protocol:** UDP (`SOCK_DGRAM`) wrapped in DTLS (`python3-dtls`).

## Setup Steps
1. **Prerequisites:** Ensure Python 3 is installed.
2. **Install Dependencies:** Run `pip install python3-dtls` on all machines.
3. **Generate Security Certificates (Server Only):** Run the following OpenSSL command in the server directory:
   `openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt`

## Usage Instructions
1. **Start the Server:** Execute `python3 server.py` on the host machine.
2. **Configure Clients:** Open `client.py` and modify the `SERVER_HOST` variable to match the server's IP address.
3. **Start the Clients:** Execute `python3 client.py` on client machines and follow the on-screen voting prompts.

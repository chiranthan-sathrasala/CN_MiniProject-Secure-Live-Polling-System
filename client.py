import socket
import threading
import time
import random
import ssl

# Injects the missing 'wrap_socket' function so the dtls wrapper can execute safely.
if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext().wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import create_packet

# Patch the standard Python sockets to support UDP over DTLS
do_patch()

SERVER_HOST = "192.168.0.104" 
SERVER_PORT = 5005

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}

# Generate a random 4-digit ID to simulate a unique voter for testing
VOTER_ID = random.randint(1000, 9999)
seq_num = 0
listening = True

def get_secure_socket():
    """Creates a fresh, encrypted DTLS connection to the server."""
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Wrap the socket. cert_reqs=ssl.CERT_NONE is CRITICAL here because 
    # we are using a self-signed college certificate, which Windows will otherwise reject.
    secure_sock = SSLConnection(raw_sock, cert_reqs=ssl.CERT_NONE)
    # Perform the DTLS handshake to establish the secure tunnel
    secure_sock.connect((SERVER_HOST, SERVER_PORT))
    return secure_sock

def poll_live_results():
    # Background thread that actively asks the server for live results every 5 seconds
    global listening
    while listening:
        time.sleep(5)
        try:
            # Securely connect and send the GET_RESULTS command
            sock = get_secure_socket()
            sock.write(b"GET_RESULTS")
            # Read and print the broadcasted results
            data = sock.read(4096)
            print(data.decode())
        except:
            # Silently ignore timeouts to avoid spamming the user's console
            pass

def send_vote(candidate_id):
    # Packs and encrypts the user's vote before sending it over the network
    global seq_num
    seq_num += 1
    # 1. Create the 19-byte binary packet using the logic from packet.py
    packet = create_packet(
        voter_id=VOTER_ID,
        seq_num=seq_num,
        candidate_id=candidate_id
    )
    print(f"[CLIENT] Encrypting and sending secure vote for {CANDIDATES[candidate_id]}...")
    try:
        # 2. Get a secure connection and send the encrypted binary packet
        sock = get_secure_socket()
        sock.write(packet)
        # 3. Wait to receive the server's acknowledgment
        data = sock.read(1024)
        message = data.decode()
        # 4. Process the server's response
        if message.startswith("ACK"):
            print("[ACK] Server securely acknowledged the vote!")
        elif message == "DUPLICATE":
            print("[REJECTED] The server detected that you already voted.")
        elif message == "INVALID_CANDIDATE":
            print("[ERROR] Invalid candidate selected.")
    except Exception as e:
        print(f"[ERROR] Failed to send vote: {e}")

def start_client():
    """Main User Interface loop for the voter."""
    global listening
    print("\n----------------------------------")
    print(" SECURE POLLING CLIENT STARTED")
    print(" Voter ID:", VOTER_ID)
    print("----------------------------------")
    # Start the background thread to fetch live results concurrently
    listener = threading.Thread(target=poll_live_results, daemon=True)
    listener.start()
    try:
        while True:
            # Provide an interactive menu for the user
            print("\n[1] Alice  [2] Bob  [3] Charlie  [q] Quit")
            choice = input("Choice: ").strip().lower()
            if choice == "q":
                break
            elif choice in ["1", "2", "3"]:
                send_vote(int(choice))
            else:
                print("Invalid choice, please try again.")
    except KeyboardInterrupt:
        pass
    finally:
        # Stop the background thread and exit cleanly
        listening = False
        print("\n[CLIENT] Disconnecting from secure server...")

if __name__ == "__main__":
    start_client()
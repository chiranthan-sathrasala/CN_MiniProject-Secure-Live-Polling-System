import socket
import threading
import ssl

# This "monkey patch" safely injects it back so the older dtls library doesn't crash.
if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext().wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import parse_packet
from stats import Stats

# Patch the standard Python sockets to support UDP over DTLS
do_patch()

# HOST is set to 0.0.0.0 to listen on all available network interfaces (crucial for VMs)
HOST = '0.0.0.0'
PORT = 5005

stats = Stats()
# We use a Lock to prevent race conditions. If multiple clients vote at the 
# exact same millisecond, this lock ensures they don't corrupt the tally.
stats_lock = threading.Lock()

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}

def handle_secure_client(secure_conn, addr):
    # Handles the secure communication and logic for a single client connection.
    try:
        # 1. Read the encrypted data from the client
        data = secure_conn.read(1024)
        # 2. Check if the client is just actively polling for live results
        if data == b"GET_RESULTS":
            with stats_lock:
                results = stats.votes_per_candidate.copy()
            # Format the live tally to send back
            lines = ["\n=== SECURE LIVE RESULTS ==="]
            for cid, name in CANDIDATES.items():
                count = results.get(cid, 0)
                lines.append(f"  {name}: {count} vote(s)")
            lines.append("===========================\n")
            secure_conn.write("\n".join(lines).encode())
            return
        # 3. If it is not a GET_RESULTS request, it must be a vote packet
        with stats_lock:
            stats.record_received()
        # Parse the custom 19-byte binary packet
        parsed = parse_packet(data)
        if parsed is None:
            with stats_lock:
                stats.record_corrupted()
            print(f"[CORRUPTED] Packet received from {addr[0]}")
            return
        voter_id = parsed['voter_id']
        candidate = parsed['candidate_id']
        seq_num = parsed['seq_num']
        # 4. Safely check for duplicates and update the statistics
        with stats_lock:
            if stats.is_duplicate(voter_id):
                stats.record_duplicate()
                secure_conn.write(b"DUPLICATE")
                print(f"[DUPLICATE] Voter {voter_id} already voted")
                return
            if candidate not in CANDIDATES:
                secure_conn.write(b"INVALID_CANDIDATE")
                return
            stats.record_vote(candidate)
        name = CANDIDATES[candidate]
        print(f"[SECURE VOTE] Voter {voter_id} securely voted for {name}")
        # 5. Send a secure acknowledgment (ACK) back to the client
        ack = f"ACK:{seq_num}".encode()
        secure_conn.write(ack)
    except Exception as e:
        print(f"[ERROR] Connection issue with {addr[0]}: {e}")
    finally:
        # Always gracefully close the secure session when finished
        secure_conn.shutdown()
        secure_conn.close()

def start_server():
    # 1. Create a raw, low-level UDP socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
    # 2. Wrap the raw socket in a secure DTLS layer using our self-signed certificates
    secure_server_sock = SSLConnection(
        raw_sock,
        keyfile="server.key",
        certfile="server.crt",
        server_side=True
    )
    print("=======================================")
    print(" SECURE DTLS LIVE POLLING SERVER STARTED")
    print(" Listening on port", PORT)
    print("=======================================\n")
    try:
        while True:
            # Accept an incoming secure DTLS connection
            secure_conn, addr = secure_server_sock.accept()
            # Spawn a new daemon thread for each client to handle multiple voters concurrently
            t = threading.Thread(
                target=handle_secure_client,
                args=(secure_conn, addr)
            )
            t.daemon = True
            t.start()
            
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        # Print the final stats report when the professor ends the demo
        with stats_lock:
            stats.report()
    finally:
        secure_server_sock.close()

if __name__ == "__main__":
    start_server()
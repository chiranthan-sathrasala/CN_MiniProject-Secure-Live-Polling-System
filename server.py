import socket
import threading
from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import parse_packet
from stats import Stats

do_patch()

HOST = '10.152.252.100'
PORT = 5005

stats = Stats()
stats_lock = threading.Lock()

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}

def handle_secure_client(secure_conn, addr):
    try:
        data = secure_conn.read(1024)
        if data == b"GET_RESULTS":
            with stats_lock:
                results = stats.votes_per_candidate.copy()
            lines = ["\n=== SECURE LIVE RESULTS ==="]
            for cid, name in CANDIDATES.items():
                count = results.get(cid, 0)
                lines.append(f"{name}: {count} vote(s)")
            lines.append("===========================\n")
            secure_conn.write("\n".join(lines).encode())
            return
        with stats_lock:
            stats.record_received()
        parsed = parse_packet(data)
        if parsed is None:
            with stats_lock:
                stats.record_corrupted()
            print("[CORRUPTED] Packet received")
            return
        voter_id = parsed['voter_id']
        candidate = parsed['candidate_id']
        seq_num = parsed['seq_num']
        with stats_lock:
            if stats.is_duplicate(voter_id):
                stats.record_duplicate()
                secure_conn.write(b"DUPLICATE")
                print("[DUPLICATE] voter already voted")
                return
            if candidate not in CANDIDATES:
                secure_conn.write(b"INVALID_CANDIDATE")
                return
            stats.record_vote(candidate)
        name = CANDIDATES[candidate]
        print(f"[SECURE VOTE] Voter {voter_id} voted for {name}")
        ack = f"ACK:{seq_num}".encode()
        secure_conn.write(ack)
    except Exception as e:
        print("[ERROR]", e)
    finally:
        secure_conn.shutdown()
        secure_conn.close()

def start_server():
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
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
            secure_conn, addr = secure_server_sock.accept()
            t = threading.Thread(
                target=handle_secure_client,
                args=(secure_conn, addr)
            )
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        with stats_lock:
            stats.report()
    finally:
        secure_server_sock.close()

if __name__ == "__main__":
    start_server()
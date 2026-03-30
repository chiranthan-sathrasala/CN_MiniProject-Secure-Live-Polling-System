import socket
import threading
import ssl
import time

if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext().wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import parse_packet
from stats import Stats

do_patch()

HOST = '0.0.0.0'
PORT = 5005
CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}

stats = Stats()
stats_lock = threading.Lock()

# --- ELECTION STATE MANAGEMENT ---
# States: WAITING, ACTIVE, CLOSED
election_state = "WAITING" 
state_lock = threading.Lock()
timer_thread = None

def election_timer():
    """Runs in the background. Closes the election after 120 seconds."""
    global election_state
    time.sleep(120)
    with state_lock:
        if election_state == "ACTIVE":
            election_state = "CLOSED"
            print("\n[SERVER] 120 seconds reached. Election AUTO-CLOSED.")
            print("[SERVER] You can now type 'REPORT' to view final stats locally.\n> ", end="")

def admin_console():
    """Allows the professor/admin to START or STOP the election from the terminal."""
    global election_state, timer_thread
    while True:
        cmd = input("").strip().upper()
        with state_lock:
            if cmd == "START" and election_state == "WAITING":
                election_state = "ACTIVE"
                print("\n[SERVER] Election is now ACTIVE! Accepting votes for 2 minutes...")
                timer_thread = threading.Thread(target=election_timer, daemon=True)
                timer_thread.start()
            elif cmd == "STOP" and election_state == "ACTIVE":
                election_state = "CLOSED"
                print("\n[SERVER] Election stopped early by Admin. Polls are CLOSED.")
            elif cmd == "REPORT":
                stats.report()
            else:
                print(f"[SERVER] Unknown command or invalid state. Current state: {election_state}")
        print("> ", end="")

def handle_secure_client(secure_conn, addr):
    """Handles client requests depending on the current Election Phase."""
    global election_state
    try:
        data = secure_conn.read(1024)
        if not data: return

        with state_lock:
            current_state = election_state

        # 1. Handle live status polling from the client GUI
        if data == b"GET_RESULTS":
            if current_state == "WAITING":
                secure_conn.write(b"STATE:WAITING")
            elif current_state == "ACTIVE":
                # BLIND ELECTION: Only send the total number of votes cast
                with stats_lock:
                    total = stats.total_valid_votes()
                secure_conn.write(f"STATE:ACTIVE|TOTAL:{total}".encode())
            elif current_state == "CLOSED":
                # FINAL RESULTS: Send the full breakdown
                with stats_lock:
                    results = stats.votes_per_candidate.copy()
                # Format: STATE:CLOSED|Alice:2,Bob:1,Charlie:0
                res_str = ",".join([f"{CANDIDATES[cid]}:{results.get(cid, 0)}" for cid in CANDIDATES])
                secure_conn.write(f"STATE:CLOSED|{res_str}".encode())
            return

        # 2. Handle actual vote packets
        if current_state != "ACTIVE":
            secure_conn.write(b"REJECTED:NOT_ACTIVE")
            return

        with stats_lock:
            stats.record_received()

        parsed = parse_packet(data)
        if parsed is None:
            return

        voter_id = parsed['voter_id']
        candidate = parsed['candidate_id']
        seq_num = parsed['seq_num']

        with stats_lock:
            if stats.is_duplicate(voter_id):
                secure_conn.write(b"DUPLICATE")
                return
            if candidate not in CANDIDATES:
                secure_conn.write(b"INVALID_CANDIDATE")
                return
            stats.record_vote(candidate)
            
        secure_conn.write(f"ACK:{seq_num}".encode())
        print(f"[VOTE] Processed secure vote from Voter {voter_id}")

    except Exception:
        pass
    finally:
        try:
            secure_conn.shutdown()
            secure_conn.close()
        except:
            pass

def start_server():
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
    
    secure_server_sock = SSLConnection(raw_sock, keyfile="server.key", certfile="server.crt", server_side=True)
    
    print("\n==============================================")
    print("    SECURE DTLS LIVE POLLING SERVER STARTED   ")
    print("==============================================")
    print(" Admin Commands:")
    print("  - Type 'START' to open the election (120s max)")
    print("  - Type 'STOP'  to close it early")
    print("  - Type 'REPORT' to view stats at the end")
    print("==============================================\n> ", end="")

    # Start the Admin Command listener in the background
    threading.Thread(target=admin_console, daemon=True).start()

    try:
        while True:
            secure_conn, addr = secure_server_sock.accept()
            threading.Thread(target=handle_secure_client, args=(secure_conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
    finally:
        secure_server_sock.close()

if __name__ == "__main__":
    start_server()
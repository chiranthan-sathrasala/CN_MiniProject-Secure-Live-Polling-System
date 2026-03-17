import socket
import threading
import time
import random
from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import create_packet

do_patch()

SERVER_HOST = "10.152.252.24"
SERVER_PORT = 5005

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}

VOTER_ID = random.randint(1000, 9999)
seq_num = 0
listening = True


def get_secure_socket():
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    secure_sock = SSLConnection(raw_sock)
    secure_sock.connect((SERVER_HOST, SERVER_PORT))
    return secure_sock


def poll_live_results():
    global listening
    while listening:
        time.sleep(5)
        try:
            sock = get_secure_socket()
            sock.write(b"GET_RESULTS")
            data = sock.read(4096)
            print(data.decode())
        except:
            pass


def send_vote(candidate_id):
    global seq_num
    seq_num += 1
    packet = create_packet(
        voter_id=VOTER_ID,
        seq_num=seq_num,
        candidate_id=candidate_id
    )
    print(f"[CLIENT] Sending secure vote for {CANDIDATES[candidate_id]}")
    try:
        sock = get_secure_socket()
        sock.write(packet)
        data = sock.read(1024)
        message = data.decode()
        if message.startswith("ACK"):
            print("[ACK] Server acknowledged vote")
        elif message == "DUPLICATE":
            print("[REJECTED] You already voted")
        elif message == "INVALID_CANDIDATE":
            print("[ERROR] Invalid candidate")
    except Exception as e:
        print("[ERROR]", e)

def start_client():
    global listening
    print("\n----------------------------------")
    print(" SECURE POLLING CLIENT STARTED")
    print(" Voter ID:", VOTER_ID)
    print("----------------------------------")
    listener = threading.Thread(target=poll_live_results, daemon=True)
    listener.start()
    try:
        while True:
            print("\n[1] Alice  [2] Bob  [3] Charlie  [q] Quit")
            choice = input("Choice: ").strip().lower()
            if choice == "q":
                break
            elif choice in ["1", "2", "3"]:
                send_vote(int(choice))
            else:
                print("Invalid choice")
    except KeyboardInterrupt:
        pass
    finally:
        listening = False
        print("\n[CLIENT] Disconnecting...")

if __name__ == "__main__":
    start_client()
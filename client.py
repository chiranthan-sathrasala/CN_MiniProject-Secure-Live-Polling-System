import socket
import threading
import time
import random
import ssl

# Injects the missing wrap_socket so the dtls wrapper can execute safely
# on Python 3.12+ where ssl.wrap_socket was removed.
if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext().wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import create_packet

# Patch the standard Python sockets to support UDP over DTLS
do_patch()

SERVER_HOST = "192.168.0.104"   # ← update to match the server's IP
SERVER_PORT = 5005

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}

# Generate a random 4-digit ID to simulate a unique voter
VOTER_ID = random.randint(1000, 9999)
seq_num = 0
listening = True

# Maximum number of send retries before giving up on a vote
MAX_RETRIES = 3
# Per-connection socket timeout in seconds
SOCK_TIMEOUT = 8
# Interval between background result polls
POLL_INTERVAL = 5


def get_secure_socket():
    """
    Creates a fresh, encrypted DTLS connection to the server.
    cert_reqs=ssl.CERT_NONE is required because we use a self-signed certificate.
    Raises on failure — callers must handle exceptions.
    """
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.settimeout(SOCK_TIMEOUT)
    secure_sock = SSLConnection(raw_sock, cert_reqs=ssl.CERT_NONE)
    secure_sock.connect((SERVER_HOST, SERVER_PORT))
    return secure_sock


def poll_live_results():
    """
    Background thread: polls the server for live vote counts every POLL_INTERVAL seconds.
    Errors are swallowed silently so they don't interrupt the voting UI.
    """
    global listening
    while listening:
        time.sleep(POLL_INTERVAL)
        if not listening:
            break
        try:
            sock = get_secure_socket()
            sock.write(b"GET_RESULTS")
            data = sock.read(4096)
            print(data.decode())
        except ssl.SSLError as e:
            # DTLS handshake failure while polling — non-fatal
            pass
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            try:
                sock.shutdown()
                sock.close()
            except Exception:
                pass


def send_vote(candidate_id):
    """
    Builds the 19-byte binary packet, encrypts it via DTLS,
    and sends it to the server with up to MAX_RETRIES attempts.
    Reports the round-trip time for each successful attempt.
    """
    global seq_num

    if candidate_id not in CANDIDATES:
        print(f"[ERROR] Unknown candidate id: {candidate_id}")
        return

    seq_num += 1

    try:
        packet = create_packet(
            voter_id=VOTER_ID,
            seq_num=seq_num,
            candidate_id=candidate_id
        )
    except ValueError as e:
        print(f"[ERROR] Could not create packet: {e}")
        return

    print(f"[CLIENT] Encrypting and sending vote for {CANDIDATES[candidate_id]}...")

    for attempt in range(1, MAX_RETRIES + 1):
        sock = None
        try:
            t_start = time.time()

            # Establish a fresh DTLS connection for each vote (connectionless UDP)
            sock = get_secure_socket()
            sock.write(packet)

            # Wait for the server's response
            data = sock.read(1024)
            rtt_ms = (time.time() - t_start) * 1000
            message = data.decode()

            # Process the server's response
            if message.startswith("ACK"):
                print(f"[ACK] Vote acknowledged by server  (RTT={rtt_ms:.1f}ms)")
                return
            elif message == "DUPLICATE":
                print("[REJECTED] Server: you have already voted.")
                return
            elif message == "INVALID_CANDIDATE":
                print("[ERROR] Server rejected: invalid candidate.")
                return
            elif message == "CORRUPTED":
                print(f"[WARN] Server: packet was corrupted (attempt {attempt}/{MAX_RETRIES})")
                # Retry with a fresh packet (new timestamp)
                try:
                    packet = create_packet(
                        voter_id=VOTER_ID,
                        seq_num=seq_num,
                        candidate_id=candidate_id
                    )
                except ValueError:
                    return
            else:
                print(f"[WARN] Unexpected server response: {message}")

        except ssl.SSLError as e:
            print(f"[SSL ERROR] DTLS handshake failed (attempt {attempt}/{MAX_RETRIES}): {e}")
        except socket.timeout:
            print(f"[TIMEOUT] Server did not respond (attempt {attempt}/{MAX_RETRIES})")
        except ConnectionRefusedError:
            print(f"[ERROR] Connection refused — is the server running at {SERVER_HOST}:{SERVER_PORT}?")
            return
        except Exception as e:
            print(f"[ERROR] Unexpected error (attempt {attempt}/{MAX_RETRIES}): {e}")
        finally:
            if sock:
                try:
                    sock.shutdown()
                    sock.close()
                except Exception:
                    pass

        if attempt < MAX_RETRIES:
            time.sleep(0.5 * attempt)  # back-off before next retry

    print(f"[FAILED] Could not deliver vote after {MAX_RETRIES} attempts.")


def start_client():
    """Interactive voting UI loop."""
    global listening

    print("\n------------------------------------------")
    print("   SECURE POLLING CLIENT STARTED")
    print(f"   Voter ID  : {VOTER_ID}")
    print(f"   Server    : {SERVER_HOST}:{SERVER_PORT}")
    print("------------------------------------------")

    # Start background live-results polling thread
    listener = threading.Thread(target=poll_live_results, daemon=True)
    listener.start()

    try:
        voted = False
        while True:
            print("\n[1] Alice  [2] Bob  [3] Charlie  [q] Quit")
            try:
                choice = input("Choice: ").strip().lower()
            except EOFError:
                break

            if choice == "q":
                break
            elif choice in ["1", "2", "3"]:
                if voted:
                    print("[INFO] You have already submitted a vote this session.")
                    print("       The server will reject any further votes from this ID.")
                send_vote(int(choice))
                voted = True
            else:
                print("[INVALID] Please enter 1, 2, 3, or q.")

    except KeyboardInterrupt:
        pass

    finally:
        listening = False
        print("\n[CLIENT] Disconnecting from secure server. Goodbye!")


if __name__ == "__main__":
    start_client()
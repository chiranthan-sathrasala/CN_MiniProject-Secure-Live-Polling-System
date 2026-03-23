import socket
import threading
import ssl
import time

# This "monkey patch" safely injects wrap_socket back so the older dtls library
# doesn't crash on Python 3.12+ where it was removed from the ssl module.
if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext().wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import parse_packet
from stats import Stats

# Patch the standard Python sockets to support UDP over DTLS
do_patch()

# HOST is 0.0.0.0 to listen on all available network interfaces (crucial for VMs).
HOST = '0.0.0.0'
PORT = 5005

stats = Stats()
# A Lock prevents race conditions when multiple clients vote concurrently.
stats_lock = threading.Lock()

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}


def handle_secure_client(secure_conn, addr):
    """
    Handles the full lifecycle of one secure DTLS client connection:
      - Read request
      - Route to GET_RESULTS or vote handling
      - Send acknowledgment / rejection
      - Clean up
    """
    recv_time = time.time()  # start timing for latency measurement
    try:
        # 1. Read the encrypted request from the client
        try:
            data = secure_conn.read(1024)
        except ssl.SSLError as e:
            print(f"[SSL ERROR] Handshake/read failed from {addr[0]}: {e}")
            return

        if not data:
            print(f"[WARN] Empty data received from {addr[0]}, ignoring.")
            return

        # 2. Live results polling request
        if data == b"GET_RESULTS":
            with stats_lock:
                results = stats.votes_per_candidate.copy()
                uptime = stats.uptime_seconds()
                throughput = stats.throughput()

            lines = ["\n=== SECURE LIVE RESULTS ==="]
            for cid, name in CANDIDATES.items():
                count = results.get(cid, 0)
                bar = "█" * count
                lines.append(f"  {name:<10}: {count:>3} vote(s)  {bar}")
            lines.append(f"\n  Uptime: {uptime}s  |  Throughput: {throughput} votes/sec")
            lines.append("===========================\n")
            try:
                secure_conn.write("\n".join(lines).encode())
            except Exception as e:
                print(f"[ERROR] Failed to send results to {addr[0]}: {e}")
            return

        # 3. All other data is treated as a vote packet
        with stats_lock:
            stats.record_received()

        # Parse the custom 19-byte binary packet
        parsed = parse_packet(data)
        if parsed is None:
            with stats_lock:
                stats.record_corrupted()
            print(f"[CORRUPTED] Malformed packet from {addr[0]}")
            try:
                secure_conn.write(b"CORRUPTED")
            except Exception:
                pass
            return

        voter_id   = parsed['voter_id']
        candidate  = parsed['candidate_id']
        seq_num    = parsed['seq_num']
        pkt_time   = parsed['timestamp']

        # Guard against implausible timestamps (clock-skew / replay attack indicator)
        server_time = int(time.time())
        if abs(server_time - pkt_time) > 120:
            print(f"[WARN] Suspicious timestamp from voter {voter_id} (skew={server_time - pkt_time}s)")

        # 4. Validate candidate, check for duplicates, record vote — all under the lock
        with stats_lock:
            if stats.is_duplicate(voter_id):
                stats.record_duplicate()
                print(f"[DUPLICATE] Voter {voter_id} already voted")
                try:
                    secure_conn.write(b"DUPLICATE")
                except Exception:
                    pass
                return

            if candidate not in CANDIDATES:
                print(f"[INVALID] Voter {voter_id} sent unknown candidate id={candidate}")
                try:
                    secure_conn.write(b"INVALID_CANDIDATE")
                except Exception:
                    pass
                return

            # Measure end-to-end processing latency in milliseconds
            latency_ms = (time.time() - recv_time) * 1000
            stats.record_vote(candidate, latency_ms=latency_ms)

        name = CANDIDATES[candidate]
        print(f"[VOTE] Voter {voter_id} voted for {name}  (latency={latency_ms:.2f}ms)")

        # 5. Send a secure acknowledgment back
        ack = f"ACK:{seq_num}".encode()
        try:
            secure_conn.write(ack)
        except Exception as e:
            print(f"[ERROR] Failed to send ACK to voter {voter_id}: {e}")

    except Exception as e:
        print(f"[ERROR] Unexpected error handling {addr[0]}: {e}")

    finally:
        # Always close the secure session — even if an exception occurred above
        try:
            secure_conn.shutdown()
            secure_conn.close()
        except Exception:
            pass


def start_server():
    """
    Initialises the raw UDP socket, wraps it in DTLS, and enters
    the main accept-loop, spawning a daemon thread per client.
    """
    # 1. Create a raw UDP socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))

    # 2. Wrap in DTLS using self-signed certificates
    try:
        secure_server_sock = SSLConnection(
            raw_sock,
            keyfile="server.key",
            certfile="server.crt",
            server_side=True
        )
    except Exception as e:
        print(f"[FATAL] Could not initialise DTLS — check server.key / server.crt: {e}")
        raw_sock.close()
        return

    print("=" * 45)
    print("  SECURE DTLS LIVE POLLING SERVER STARTED")
    print(f"  Listening on {HOST}:{PORT}")
    print("=" * 45 + "\n")

    try:
        while True:
            try:
                # Accept an incoming secure DTLS connection
                secure_conn, addr = secure_server_sock.accept()
            except ssl.SSLError as e:
                # DTLS handshake failure — log and keep accepting new clients
                print(f"[SSL HANDSHAKE FAIL] {e}  — server continues.")
                continue
            except OSError as e:
                print(f"[SOCKET ERROR] {e}  — server continues.")
                continue

            # Spawn a daemon thread so the main loop never blocks
            t = threading.Thread(
                target=handle_secure_client,
                args=(secure_conn, addr),
                daemon=True
            )
            t.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down gracefully...")
        with stats_lock:
            stats.report()

    finally:
        try:
            secure_server_sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    start_server()

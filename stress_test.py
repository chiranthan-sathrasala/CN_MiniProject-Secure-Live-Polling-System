"""
stress_test.py — Performance Evaluation Script
================================================
Simulates N concurrent voters sending votes to the server simultaneously.
Measures:
  - Total time to complete all votes
  - Per-vote round-trip time (RTT) / latency
  - Throughput (votes per second)
  - Success / duplicate / failure breakdown

Usage:
  python3 stress_test.py [--host HOST] [--port PORT] [--voters N] [--delay MS]
default value for host is 192.168.0.104 and port is 5005
[--host HOST] --> server ip address  “Send votes to THIS machine”
[--port PORT] --> Port number of the server
[--voters N] --> number of fake users (threads)
[--delay MS] --> delay between votes (ms)
Example:
  python3 stress_test.py --voters 20 --delay 0
  python3 stress_test.py --voters 50 --delay 100
  python3 stress_test.py --host 127.0.0.1 --voters 10
"""
#module for network communication, used to send/receive data between client and server in our project
import socket  # eg usage raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) l76

#adds security(encryption), in our project used for DTLS(datagram transport layer security)
import ssl #sock = SSLConnection(raw_sock, cert_reqs=ssl.CERT_NONE) l78

#Threading allows multiple tasks at same time, here each voter = one thread
import threading #threading.Thread(target=voter_thread, ...) l131
import time # measure latency (t_start and rtt) and add delay (time.sleep(0.2))
import random #random delay, random vote, Unique Voter IDs
import argparse #l177 lets you pass inputs from the terminal
import statistics #l164 median latency and standard deviation

"""Python 3.12+ removed ssl.wrap_socket, this line adds this manually, DTLS library expects this and without this our code will crash """
if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext().wrap_socket 
    #restoring the deprecated ssl.wrap_socket to the modern method for compatibility
    #wrap_socket takes a normal socket and converts it into ssl/tls socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection #l83 , encryption, handshake and secure communication
from packet import create_packet #custom fun used to build vote packet, returns binary data sent to server l69

do_patch() #modifies python's socket system, after calling it , it converts the normal udp sockets --> dtls capable ones

# ─── Shared results container ───────────────────────────────────────────────
results_lock = threading.Lock() # this creates a mutex lock, since many threads will update the results without lock it will lead to data corruption, only one thread updates results at a time
results = {
    "success":    0,
    "duplicate":  0,
    "corrupted":  0,
    "timeout":    0,
    "ssl_error":  0,
    "other_fail": 0,
    "latencies":  []   # RTT in milliseconds for each successful vote
}
#all initialised to zero and empty array at the beginning and later gets altered

def voter_thread(server_host, server_port, voter_id, inter_vote_delay_ms):
    """
    Simulates a single voter: connects, votes once, records the outcome.
    """
    candidate_id = random.choice([1, 2, 3])
    seq = 1  #“Currently it’s fixed since each client sends only one packet, but it is included to support future extensions like retransmission handling, packet ordering, and replay detection.”

    try:
        packet = create_packet(voter_id=voter_id, seq_num=seq, candidate_id=candidate_id)
    except ValueError as e:
        with results_lock:
            results["other_fail"] += 1
        return

    if inter_vote_delay_ms > 0:
        time.sleep(inter_vote_delay_ms / 1000.0 * random.uniform(0, 1))

    sock = None #no socketed created as of now, done to prevent from undefined sock getting created
    try:
        t_start = time.time() 
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw_sock.settimeout(8)
        sock = SSLConnection(raw_sock, cert_reqs=ssl.CERT_NONE)
        sock.connect((server_host, server_port))
        sock.write(packet) # send your vote
        data = sock.read(1024) #recieve response ex: ACK:1, DUPLICATE etc
        rtt_ms = (time.time() - t_start) * 1000 # calc RTT
        message = data.decode() #converts bytes to string b'ACK:1' to "ACK:1"

        with results_lock:
            if message.startswith("ACK"):
                results["success"] += 1
                results["latencies"].append(rtt_ms)
            elif message == "DUPLICATE":
                results["duplicate"] += 1
            elif message == "CORRUPTED":
                results["corrupted"] += 1
            else:
                results["other_fail"] += 1

    except ssl.SSLError:
        with results_lock:
            results["ssl_error"] += 1
    except socket.timeout:
        with results_lock:
            results["timeout"] += 1
    except Exception:
        with results_lock:
            results["other_fail"] += 1
    finally:
        if sock:
            try:
                sock.shutdown()
                sock.close()
            except Exception:
                pass


def run_stress_test(server_host, server_port, num_voters, inter_vote_delay_ms):
    print("\n" + "=" * 50)
    print("        STRESS TEST — PERFORMANCE EVALUATION")
    print("=" * 50)
    print(f"  Server     : {server_host}:{server_port}")
    print(f"  Voters     : {num_voters}")
    print(f"  Max delay  : {inter_vote_delay_ms}ms (randomised per thread)\n")

    threads = []
    # Assign unique voter IDs starting from 10000 to avoid collisions with manual testers
    voter_ids = random.sample(range(10000, 10000 + num_voters * 10), num_voters)
    #it will generate num_voters number of unique ids
    t_wall_start = time.time()

    for voter_id in voter_ids:
        t = threading.Thread(
            target=voter_thread, #function each thread runs
            args=(server_host, server_port, voter_id, inter_vote_delay_ms),
            daemon=True  #thread will auto close when the main program ends
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=30)  # don't hang forever if a thread stalls/ wait 30s until this thread finishes

    elapsed = time.time() - t_wall_start

    # ─── Report ────────────────────────────────────────────────────────────
    lats = results["latencies"] #store the latencies from the dictionary to lats for easier access
    total_attempted = num_voters

    print("\n" + "─" * 50)
    print("  RESULTS")
    print("─" * 50)
    print(f"  Total wall-clock time : {elapsed:.3f}s")
    print(f"  Voters attempted      : {total_attempted}")
    print(f"  ✔ Successful votes    : {results['success']}")
    print(f"  ✖ Duplicates          : {results['duplicate']}")
    print(f"  ✖ Corrupted           : {results['corrupted']}")
    print(f"  ✖ Timeouts            : {results['timeout']}")
    print(f"  ✖ SSL errors          : {results['ssl_error']}")
    print(f"  ✖ Other failures      : {results['other_fail']}")

    if lats:
        print(f"\n  Latency (min)         : {min(lats):.2f} ms")
        print(f"  Latency (max)         : {max(lats):.2f} ms")
        print(f"  Latency (avg)         : {sum(lats)/len(lats):.2f} ms")
        print(f"  Latency (median)      : {statistics.median(lats):.2f} ms")
        if len(lats) >= 2:
            print(f"  Latency (stdev)       : {statistics.stdev(lats):.2f} ms")

    throughput = results["success"] / elapsed if elapsed > 0 else 0
    print(f"\n  Throughput            : {throughput:.2f} successful votes/sec")

    loss_pct = ((total_attempted - results["success"]) / total_attempted * 100) if total_attempted else 0
    print(f"  Effective packet loss : {loss_pct:.1f}%  (includes timeouts + errors)")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stress-test the polling server")
    parser.add_argument("--host",   default="192.168.0.104", help="Server IP address")
    parser.add_argument("--port",   type=int, default=5005,  help="Server port")
    parser.add_argument("--voters", type=int, default=20,    help="Number of concurrent voters")
    parser.add_argument("--delay",  type=int, default=0,     help="Max random inter-vote delay in ms")
    args = parser.parse_args()

    run_stress_test(args.host, args.port, args.voters, args.delay)

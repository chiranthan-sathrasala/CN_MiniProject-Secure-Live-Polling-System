import socket
import ssl
import threading
import time
import random
import argparse
import statistics

if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import create_packet

do_patch()

# ─── Shared results container ───────────────────────────────────────────────
results_lock = threading.Lock()
results = {
    "success":    0,
    "duplicate":  0,
    "corrupted":  0,
    "rejected_state": 0,  # Catches phase mismatch
    "timeout":    0,
    "ssl_error":  0,
    "other_fail": 0,
    "latencies":  []   
}

def voter_thread(server_host, server_port, voter_id, inter_vote_delay_ms):
    candidate_id = random.choice([1, 2, 3])
    seq = 1

    try:
        packet = create_packet(voter_id=voter_id, seq_num=seq, candidate_id=candidate_id)
    except ValueError:
        with results_lock:
            results["other_fail"] += 1
        return

    if inter_vote_delay_ms > 0:
        time.sleep(inter_vote_delay_ms / 1000.0 * random.uniform(0, 1))

    sock = None
    try:
        t_start = time.time()
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw_sock.settimeout(0.5) # BLAZING FAST TIMEOUT
        
        sock = SSLConnection(raw_sock, cert_reqs=ssl.CERT_NONE)
        sock.connect((server_host, server_port))
        sock.write(packet)
        data = sock.read(1024)
        rtt_ms = (time.time() - t_start) * 1000
        message = data.decode()

        with results_lock:
            if message.startswith("ACK"):
                results["success"] += 1
                results["latencies"].append(rtt_ms)
            elif message == "DUPLICATE":
                results["duplicate"] += 1
            elif message == "CORRUPTED":
                results["corrupted"] += 1
            elif message == "REJECTED:NOT_ACTIVE":
                results["rejected_state"] += 1
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
    print(f"  Max delay  : {inter_vote_delay_ms}ms\n")

    threads = []
    voter_ids = random.sample(range(10000, 10000 + num_voters * 10), num_voters)

    t_wall_start = time.time()

    for voter_id in voter_ids:
        t = threading.Thread(
            target=voter_thread,
            args=(server_host, server_port, voter_id, inter_vote_delay_ms),
            daemon=True
        )
        threads.append(t)
        t.start()

    # Wait for all threads to finish. 
    for t in threads:
        t.join(timeout=10) 

    elapsed = time.time() - t_wall_start
    lats = results["latencies"]
    total_attempted = num_voters

    print("\n" + "─" * 50)
    print("  RESULTS")
    print("─" * 50)
    print(f"  Total wall-clock time : {elapsed:.3f}s")
    print(f"  Voters attempted      : {total_attempted}")
    print(f"  ✔ Successful votes    : {results['success']}")
    print(f"  ✖ Blocked (Wrong Phase): {results['rejected_state']}")
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

    throughput = results["success"] / elapsed if elapsed > 0 else 0
    print(f"\n  Throughput            : {throughput:.2f} successful votes/sec")

    # Exclude intentional Phase Blocks from the "Packet Loss" calculation
    loss_pct = ((total_attempted - results["success"] - results["rejected_state"]) / total_attempted * 100) if total_attempted else 0
    print(f"  Effective packet loss : {loss_pct:.1f}%")
    print("=" * 50 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stress-test the polling server")
    parser.add_argument("--host",   default="127.0.0.1", help="Server IP address")
    parser.add_argument("--port",   type=int, default=5005,  help="Server port")
    parser.add_argument("--voters", type=int, default=50,    help="Number of concurrent voters")
    parser.add_argument("--delay",  type=int, default=0,     help="Max random inter-vote delay in ms")
    args = parser.parse_args()

    run_stress_test(args.host, args.port, args.voters, args.delay)
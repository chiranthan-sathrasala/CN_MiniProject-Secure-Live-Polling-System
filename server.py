import socket
import threading
import ssl
import time

# This "monkey patch" safely injects wrap_socket back so the older dtls library
# doesn't crash on Python 3.12+ where it was removed from the ssl module.
if not hasattr(ssl, 'wrap_socket'):
    def legacy_wrap_socket(sock, keyfile=None, certfile=None,
                           server_side=False, cert_reqs=ssl.CERT_NONE,
                           ssl_version=None, ca_certs=None,
                           do_handshake_on_connect=True,
                           suppress_ragged_eofs=True, ciphers=None):
        # Create a modern context based on client/server role
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = cert_reqs
        context.check_hostname = False
        
        if ca_certs:
            context.load_verify_locations(ca_certs)
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ciphers:
            context.set_ciphers(ciphers)
            
        return context.wrap_socket(sock, server_side=server_side,
                                   do_handshake_on_connect=do_handshake_on_connect,
                                   suppress_ragged_eofs=suppress_ragged_eofs)
    
    ssl.wrap_socket = legacy_wrap_socket

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
            return # happens if handshake fails or corrupted encrypted data

        if not data:
            print(f"[WARN] Empty data received from {addr[0]}, ignoring.")
            return 

        # 2. Live results polling request
        if data == b"GET_RESULTS": #client is asking to show live voting results
            with stats_lock:  #lock for safety preventing race conditions/ multiple thread accessing stats
                results = stats.votes_per_candidate.copy()#imp for safe update so that other threads cannot simultaneously access it
                uptime = stats.uptime_seconds() #server runtime
                throughput = stats.throughput() #number votes per sec

            lines = ["\n=== SECURE LIVE RESULTS ==="]
            for cid, name in CANDIDATES.items(): #loop through candidates
                count = results.get(cid, 0) # we use get() here so that it does not creash when the key is missing
                bar = "█" * count
                lines.append(f"  {name:<10}: {count:>3} vote(s)  {bar}")
            lines.append(f"\n  Uptime: {uptime}s  |  Throughput: {throughput} votes/sec")
            lines.append("===========================\n")
            try:
                secure_conn.write("\n".join(lines).encode())# combine list into one string , encode converting string to bytes(req for network transmission) and send over DTLS
            except Exception as e:
                print(f"[ERROR] Failed to send results to {addr[0]}: {e}")
            return # client discon or network issue and stops further execution since its not a vote its a results request

        # 3. All other data is treated as a vote packet
        with stats_lock:  #only runs if the req was not "get results" counts incoming requests
            stats.record_received()

        # Parse the custom 19-byte binary packet in packet.py
        parsed = parse_packet(data) #converts raw binary into structured dictionary
        if parsed is None: #packet malformed or corrupted data
            with stats_lock:
                stats.record_corrupted()
            print(f"[CORRUPTED] Malformed packet from {addr[0]}") #address is of client and is a tuple ex: ("some ip", some port)   addr[0]-> ip address
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
        if abs(server_time - pkt_time) > 120:  #checking if packet is too old or sussyyy, defense against replay attackkerssss
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

        name = CANDIDATES[candidate] #server side logging votes
        print(f"[VOTE] Voter {voter_id} voted for {name}  (latency={latency_ms:.2f}ms)")

        # 5. Send a secure acknowledgment back
        ack = f"ACK:{seq_num}".encode()  #seq num ensures this ack corresponds to the client's packet
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
            secure_conn.close()  #prevents memory leak, socket exhaustion and server creash
        except Exception:
            pass


def start_server():
    """
    Initialises the raw UDP socket, wraps it in DTLS, and enters
    the main accept-loop, spawning a daemon thread per client.
    """
    # 1. Create a raw UDP socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#for port reuse if we did not add this then next time when we run the server again then it will give the message address already in use
    raw_sock.bind((HOST, PORT)) #tells os i want to listen on this ip+ port

    # 2. Wrap in DTLS using self-signed certificates
    try:
        secure_server_sock = SSLConnection( #converts normal udp to dtls socket
            raw_sock,
            keyfile="server.key", #contains private key - used for decrypting data and signing handshake
            certfile="server.crt",#proving server identity and part of handshake
            server_side=True   #this is the server if false then client
        )
#Client → hello
#Server → certificate
#Key exchange
#Secure channel established
    except Exception as e: #missing key, crt wrong path invalid cert etc
        print(f"[FATAL] Could not initialise DTLS — check server.key / server.crt: {e}")
        raw_sock.close()
        return #server stops completely

    print("=" * 45)
    print("  SECURE DTLS LIVE POLLING SERVER STARTED")
    print(f"  Listening on {HOST}:{PORT}")
    print("=" * 45 + "\n")

    try:
        while True: #keep running forever and accept clients
            try:
                # Accept an incoming secure DTLS connection
                secure_conn, addr = secure_server_sock.accept() #main thread
            except ssl.SSLError as e:
                # DTLS handshake failure — log and keep accepting new clients
                print(f"[SSL HANDSHAKE FAIL] {e}  — server continues.")
                continue
            except OSError as e:
                print(f"[SOCKET ERROR] {e}  — server continues.") #network issue or port problem
                continue

            # Spawn a daemon thread so the main loop never blocks
            t = threading.Thread(
                target=handle_secure_client,        #worker thread
                args=(secure_conn, addr),
                daemon=True #thread auto kills when the main program exits,  no hanging threads
            )
            #main thread = accepts client and worker threads == process clients
            t.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down gracefully...")
        with stats_lock:
            stats.report()

    finally:
        try:
            secure_server_sock.close() #always runs 
        except Exception:
            pass


if __name__ == "__main__":
    start_server()

import struct
import time

# Packet format:
# | voter_id (4 bytes) | seq_num (4 bytes) | candidate_id (1 byte) | timestamp (8 bytes) | checksum (2 bytes) |
# Total = 19 bytes

PACKET_FORMAT = '!IIBqH'  # I = unsigned int, B = unsigned char, q = long long, H = unsigned short
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)  

def create_packet(voter_id, seq_num, candidate_id):
    timestamp = int(time.time())
    # Pack everything except checksum first
    partial = struct.pack('!IIBq', voter_id, seq_num, candidate_id, timestamp)
    # Simple checksum — sum of all bytes mod 65536
    checksum = sum(partial) % 65536
    # Now pack the full packet including checksum
    full_packet = struct.pack(PACKET_FORMAT, voter_id, seq_num, candidate_id, timestamp, checksum)
    return full_packet

def parse_packet(raw_data):
    if len(raw_data) != PACKET_SIZE:
        print(f"[ERROR] Invalid packet size: {len(raw_data)} bytes (expected {PACKET_SIZE})")
        return None
    voter_id, seq_num, candidate_id, timestamp, received_checksum = struct.unpack(PACKET_FORMAT, raw_data)
    # Verify checksum
    partial = struct.pack('!IIBq', voter_id, seq_num, candidate_id, timestamp)
    expected_checksum = sum(partial) % 65536
    if received_checksum != expected_checksum:
        print(f"[ERROR] Checksum mismatch! Packet may be corrupted.")
        return None
    return {
        'voter_id': voter_id,
        'seq_num': seq_num,
        'candidate_id': candidate_id,
        'timestamp': timestamp
    }

#used for debugging if required
'''def display_packet(packet_dict):
    print(f"  Voter ID     : {packet_dict['voter_id']}")
    print(f"  Seq Number   : {packet_dict['seq_num']}")
    print(f"  Candidate    : {packet_dict['candidate_id']}")
    print(f"  Timestamp    : {packet_dict['timestamp']}")'''
import struct
import time

# Packet format:
# | voter_id (4 bytes) | seq_num (4 bytes) | candidate_id (1 byte) | timestamp (8 bytes) | checksum (2 bytes) |
# Total = 19 bytes

PACKET_FORMAT = '!IIBqH'  # I = unsigned int, B = unsigned char, q = long long, H = unsigned short
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)

VALID_CANDIDATES = {1, 2, 3}
MAX_VOTER_ID = 0xFFFFFFFF  # 4-byte unsigned int max


def create_packet(voter_id, seq_num, candidate_id):
    if not (0 < voter_id <= MAX_VOTER_ID):
        raise ValueError(f"voter_id must be between 1 and {MAX_VOTER_ID}")
    if candidate_id not in VALID_CANDIDATES:
        raise ValueError(f"candidate_id must be one of {VALID_CANDIDATES}")
    if seq_num < 0:
        raise ValueError("seq_num must be non-negative")

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

    try:
        voter_id, seq_num, candidate_id, timestamp, received_checksum = struct.unpack(PACKET_FORMAT, raw_data)
    except struct.error as e:
        print(f"[ERROR] Failed to unpack packet: {e}")
        return None

    # Verify checksum
    partial = struct.pack('!IIBq', voter_id, seq_num, candidate_id, timestamp)
    expected_checksum = sum(partial) % 65536

    if received_checksum != expected_checksum:
        print(f"[ERROR] Checksum mismatch! Expected {expected_checksum}, got {received_checksum}. Packet may be corrupted.")
        return None

    # Validate field ranges
    if voter_id == 0:
        print("[ERROR] Invalid voter_id=0 in packet.")
        return None

    return {
        'voter_id': voter_id,
        'seq_num': seq_num,
        'candidate_id': candidate_id,
        'timestamp': timestamp
    }

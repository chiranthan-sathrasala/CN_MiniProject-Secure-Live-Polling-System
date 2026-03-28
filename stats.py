import time
import threading


class Stats:
    def __init__(self):
        self.total_received = 0
        self.total_duplicates = 0
        self.total_corrupted = 0
        self.votes_per_candidate = {}       # {candidate_id: count}
        self.voters_seen = set()            # for duplicate detection

        # Performance metrics
        self._start_time = time.time()
        self._latencies = []                # per-vote processing latency in ms
        self._lock = threading.Lock()       # internal lock for latency list

    def record_received(self):
        # Called every time any packet arrives.
        self.total_received += 1

    def record_duplicate(self):
        # Called when a duplicate voter_id is detected.
        self.total_duplicates += 1

    def record_corrupted(self):
        # Called when checksum verification fails.
        self.total_corrupted += 1

    def record_vote(self, candidate_id, latency_ms=None):
        """
        Called when a valid, unique vote is counted.
        Optionally records the per-request processing latency in milliseconds.
        """
        if candidate_id not in self.votes_per_candidate:
            self.votes_per_candidate[candidate_id] = 0
        self.votes_per_candidate[candidate_id] += 1

        if latency_ms is not None:
            with self._lock:
                self._latencies.append(latency_ms)

    def is_duplicate(self, voter_id):
        # Returns True if voter already voted; registers them on first call.
        if voter_id in self.voters_seen:
            return True
        self.voters_seen.add(voter_id)
        return False

    def total_valid_votes(self):
        return sum(self.votes_per_candidate.values())

    def uptime_seconds(self):
        return round(time.time() - self._start_time, 2)

    def throughput(self):
        # Valid votes per second since server started.
        elapsed = time.time() - self._start_time
        if elapsed == 0:
            return 0.0
        return round(self.total_valid_votes() / elapsed, 4)

    def calculate_loss(self, total_sent):
        # Packet loss percentage relative to total_sent by client.
        if total_sent == 0:
            return 0.0
        valid = self.total_received - self.total_duplicates - self.total_corrupted
        loss = ((total_sent - valid) / total_sent) * 100
        return round(loss, 2)

    def latency_stats(self):
        # Returns (min, max, avg) latency in ms, or (0,0,0) if no data.
        with self._lock:
            if not self._latencies:
                return 0.0, 0.0, 0.0
            return (
                round(min(self._latencies), 3),
                round(max(self._latencies), 3),
                round(sum(self._latencies) / len(self._latencies), 3)
            )

    def report(self, total_sent=None):
        # Prints a full stats report to stdout.
        lat_min, lat_max, lat_avg = self.latency_stats()
        print("\n" + "=" * 44)
        print("           POLLING STATS REPORT")
        print("-" * 44)
        print(f"  Uptime              : {self.uptime_seconds()}s")
        print(f"  Packets Received    : {self.total_received}")
        print(f"  Valid Votes Cast    : {self.total_valid_votes()}")
        print(f"  Duplicates Dropped  : {self.total_duplicates}")
        print(f"  Corrupted Dropped   : {self.total_corrupted}")
        print(f"  Throughput          : {self.throughput()} votes/sec")

        if self._latencies:
            print(f"  Latency (min/avg/max): {lat_min}/{lat_avg}/{lat_max} ms")

        if total_sent:
            loss = self.calculate_loss(total_sent)
            print(f"  Packet Loss         : {loss}%")

        print("\n  --- VOTE COUNTS ---")
        CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}
        if not self.votes_per_candidate:
            print("  No votes recorded yet.")
        else:
            for cid, count in sorted(self.votes_per_candidate.items()):
                name = CANDIDATES.get(cid, f"Candidate {cid}")
                bar = "█" * count
                print(f"  {name:<10}: {count:>3} vote(s)  {bar}")
        print("=" * 44 + "\n")

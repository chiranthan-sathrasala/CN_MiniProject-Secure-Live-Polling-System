class Stats:
    def __init__(self):
        self.total_received = 0
        self.total_duplicates = 0
        self.total_corrupted = 0
        self.votes_per_candidate = {}   # {candidate_id: count}
        self.voters_seen = set()        # for duplicate detection

    # called every time a packet arrives 
    def record_received(self):
        self.total_received += 1

    # called when a duplicate voter_id is detected 
    def record_duplicate(self):
        self.total_duplicates += 1

    # called when checksum fails 
    def record_corrupted(self):
        self.total_corrupted += 1

    # called when a valid, unique vote is counted 
    def record_vote(self, candidate_id):
        if candidate_id not in self.votes_per_candidate:
            self.votes_per_candidate[candidate_id] = 0
        self.votes_per_candidate[candidate_id] += 1

    # duplicate detection 
    def is_duplicate(self, voter_id):
        if voter_id in self.voters_seen:
            return True
        self.voters_seen.add(voter_id)
        return False

    # packet loss % (client tells server how many it sent) 
    def calculate_loss(self, total_sent):
        if total_sent == 0:
            return 0.0
        valid = self.total_received - self.total_duplicates - self.total_corrupted
        loss = ((total_sent - valid) / total_sent) * 100
        return round(loss, 2)

    # print a full stats report 
    def report(self, total_sent=None):
        print("\n" + "="*40)
        print("         POLLING STATS REPORT")
        print("--------------------------------------------")
        print(f"  Packets Received   : {self.total_received}")
        print(f"  Duplicates Dropped : {self.total_duplicates}")
        print(f"  Corrupted Dropped  : {self.total_corrupted}")

        if total_sent:
            loss = self.calculate_loss(total_sent)
            print(f"  Packet Loss        : {loss}%")

        print("\n  --- VOTE COUNTS ---")
        if not self.votes_per_candidate:
            print("  No votes recorded yet.")
        else:
            for candidate, count in sorted(self.votes_per_candidate.items()):
                print(f"  Candidate {candidate}        : {count} vote(s)")
        print("-----------------------\n")
        

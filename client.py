import socket
import threading
import time
import random
import ssl
import customtkinter as ctk

if not hasattr(ssl, 'wrap_socket'):
    ssl.wrap_socket = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_socket

from dtls import do_patch
from dtls.sslconnection import SSLConnection
from packet import create_packet

do_patch()

CANDIDATES = {1: "Alice", 2: "Bob", 3: "Charlie"}
VOTER_ID = random.randint(1000, 9999)
MAX_RETRIES = 3
SOCK_TIMEOUT = 3

SERVER_HOST = ""
SERVER_PORT = 5005
has_voted = False
seq_num = 0

def get_secure_socket():
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.settimeout(SOCK_TIMEOUT)
    secure_sock = SSLConnection(raw_sock, cert_reqs=ssl.CERT_NONE)
    secure_sock.connect((SERVER_HOST, SERVER_PORT))
    return secure_sock

class VotingApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure DTLS Voting Client")
        self.geometry("450x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # --- PERSISTENT HEADER ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent", height=40)
        self.header_frame.pack(fill="x", padx=15, pady=5)
        self.header_frame.pack_propagate(False)
        
        self.voter_id_label = ctk.CTkLabel(
            self.header_frame, 
            text=f"Voter ID: {VOTER_ID}", 
            font=("Arial", 14, "bold"), 
            text_color="#00ffcc" 
        )
        self.voter_id_label.pack(side="right")
        
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)

        self.build_ip_screen()

    def clear_screen(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def build_ip_screen(self):
        self.clear_screen()
        ctk.CTkLabel(self.main_frame, text="Secure Polling System", font=("Arial", 26, "bold")).pack(pady=50)
        self.ip_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Enter Server IP Address", width=250, height=40)
        self.ip_entry.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Connect", command=self.connect_to_server, height=40, width=200).pack(pady=20)

    def connect_to_server(self):
        global SERVER_HOST
        SERVER_HOST = self.ip_entry.get().strip()
        if not SERVER_HOST: return
        self.build_waiting_screen()
        threading.Thread(target=self.poll_server_state, daemon=True).start()

    def build_waiting_screen(self):
        self.clear_screen()
        ctk.CTkLabel(self.main_frame, text="Waiting Room", font=("Arial", 28, "bold")).pack(pady=60)
        self.wait_label = ctk.CTkLabel(self.main_frame, text="Connecting to secure server...", font=("Arial", 16))
        self.wait_label.pack(pady=20)
        self.spinner = ctk.CTkProgressBar(self.main_frame, mode="indeterminate", width=250)
        self.spinner.pack(pady=20)
        self.spinner.start()

    def build_voting_screen(self):
        self.clear_screen()
        ctk.CTkLabel(self.main_frame, text="Cast Your Vote", font=("Arial", 28, "bold")).pack(pady=30)
        
        self.radio_var = ctk.IntVar(value=0)
        self.radio_buttons = []
        
        for cid, name in CANDIDATES.items():
            rb = ctk.CTkRadioButton(self.main_frame, text=name, variable=self.radio_var, value=cid, font=("Arial", 18))
            rb.pack(pady=15)
            self.radio_buttons.append(rb)
            
        self.vote_btn = ctk.CTkButton(self.main_frame, text="Submit Secure Vote", command=self.trigger_vote, height=45, width=220)
        self.vote_btn.pack(pady=30)
        
        self.status_label = ctk.CTkLabel(self.main_frame, text="", text_color="yellow", font=("Arial", 14))
        self.status_label.pack(pady=5)
        
        self.tally_label = ctk.CTkLabel(self.main_frame, text="Total votes cast by all users: 0", font=("Arial", 14), text_color="gray")
        self.tally_label.pack(pady=20)

    def trigger_vote(self):
        """Disables UI instantly and hands the robust retry logic to a background thread."""
        choice = self.radio_var.get()
        if choice == 0:
            self.status_label.configure(text="Please select a candidate first!", text_color="#ff4d4d")
            return
            
        self.vote_btn.configure(state="disabled", text="Encrypting...")
        for rb in self.radio_buttons:
            rb.configure(state="disabled")
            
        threading.Thread(target=self._robust_send_vote, args=(choice,), daemon=True).start()

    def _robust_send_vote(self, candidate_id):
        """Your teammate's robust Terminal-Logging and Retry Logic."""
        global has_voted, seq_num
        seq_num += 1
        packet = create_packet(VOTER_ID, seq_num, candidate_id)
        
        print(f"\n[CLIENT] Encrypting and sending vote for {CANDIDATES[candidate_id]}...")

        for attempt in range(1, MAX_RETRIES + 1):
            sock = None
            try:
                t_start = time.time()
                sock = get_secure_socket()
                sock.write(packet)
                
                data = sock.read(1024)
                rtt_ms = (time.time() - t_start) * 1000
                message = data.decode()

                if message.startswith("ACK"):
                    print(f"[ACK] Vote acknowledged by server (RTT={rtt_ms:.1f}ms)")
                    has_voted = True
                    self.after(0, lambda: self.status_label.configure(text="Vote Successfully Recorded!", text_color="#00ffcc"))
                    self.after(0, lambda: self.vote_btn.configure(text="Vote Submitted"))
                    return
                elif message == "DUPLICATE":
                    print("[REJECTED] Server: you have already voted.")
                    self.after(0, lambda: self.status_label.configure(text="Error: You already voted!", text_color="#ff4d4d"))
                    return
                elif message == "CORRUPTED":
                    print(f"[WARN] Server: packet was corrupted (attempt {attempt}/{MAX_RETRIES})")
                    packet = create_packet(VOTER_ID, seq_num, candidate_id) # Regenerate timestamp
                elif message == "REJECTED:NOT_ACTIVE":
                    print("[REJECTED] Server: Election is not currently active.")
                    self.after(0, lambda: self.status_label.configure(text="Election is not active!", text_color="#ff4d4d"))
                    return

            except ssl.SSLError as e:
                print(f"[SSL ERROR] DTLS handshake failed (attempt {attempt}/{MAX_RETRIES}): {e}")
            except socket.timeout:
                print(f"[TIMEOUT] Server did not respond (attempt {attempt}/{MAX_RETRIES})")
            except Exception as e:
                print(f"[ERROR] Unexpected error (attempt {attempt}/{MAX_RETRIES}): {e}")
            finally:
                if sock:
                    try: sock.shutdown(); sock.close()
                    except: pass

            if attempt < MAX_RETRIES:
                time.sleep(0.5 * attempt) 

        print(f"[FAILED] Could not deliver vote after {MAX_RETRIES} attempts.")
        self.after(0, lambda: self.status_label.configure(text="Network Failure. Restart Client.", text_color="#ff4d4d"))

    def build_transition_screen(self, results_string):
        self.clear_screen()
        ctk.CTkLabel(self.main_frame, text="Election Closed!", font=("Arial", 28, "bold"), text_color="orange").pack(pady=60)
        ctk.CTkLabel(self.main_frame, text="Calculating cryptographic tallies...", font=("Arial", 16)).pack(pady=20)
        pb = ctk.CTkProgressBar(self.main_frame, mode="indeterminate", width=250)
        pb.pack(pady=20)
        pb.start()
        self.after(3000, lambda: self.build_results_screen(results_string))

    def build_results_screen(self, results_string):
        self.clear_screen()
        ctk.CTkLabel(self.main_frame, text="*** OFFICIAL RESULTS ***", font=("Arial", 26, "bold"), text_color="#00ffcc").pack(pady=20)
        try:
            counts = {name: int(votes) for item in results_string.split(",") for name, votes in [item.split(":")]}
            winner = max(counts, key=counts.get)
            ctk.CTkLabel(self.main_frame, text=f"WINNER: {winner.upper()}", font=("Arial", 24, "bold"), text_color="gold").pack(pady=15)
            
            for name, votes in counts.items():
                frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
                frame.pack(fill="x", padx=50, pady=10)
                ctk.CTkLabel(frame, text=name, width=60, anchor="w", font=("Arial", 14)).pack(side="left")
                bar_width = max(5, votes * 30) 
                bar = ctk.CTkFrame(frame, width=bar_width, height=20, fg_color="#1f538d")
                bar.pack(side="left", padx=15)
                bar.pack_propagate(False)
                ctk.CTkLabel(frame, text=f"{votes}", font=("Arial", 14, "bold")).pack(side="left")
        except Exception:
             ctk.CTkLabel(self.main_frame, text="Error parsing results.").pack(pady=20)

    def poll_server_state(self):
        current_gui_state = "WAITING"
        while True:
            time.sleep(2)
            try:
                sock = get_secure_socket()
                sock.write(b"GET_RESULTS")
                data = sock.read(1024).decode()
                
                # NOTE: Intentionally NOT printing 'data' to terminal to keep logs clean!
                
                if data.startswith("STATE:WAITING"):
                    if current_gui_state != "WAITING":
                        self.after(0, lambda: self.wait_label.configure(text="Waiting for the Server to start the election..."))
                        current_gui_state = "WAITING"
                elif data.startswith("STATE:ACTIVE"):
                    total_votes = data.split("TOTAL:")[1]
                    if current_gui_state == "WAITING":
                        self.after(0, self.build_voting_screen)
                        current_gui_state = "ACTIVE"
                    elif current_gui_state == "ACTIVE":
                        self.after(0, lambda v=total_votes: self.tally_label.configure(text=f"Total votes cast by all users: {v}"))
                elif data.startswith("STATE:CLOSED"):
                    results_string = data.split("RESULTS:")[1] if "RESULTS:" in data else data.split("|")[1]
                    if current_gui_state != "CLOSED":
                        self.after(0, lambda r=results_string: self.build_transition_screen(r))
                        current_gui_state = "CLOSED"
                        break 
            except Exception:
                pass 

if __name__ == "__main__":
    app = VotingApp()
    app.mainloop()
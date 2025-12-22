import json
import socket
import time

HOST = "stratum.solopool.com"
PORT = 3334
USER = "tb1YOURTESTNET4ADDRESS.vireon1"
PWD  = "x"

def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())

def recv_lines(sock, timeout=10):
    sock.settimeout(timeout)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    yield line.decode(errors="replace")
        except socket.timeout:
            break

def main():
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        print(f"[NET] Connected {HOST}:{PORT}")
        send(s, {"id": 1, "method": "mining.subscribe", "params": ["vireon-probe/4.0"]})
        for line in recv_lines(s, timeout=5):
            print("[<-]", line)

        send(s, {"id": 2, "method": "mining.authorize", "params": [USER, PWD]})
        for line in recv_lines(s, timeout=5):
            print("[<-]", line)

        # Listen briefly for notify / set_difficulty
        print("[NET] Listening for jobs...")
        for line in recv_lines(s, timeout=10):
            print("[<-]", line)

if __name__ == "__main__":
    main()

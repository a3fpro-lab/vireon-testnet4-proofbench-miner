import json
import socket
import time

from vireon_miner.miner import connect_and_handshake, JsonLineReader, _send_json_line

# ---- EDIT THESE ----
HOST = "stratum.solopool.com"
PORT = 3334
USER = "tb1PUT_TESTNET4_ADDRESS_HERE.vireon1"
PWD  = "x"
TIMEOUT = 10.0
# --------------------


def main():
    print("═" * 70)
    print(" VIREON LIVE SMOKE — Stratum subscribe/authorize + first notify")
    print(f" Host: {HOST}:{PORT}")
    print(f" User: {USER}")
    print("═" * 70)

    # Do handshake using the robust code you now have
    hs = connect_and_handshake(HOST, PORT, USER, PWD, timeout=TIMEOUT)
    print(f"[OK] authorized={hs.authorized}")
    print(f"[OK] extranonce1={hs.subscribe.extranonce1} extranonce2_size={hs.subscribe.extranonce2_size}")

    # Reconnect and listen (handshake closes socket by design). Keep this script simple.
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        r = JsonLineReader(sock)

        _send_json_line(sock, {"id": 1, "method": "mining.subscribe", "params": ["vireon-live-smoke/0.1"]})
        # Wait for id==1
        while True:
            msg = r.read_one()
            if msg.get("id") == 1:
                break

        _send_json_line(sock, {"id": 2, "method": "mining.authorize", "params": [USER, PWD]})
        # Wait for id==2
        while True:
            msg = r.read_one()
            if msg.get("id") == 2:
                break

        print("[NET] listening for difficulty + job (10s)...")
        t_end = time.time() + 10
        while time.time() < t_end:
            m = r.read_one()
            # print only the useful stuff
            if m.get("method") in ("mining.set_difficulty", "mining.notify"):
                print(json.dumps(m)[:500])

    print("[DONE] smoke test finished.")


if __name__ == "__main__":
    main()

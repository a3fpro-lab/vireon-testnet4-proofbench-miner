import json
import socket
import threading
import time

from vireon_miner.miner import connect_and_handshake, parse_set_difficulty, parse_notify


def _fake_stratum_server(host: str, port: int, ready_evt: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    ready_evt.set()

    conn, _ = srv.accept()
    conn.settimeout(5)

    def recv_line():
        buf = b""
        while b"\n" not in buf:
            buf += conn.recv(4096)
        line, _ = buf.split(b"\n", 1)
        return json.loads(line.decode())

    def send(obj):
        conn.sendall((json.dumps(obj) + "\n").encode())

    # subscribe
    sub = recv_line()
    assert sub["method"] == "mining.subscribe"
    send(
        {
            "id": sub["id"],
            "result": [
                [["mining.set_difficulty", "deadbeef"], ["mining.notify", "cafebabe"]],
                "01020304",
                8,
            ],
            "error": None,
        }
    )

    # authorize
    auth = recv_line()
    assert auth["method"] == "mining.authorize"
    send({"id": auth["id"], "result": True, "error": None})

    # notifications (for parser tests)
    send({"id": None, "method": "mining.set_difficulty", "params": [1.0]})
    send(
        {
            "id": None,
            "method": "mining.notify",
            "params": [
                "job1",
                "00" * 32,
                "aa",
                "bb",
                [],
                "20000000",
                "1d00ffff",
                "5e9a2b5a",
                True,
            ],
        }
    )

    time.sleep(0.1)
    conn.close()
    srv.close()


def test_handshake_local():
    host = "127.0.0.1"
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind((host, 0))
    port = tmp.getsockname()[1]
    tmp.close()

    ready = threading.Event()
    th = threading.Thread(target=_fake_stratum_server, args=(host, port, ready), daemon=True)
    th.start()
    assert ready.wait(2)

    res = connect_and_handshake(host, port, "user", "x", timeout=2.0)
    assert res.authorized is True
    assert res.subscribe.extranonce1 == "01020304"
    assert res.subscribe.extranonce2_size == 8


def test_parse_notifications():
    assert parse_set_difficulty({"id": None, "method": "mining.set_difficulty", "params": [2.5]}) == 2.5

    notify_msg = {
        "id": None,
        "method": "mining.notify",
        "params": [
            "jobX",
            "11" * 32,
            "aa",
            "bb",
            [],
            "20000000",
            "1d00ffff",
            "5e9a2b5a",
            False,
        ],
    }
    tup = parse_notify(notify_msg)
    assert tup is not None
    assert tup[0] == "jobX"
    assert tup[-1] is False

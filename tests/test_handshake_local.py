import json
import socketserver
import threading

from vireon_miner.miner import connect_and_handshake


class FakeStratumHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Expect subscribe
        line1 = self.rfile.readline()
        msg1 = json.loads(line1.decode("utf-8").strip())
        assert msg1["method"] == "mining.subscribe"
        self.wfile.write(b'{"id":1,"result":true,"error":null}\n')
        self.wfile.flush()

        # Expect authorize
        line2 = self.rfile.readline()
        msg2 = json.loads(line2.decode("utf-8").strip())
        assert msg2["method"] == "mining.authorize"
        self.wfile.write(b'{"id":2,"result":true,"error":null}\n')
        self.wfile.flush()


def test_connect_and_handshake_local():
    with socketserver.TCPServer(("127.0.0.1", 0), FakeStratumHandler) as srv:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        host, port = srv.server_address

        res = connect_and_handshake(
            host=host,
            port=port,
            username="t1.vireon.worker",
            password="x",
            timeout_s=2.0,
        )

        assert res.subscribe_reply["id"] == 1
        assert res.authorize_reply["result"] is True

        srv.shutdown()
        srv.server_close()

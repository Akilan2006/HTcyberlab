from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime
from pathlib import Path

LOG = Path(r"C:\CyberLab\http_events.log")

class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        entry = (
            f"{datetime.now().isoformat(timespec='seconds')} "
            f"source={self.client_address[0]} "
            f"request={fmt % args}"
        )
        with LOG.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
        print(entry)

LOG.parent.mkdir(parents=True, exist_ok=True)
server = HTTPServer(("192.168.56.2", 8080), Handler)
print("CyberLab HTTP server listening on 192.168.56.2:8080")
server.serve_forever()

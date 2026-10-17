import http.server
import socketserver
import json
import os

PORT = 8443

class FedRAMP20xHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {
            "service": "Aether FedRAMP 20x MAS Microservice",
            "mas_scope": "MAS-CSO-IIR In-Scope",
            "fips_endpoint_mode": os.environ.get("AWS_USE_FIPS_ENDPOINT", "false"),
            "ksi_cmt_lmc": "Immutable Container Active (Read-Only RootFS, Non-Root UID 10001)"
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), FedRAMP20xHandler) as httpd:
        print(f"Serving immutable MAS microservice on port {PORT}", flush=True)
        httpd.serve_forever()

#!/usr/bin/env python3
"""
Forensic Lab Beacon Listener (safe stand-in)
---------------------------------------------
Purpose: Generates a real, loggable network connection from the Windows
victim VM to the Kali attacker VM, so that Zeek/tcpdump and Volatility's
netscan both have genuine traffic to capture and correlate.

This listener does NOT serve any payload, script, or executable content.
It only acknowledges a GET request and logs the timestamp + source IP.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PORT = 8080

class BeaconHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ts = datetime.utcnow().isoformat() + "Z"
        print(f"[{ts}] Beacon GET received from {self.client_address[0]}")
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"beacon-ack")

    def log_message(self, fmt, *args):
        # Keep default console logging (useful for the live demo)
        super().log_message(fmt, *args)

if __name__ == "__main__":
    print(f"[*] Forensic Lab Beacon Listener on 0.0.0.0:{PORT} (no payload served)")
    HTTPServer(("0.0.0.0", PORT), BeaconHandler).serve_forever()

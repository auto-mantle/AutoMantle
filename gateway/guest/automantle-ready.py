#!/usr/bin/python3
"""Report readiness only after provisioning and a response from the host proxy."""
import socket
import subprocess
import time

subprocess.run(["cloud-init", "status", "--wait"], check=True)
for attempt in range(120):
    try:
        with socket.create_connection(("10.0.2.100", 3128), timeout=2) as connection:
            # A deliberately invalid target exercises the proxy without external traffic.
            connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            if not connection.recv(256).startswith(b"HTTP/"):
                raise OSError("No HTTP response from AutoMantle")
        with open("/dev/ttyS0", "w") as console:
            console.write("\nAUTOMANTLE_GUEST_READY\n")
        break
    except OSError:
        if attempt == 119:
            raise
        time.sleep(1)

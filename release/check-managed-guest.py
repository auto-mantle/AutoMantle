#!/usr/bin/env python3
"""Boot the real managed guest twice, using TCG only in this release test."""
import json
import pathlib
import shlex
import socket
import subprocess
import sys
import time

qemu, image, seed, directory = sys.argv[1:]
directory = pathlib.Path(directory)
image_format = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", image]))["format"]
disk = directory / "test.qcow2"
subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", image_format, "-b", image, str(disk), "32G"], check=True)
helper = directory / "proxy.py"
helper.write_text("import sys\nsys.stdin.buffer.readline()\nsys.stdout.buffer.write(b'HTTP/1.1 400 Bad Request\\r\\nContent-Length: 0\\r\\n\\r\\n')\nsys.stdout.buffer.flush()\n")
serial = directory / "serial.sock"
for boot in range(2):
    serial.unlink(missing_ok=True)
    with (directory / f"qemu-{boot}.log").open("w") as error_log:
        process = subprocess.Popen([
            qemu, "-machine", "q35", "-accel", "tcg", "-m", "1024", "-smp", "2",
            "-display", "none", "-vga", "none", "-monitor", "none",
            "-drive", f"file={disk},format=qcow2,if=virtio",
            "-drive", f"file={seed},format=raw,if=virtio,readonly=on",
            "-netdev", "user,id=proxy,restrict=on,guestfwd=tcp:10.0.2.100:3128-cmd:python3 " + shlex.quote(str(helper)),
            "-device", "e1000e,netdev=proxy,mac=52:54:00:12:34:56,romfile=",
            "-serial", f"unix:{serial},server=on,wait=on", "-no-reboot",
        ], stdout=error_log, stderr=error_log)
        try:
            deadline = time.monotonic() + 300
            with socket.socket(socket.AF_UNIX) as console:
                while True:
                    try:
                        console.connect(str(serial))
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError(f"QEMU did not start: {error_log.name}")
                        time.sleep(.1)
                console.settimeout(1)
                output = b""
                sent = False
                verified = False
                with (directory / f"console-{boot}.log").open("wb") as log:
                    while time.monotonic() < deadline:
                        try:
                            chunk = console.recv(8192)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        log.write(chunk)
                        log.flush()
                        output = (output + chunk)[-65536:]
                        if not sent and b"AUTOMANTLE_GUEST_READY" in output and b"automantle@automantle:" in output:
                            persistence = b"echo persisted > ~/.automantle-smoke; " if boot == 0 else b"test \"$(cat ~/.automantle-smoke)\" = persisted && "
                            console.sendall(persistence + b"printf 'AM_CHECK:%s:%s\\n' \"$(id -un)\" \"$http_proxy\"; sudo poweroff\r")
                            sent = True
                        if b"AM_CHECK:automantle:http://10.0.2.100:3128" in output:
                            verified = True
                if not verified:
                    print(output.decode("utf-8", errors="replace")[-12000:], flush=True)
                    raise RuntimeError(f"Guest was not ready on boot {boot}; inspect {directory}")
                process.wait(timeout=60)
                if process.returncode != 0:
                    raise RuntimeError("Guest failed to shut down cleanly")
                print(f"PASS boot {boot + 1}: provisioned, proxy reachable, terminal logged in automatically", flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

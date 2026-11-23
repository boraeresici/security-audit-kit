#!/usr/bin/env python3
"""Drive headless Chrome over the DevTools protocol, standard library only (tests/report-browser.sh).

Opens a URL, submits the first form whose action matches, waits for the next page and prints its
text. Used for R13b: the local UI's own form must reach the server with an Origin it accepts. A unit
test sets headers by hand and cannot catch what a real browser sends (with `Referrer-Policy:
no-referrer`, Chrome sends `Origin: null` on a form POST).

Usage: browser_cdp.py <chrome> <profile-dir> <url> <form-action>
Prints the resulting page's text; exits 2 if the browser cannot be driven.
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request


def ws_connect(url):
    rest = url.split("://", 1)[1]
    hostport, path = rest.split("/", 1)
    host, port = hostport.split(":")
    s = socket.create_connection((host, int(port)), timeout=20)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    if b" 101 " not in head.split(b"\r\n", 1)[0]:
        raise SystemExit("websocket handshake failed")
    return s


def ws_send(s, text):
    data = text.encode()
    mask = os.urandom(4)
    n = len(data)
    hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536
                           else bytes([0x80 | 127]) + struct.pack(">Q", n))
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise SystemExit("websocket closed")
        buf += chunk
    return buf


def ws_recv(s):
    b1, b2 = recv_exact(s, 2)
    n = b2 & 0x7F
    if n == 126:
        n = struct.unpack(">H", recv_exact(s, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", recv_exact(s, 8))[0]
    return recv_exact(s, n).decode("utf-8", "replace")


class Page:
    def __init__(self, ws_url):
        self.s, self.n = ws_connect(ws_url), 0

    def call(self, method, params=None):
        self.n += 1
        ws_send(self.s, json.dumps({"id": self.n, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(ws_recv(self.s))
            if msg.get("id") == self.n:
                return msg.get("result", {})

    def wait_load(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            msg = json.loads(ws_recv(self.s))
            if msg.get("method") == "Page.loadEventFired":
                return
        raise SystemExit("page did not load")

    def eval(self, expr):
        return self.call("Runtime.evaluate", {"expression": expr, "returnByValue": True}).get("result", {}).get("value")


def main():
    chrome, profile, url, action = sys.argv[1:5]
    flags = ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
             f"--user-data-dir={profile}", "--remote-debugging-port=0", "about:blank"]
    if sys.platform.startswith("linux"):
        flags.insert(0, "--no-sandbox")
    proc = subprocess.Popen([chrome, *flags], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        port_file = os.path.join(profile, "DevToolsActivePort")
        for _ in range(100):
            if os.path.exists(port_file) and os.path.getsize(port_file):
                break
            time.sleep(0.1)
        port = open(port_file).read().split()[0]
        targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10))
        page = Page(next(t for t in targets if t.get("type") == "page")["webSocketDebuggerUrl"])
        page.call("Page.enable")
        page.call("Page.navigate", {"url": url})
        page.wait_load()
        # DevTools evaluation is not the page's script: the CSP that blocks inline code does not
        # apply to it, and the submit it triggers is an ordinary form navigation.
        page.eval(f'document.querySelector(\'form[action="{action}"]\').submit()')
        page.wait_load()
        print(page.eval("document.title + '\\n' + document.body.innerText"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()

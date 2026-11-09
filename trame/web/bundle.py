#!/usr/bin/env python3
"""Build a single self-contained page from web/: the engine (trame.wasm) and the
sample capture are embedded as base64, app.js is inlined.

  python3 web/bundle.py              -> dist/trame.html (full HTML document)
  python3 web/bundle.py --fragment   -> dist/trame-fragment.html (no <html>/<head>/<body>,
                                        for hosts that add their own document skeleton)
"""
import base64
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "..", "dist")


def b64(name):
    with open(os.path.join(ROOT, name), "rb") as f:
        return base64.b64encode(f.read()).decode()


def main():
    fragment = "--fragment" in sys.argv
    html = open(os.path.join(ROOT, "index.html"), encoding="utf-8").read()
    app = open(os.path.join(ROOT, "app.js"), encoding="utf-8").read()
    inline = (
        f"<script>window.TRAME_WASM_B64=\"{b64('trame.wasm')}\";\n"
        f"window.TRAME_SAMPLE_B64=\"{b64('sample.pcapng')}\";</script>\n"
        f"<script>{app}</script>"
    )
    html = html.replace('<script src="app.js"></script>', inline)
    if fragment:
        head = re.search(r"<head>(.*?)</head>", html, re.S).group(1)
        head = re.sub(r'<meta charset="utf-8">\s*', "", head)
        head = re.sub(r'<meta name="viewport"[^>]*>\s*', "", head)
        body = re.search(r"<body>(.*)</body>", html, re.S).group(1)
        html = head.strip() + "\n" + body.strip() + "\n"
    os.makedirs(DIST, exist_ok=True)
    out = os.path.join(DIST, "trame-fragment.html" if fragment else "trame.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{out}: {os.path.getsize(out) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()

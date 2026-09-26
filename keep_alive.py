"""
keep_alive.py

Tiny Flask server run in a background thread so Render's free Web Service
sees an open port and stays "alive". Render's free plan spins a Web
Service down after 15 minutes with no inbound HTTP traffic, so this only
works combined with an external uptime pinger (see bot.py's docstring /
the setup notes) hitting this server every 5-10 minutes.

This does NOT replace the WEAO proxy routes — it's just a heartbeat.
"""

import os
import threading

from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return "Bot is alive."


def _run():
    port = int(os.getenv("PORT", 8080))  # Render sets $PORT for you
    app.run(host="0.0.0.0", port=port)


def keep_alive():
    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
